//go:build windows

package system

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// -----------------------------------------------------------------------
// GetRoutes
// -----------------------------------------------------------------------

func GetRoutes(ctx context.Context) ([]Route, error) {
	out, err := runCmd(ctx, "route", "print", "-4")
	if err != nil {
		return nil, fmt.Errorf("route print: %w", err)
	}
	return parseRoutePrint(out), nil
}

func parseRoutePrint(output string) []Route {
	var routes []Route
	inActiveRoutes := false

	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "Active Routes:") {
			inActiveRoutes = true
			continue
		}
		if strings.HasPrefix(trimmed, "Persistent Routes:") || strings.HasPrefix(trimmed, "====") {
			if inActiveRoutes {
				break
			}
			continue
		}
		if strings.HasPrefix(trimmed, "Network Destination") {
			continue
		}

		if !inActiveRoutes || trimmed == "" {
			continue
		}

		fields := strings.Fields(trimmed)
		if len(fields) < 5 {
			continue
		}

		dest := fields[0]
		mask := fields[1]
		gateway := fields[2]
		iface := fields[3]
		metric := 0
		if m, err := strconv.Atoi(fields[4]); err == nil {
			metric = m
		}

		prefix := netmaskToPrefix(mask)
		if dest == "0.0.0.0" && mask == "0.0.0.0" {
			dest = "default"
		} else if prefix > 0 {
			dest = fmt.Sprintf("%s/%d", dest, prefix)
		}

		routes = append(routes, Route{
			Destination: dest,
			Gateway:     gateway,
			Device:      iface,
			Metric:      metric,
		})
	}
	return routes
}

func netmaskToPrefix(mask string) int {
	ip := net.ParseIP(mask)
	if ip == nil {
		return 0
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	ones, _ := net.IPMask(ip4).Size()
	return ones
}

// -----------------------------------------------------------------------
// GetRouteToTarget
// -----------------------------------------------------------------------

func GetRouteToTarget(ctx context.Context, target string) (*Route, error) {
	routes, err := GetRoutes(ctx)
	if err != nil {
		return nil, err
	}

	targetIP := net.ParseIP(target)
	if targetIP == nil {
		return nil, fmt.Errorf("invalid target IP: %s", target)
	}

	var bestRoute *Route
	bestPrefix := -1

	for i := range routes {
		r := &routes[i]
		dest := r.Destination

		if dest == "default" {
			if bestPrefix < 0 {
				bestRoute = r
				bestPrefix = 0
			}
			continue
		}

		_, network, err := net.ParseCIDR(dest)
		if err != nil {
			network = &net.IPNet{
				IP:   net.ParseIP(dest),
				Mask: net.CIDRMask(32, 32),
			}
		}
		if network != nil && network.Contains(targetIP) {
			ones, _ := network.Mask.Size()
			if ones > bestPrefix {
				bestRoute = r
				bestPrefix = ones
			}
		}
	}

	if bestRoute == nil {
		return nil, fmt.Errorf("no route to %s", target)
	}

	return &Route{
		Destination: target,
		Gateway:     bestRoute.Gateway,
		Device:      bestRoute.Device,
		Metric:      bestRoute.Metric,
	}, nil
}

// -----------------------------------------------------------------------
// Ping
// -----------------------------------------------------------------------

var (
	rePktLossWindows = regexp.MustCompile(`\((\d+)% loss\)`)
	reAvgRTTWindows  = regexp.MustCompile(`Average = (\d+)ms`)
)

func Ping(ctx context.Context, target string) (*PingResult, error) {
	out, err := runCmd(ctx, "ping", "-n", "3", "-w", "2000", target)
	if err != nil && ctx.Err() != nil {
		return nil, fmt.Errorf("ping cancelled: %w", ctx.Err())
	}

	pr := &PingResult{}
	if m := rePktLossWindows.FindStringSubmatch(out); m != nil {
		loss, _ := strconv.ParseFloat(m[1], 64)
		pr.PacketLoss = loss
		pr.Reachable = loss < 100
	} else if err != nil {
		pr.Reachable = false
		pr.PacketLoss = 100
		return pr, nil
	}
	if m := reAvgRTTWindows.FindStringSubmatch(out); m != nil {
		pr.AvgLatency = m[1]
	}
	return pr, nil
}

// -----------------------------------------------------------------------
// Traceroute
// -----------------------------------------------------------------------

func Traceroute(ctx context.Context, target string) ([]TracerouteHop, error) {
	out, err := runCmd(ctx, "tracert", "-d", "-h", "15", "-w", "2000", target)
	if err != nil && ctx.Err() != nil {
		return nil, fmt.Errorf("tracert cancelled: %w", ctx.Err())
	}

	var hops []TracerouteHop
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Tracing") || strings.HasPrefix(line, "over a") {
			continue
		}
		if hop := parseTracertLine(line); hop != nil {
			hops = append(hops, *hop)
		}
	}
	return hops, nil
}

var reTracertHop = regexp.MustCompile(`^\s*(\d+)`) //nolint:unused // used via parseTracertLine in same package

func parseTracertLine(line string) *TracerouteHop {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return nil
	}

	num, err := strconv.Atoi(fields[0])
	if err != nil {
		return nil
	}

	hop := &TracerouteHop{Number: num}

	lastField := fields[len(fields)-1]
	if net.ParseIP(lastField) != nil {
		hop.Address = lastField
	} else if lastField == "out." || strings.HasPrefix(lastField, "Request") {
		hop.Address = "*"
		return hop
	} else {
		hop.Address = "*"
		return hop
	}

	for i := 1; i < len(fields)-1; i++ {
		f := strings.TrimSuffix(fields[i], "ms")
		if f == "*" || f == "" {
			continue
		}
		if f == "<1" {
			hop.RTT = "<1 ms"
			break
		}
		if _, err := strconv.ParseFloat(f, 64); err == nil {
			hop.RTT = f + " ms"
			break
		}
	}

	return hop
}

// -----------------------------------------------------------------------
// GetInterfaces
// -----------------------------------------------------------------------

func GetInterfaces(ctx context.Context) ([]Interface, error) {
	goIfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("listing interfaces: %w", err)
	}

	ifaces := make([]Interface, 0, len(goIfaces))
	for _, gi := range goIfaces {
		state := "down"
		if gi.Flags&net.FlagUp != 0 {
			state = "up"
		}

		iface := Interface{
			Name:  gi.Name,
			State: state,
			Addrs: []string{},
			Type:  classifyInterface(gi.Name, ""),
		}

		addrs, err := gi.Addrs()
		if err == nil {
			for _, a := range addrs {
				iface.Addrs = append(iface.Addrs, a.String())
			}
		}

		ifaces = append(ifaces, iface)
	}
	return ifaces, nil
}

// -----------------------------------------------------------------------
// CheckVPNInterface
// -----------------------------------------------------------------------

func CheckVPNInterface(ctx context.Context, ifaceName string) (bool, error) {
	if !isVPNInterfaceName(ifaceName) {
		return false, nil
	}

	ifaces, err := GetInterfaces(ctx)
	if err != nil {
		return false, fmt.Errorf("getting interfaces: %w", err)
	}
	for _, iface := range ifaces {
		if iface.Name == ifaceName {
			return iface.State == "up", nil
		}
	}
	return false, nil
}
