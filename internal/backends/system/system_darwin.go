//go:build darwin

package system

import (
	"context"
	"fmt"
	"math/bits"
	"regexp"
	"strconv"
	"strings"
)

// -----------------------------------------------------------------------
// GetRoutes
// -----------------------------------------------------------------------

func GetRoutes(ctx context.Context) ([]Route, error) {
	out, err := runCmd(ctx, "netstat", "-rn", "-f", "inet")
	if err != nil {
		return nil, fmt.Errorf("netstat -rn: %w", err)
	}
	return parseNetstatRoutes(out), nil
}

func parseNetstatRoutes(output string) []Route {
	var routes []Route
	inTable := false

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Skip everything until we find the column header
		if strings.HasPrefix(line, "Destination") {
			inTable = true
			continue
		}
		if !inTable {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		r := Route{
			Destination: fields[0],
			Gateway:     fields[1],
			// fields[2] = Flags
			Device: fields[3],
		}
		routes = append(routes, r)
	}
	return routes
}

// -----------------------------------------------------------------------
// GetRouteToTarget
// -----------------------------------------------------------------------

func GetRouteToTarget(ctx context.Context, target string) (*Route, error) {
	out, err := runCmd(ctx, "route", "-n", "get", target)
	if err != nil {
		return nil, fmt.Errorf("route -n get %s: %w", target, err)
	}

	r := &Route{Destination: target}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		switch key {
		case "destination":
			r.Destination = val
		case "gateway":
			r.Gateway = val
		case "interface":
			r.Device = val
		}
	}

	if r.Device == "" && r.Gateway == "" {
		return nil, fmt.Errorf("could not parse route to %s", target)
	}
	return r, nil
}

// -----------------------------------------------------------------------
// Ping
// -----------------------------------------------------------------------

var (
	rePktLossDarwin = regexp.MustCompile(`(\d+(?:\.\d+)?)% packet loss`)
	reAvgRTTDarwin  = regexp.MustCompile(`round-trip min/avg/max/stddev = [\d.]+/([\d.]+)/`)
)

func Ping(ctx context.Context, target string) (*PingResult, error) {
	// macOS uses -t for timeout (seconds), not -W
	out, err := runCmd(ctx, "ping", "-c", "3", "-t", "2", target)
	if err != nil && ctx.Err() != nil {
		return nil, fmt.Errorf("ping cancelled: %w", ctx.Err())
	}

	pr := &PingResult{}
	if m := rePktLossDarwin.FindStringSubmatch(out); m != nil {
		loss, _ := strconv.ParseFloat(m[1], 64)
		pr.PacketLoss = loss
		pr.Reachable = loss < 100
	} else if err != nil {
		pr.Reachable = false
		pr.PacketLoss = 100
		return pr, nil
	}
	if m := reAvgRTTDarwin.FindStringSubmatch(out); m != nil {
		pr.AvgLatency = m[1]
	}
	return pr, nil
}

// -----------------------------------------------------------------------
// Traceroute
// -----------------------------------------------------------------------

func Traceroute(ctx context.Context, target string) ([]TracerouteHop, error) {
	out, err := runCmd(ctx, "traceroute", "-n", "-m", "15", "-w", "2", target)
	if err != nil && ctx.Err() != nil {
		return nil, fmt.Errorf("traceroute cancelled: %w", ctx.Err())
	}

	var hops []TracerouteHop
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "traceroute") {
			continue
		}
		if hop := parseTracerouteLineDarwin(line); hop != nil {
			hops = append(hops, *hop)
		}
	}
	return hops, nil
}

func parseTracerouteLineDarwin(line string) *TracerouteHop {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return nil
	}
	num, err := strconv.Atoi(fields[0])
	if err != nil {
		return nil
	}
	hop := &TracerouteHop{Number: num}
	if fields[1] == "*" {
		hop.Address = "*"
		return hop
	}
	hop.Address = fields[1]
	for i := 2; i+1 < len(fields); i++ {
		if fields[i] != "*" {
			if _, err := strconv.ParseFloat(fields[i], 64); err == nil {
				if fields[i+1] == "ms" {
					hop.RTT = fields[i] + " ms"
					break
				}
			}
		}
	}
	return hop
}

// -----------------------------------------------------------------------
// GetInterfaces
// -----------------------------------------------------------------------

var (
	reIfconfigHeader = regexp.MustCompile(`^(\w+):\s+flags=\d+<([^>]*)>`)
	reIfconfigInet   = regexp.MustCompile(`inet (\d+\.\d+\.\d+\.\d+)`)
	reIfconfigMask   = regexp.MustCompile(`netmask (0x[0-9a-fA-F]+)`)
	reIfconfigInet6  = regexp.MustCompile(`inet6 ([0-9a-fA-F:]+)(?:%\S+)?\s+prefixlen (\d+)`)
	reIfconfigStatus = regexp.MustCompile(`status:\s+(\S+)`)
)

func GetInterfaces(ctx context.Context) ([]Interface, error) {
	out, err := runCmd(ctx, "ifconfig")
	if err != nil {
		return nil, fmt.Errorf("ifconfig: %w", err)
	}
	return parseIfconfig(out), nil
}

func parseIfconfig(output string) []Interface {
	var ifaces []Interface
	var current *Interface

	for _, line := range strings.Split(output, "\n") {
		// New interface block
		if m := reIfconfigHeader.FindStringSubmatch(line); m != nil {
			if current != nil {
				ifaces = append(ifaces, *current)
			}
			flags := m[2]
			state := "down"
			if strings.Contains(flags, "UP") {
				state = "up"
			}
			current = &Interface{
				Name:  m[1],
				State: state,
				Addrs: []string{},
				Type:  classifyInterface(m[1], ""),
			}
			continue
		}

		if current == nil {
			continue
		}

		trimmed := strings.TrimSpace(line)

		// Status line override (macOS specific)
		if m := reIfconfigStatus.FindStringSubmatch(trimmed); m != nil {
			if m[1] == "inactive" {
				current.State = "down"
			}
			continue
		}

		// IPv4 address
		if m := reIfconfigInet.FindStringSubmatch(trimmed); m != nil {
			addr := m[1]
			prefix := 32
			if mask := reIfconfigMask.FindStringSubmatch(trimmed); mask != nil {
				prefix = hexMaskToPrefix(mask[1])
			}
			current.Addrs = append(current.Addrs, fmt.Sprintf("%s/%d", addr, prefix))
			continue
		}

		// IPv6 address
		if m := reIfconfigInet6.FindStringSubmatch(trimmed); m != nil {
			prefix, _ := strconv.Atoi(m[2])
			current.Addrs = append(current.Addrs, fmt.Sprintf("%s/%d", m[1], prefix))
			continue
		}
	}

	if current != nil {
		ifaces = append(ifaces, *current)
	}
	return ifaces
}

// hexMaskToPrefix converts a hex netmask like "0xffffff00" to a prefix length (24).
func hexMaskToPrefix(hex string) int {
	hex = strings.TrimPrefix(hex, "0x")
	hex = strings.TrimPrefix(hex, "0X")
	val, err := strconv.ParseUint(hex, 16, 32)
	if err != nil {
		return 32
	}
	return bits.OnesCount32(uint32(val))
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
