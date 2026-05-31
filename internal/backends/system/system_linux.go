//go:build linux

package system

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// -----------------------------------------------------------------------
// GetRoutes
// -----------------------------------------------------------------------

func GetRoutes(ctx context.Context) ([]Route, error) {
	out, err := runCmd(ctx, "ip", "route")
	if err != nil {
		return nil, fmt.Errorf("ip route: %w", err)
	}
	return parseIPRouteOutput(out), nil
}

func parseIPRouteOutput(output string) []Route {
	var routes []Route
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if r := parseIPRouteLine(line); r != nil {
			routes = append(routes, *r)
		}
	}
	return routes
}

func parseIPRouteLine(line string) *Route {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return nil
	}
	r := &Route{Destination: fields[0]}
	for i := 1; i < len(fields); i++ {
		switch fields[i] {
		case "via":
			if i+1 < len(fields) {
				r.Gateway = fields[i+1]
				i++
			}
		case "dev":
			if i+1 < len(fields) {
				r.Device = fields[i+1]
				i++
			}
		case "proto":
			if i+1 < len(fields) {
				r.Protocol = fields[i+1]
				i++
			}
		case "scope":
			if i+1 < len(fields) {
				r.Scope = fields[i+1]
				i++
			}
		case "metric":
			if i+1 < len(fields) {
				if m, err := strconv.Atoi(fields[i+1]); err == nil {
					r.Metric = m
				}
				i++
			}
		}
	}
	return r
}

// -----------------------------------------------------------------------
// GetRouteToTarget
// -----------------------------------------------------------------------

func GetRouteToTarget(ctx context.Context, target string) (*Route, error) {
	out, err := runCmd(ctx, "ip", "route", "get", target)
	if err != nil {
		return nil, fmt.Errorf("ip route get %s: %w", target, err)
	}

	line := strings.TrimSpace(strings.SplitN(out, "\n", 2)[0])
	if line == "" {
		return nil, fmt.Errorf("no route to %s", target)
	}

	fields := strings.Fields(line)
	r := &Route{}
	for i := 0; i < len(fields); i++ {
		switch fields[i] {
		case "local":
			// skip keyword
		case "via":
			if i+1 < len(fields) {
				r.Gateway = fields[i+1]
				i++
			}
		case "dev":
			if i+1 < len(fields) {
				r.Device = fields[i+1]
				i++
			}
		case "src":
			i++ // skip source address
		case "uid":
			i++ // skip uid
		default:
			if r.Destination == "" && !strings.HasPrefix(fields[i], "cache") {
				r.Destination = fields[i]
			}
		}
	}
	if r.Destination == "" {
		r.Destination = target
	}
	return r, nil
}

// -----------------------------------------------------------------------
// Ping
// -----------------------------------------------------------------------

var (
	rePktLossLinux = regexp.MustCompile(`(\d+(?:\.\d+)?)% packet loss`)
	reAvgRTTLinux  = regexp.MustCompile(`rtt min/avg/max/mdev = [\d.]+/([\d.]+)/`)
)

func Ping(ctx context.Context, target string) (*PingResult, error) {
	out, err := runCmd(ctx, "ping", "-c", "3", "-W", "2", target)
	if err != nil && ctx.Err() != nil {
		return nil, fmt.Errorf("ping cancelled: %w", ctx.Err())
	}

	pr := &PingResult{}
	if m := rePktLossLinux.FindStringSubmatch(out); m != nil {
		loss, _ := strconv.ParseFloat(m[1], 64)
		pr.PacketLoss = loss
		pr.Reachable = loss < 100
	} else if err != nil {
		pr.Reachable = false
		pr.PacketLoss = 100
		return pr, nil
	}
	if m := reAvgRTTLinux.FindStringSubmatch(out); m != nil {
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
		if hop := parseTracerouteLine(line); hop != nil {
			hops = append(hops, *hop)
		}
	}
	return hops, nil
}

func parseTracerouteLine(line string) *TracerouteHop {
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

type ipAddrJSON struct {
	Ifname    string `json:"ifname"`
	Operstate string `json:"operstate"`
	LinkType  string `json:"link_type"`
	AddrInfo  []struct {
		Family    string `json:"family"`
		Local     string `json:"local"`
		Prefixlen int    `json:"prefixlen"`
	} `json:"addr_info"`
}

func GetInterfaces(ctx context.Context) ([]Interface, error) {
	out, err := runCmd(ctx, "ip", "-j", "addr", "show")
	if err == nil && strings.TrimSpace(out) != "" && strings.HasPrefix(strings.TrimSpace(out), "[") {
		return parseInterfacesJSON(out)
	}
	out, err = runCmd(ctx, "ip", "addr", "show")
	if err != nil {
		return nil, fmt.Errorf("ip addr show: %w", err)
	}
	return parseInterfacesText(out), nil
}

func parseInterfacesJSON(output string) ([]Interface, error) {
	var raw []ipAddrJSON
	if err := json.Unmarshal([]byte(output), &raw); err != nil {
		return nil, fmt.Errorf("parsing ip -j addr show: %w", err)
	}
	ifaces := make([]Interface, 0, len(raw))
	for _, r := range raw {
		iface := Interface{
			Name:  r.Ifname,
			State: strings.ToLower(r.Operstate),
			Addrs: make([]string, 0),
			Type:  classifyInterface(r.Ifname, r.LinkType),
		}
		for _, a := range r.AddrInfo {
			iface.Addrs = append(iface.Addrs,
				fmt.Sprintf("%s/%d", a.Local, a.Prefixlen))
		}
		ifaces = append(ifaces, iface)
	}
	return ifaces, nil
}

var (
	reIfaceHeaderLinux = regexp.MustCompile(`^\d+:\s+(\S+):\s+<([^>]*)>`)
	reInetAddrLinux    = regexp.MustCompile(`inet6?\s+(\S+)`)
)

func parseInterfacesText(output string) []Interface {
	var ifaces []Interface
	var current *Interface

	for _, line := range strings.Split(output, "\n") {
		if m := reIfaceHeaderLinux.FindStringSubmatch(line); m != nil {
			if current != nil {
				ifaces = append(ifaces, *current)
			}
			flags := m[2]
			state := "down"
			if strings.Contains(flags, "UP") {
				state = "up"
			}
			current = &Interface{
				Name:  strings.TrimSuffix(m[1], "@NONE"),
				State: state,
				Addrs: []string{},
				Type:  classifyInterface(m[1], ""),
			}
			continue
		}
		if current == nil {
			continue
		}
		if m := reInetAddrLinux.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			current.Addrs = append(current.Addrs, m[1])
		}
	}
	if current != nil {
		ifaces = append(ifaces, *current)
	}
	return ifaces
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
			return iface.State == "up" || iface.State == "unknown", nil
		}
	}
	// Fallback: check ip link directly
	out, err := runCmd(ctx, "ip", "link", "show", ifaceName)
	if err != nil {
		return false, nil
	}
	return strings.Contains(strings.ToUpper(out), "UP"), nil
}
