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

const (
	pingCountFlag   = "-c"
	pingTimeoutFlag = "-t"
	pingTimeout     = "2"
)

func (s PingSource) bindArgs() []string { return []string{"-b", s.Interface, "-S", s.IP.String()} }

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
