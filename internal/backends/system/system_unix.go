//go:build !windows

package system

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// -----------------------------------------------------------------------
// Traceroute
// -----------------------------------------------------------------------

// Traceroute runs traceroute to the target and parses hops. Linux and macOS
// both use the same traceroute binary and output format; Windows uses tracert
// instead (see system_windows.go).
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
	if hop.RTT == "" {
		return nil
	}
	return hop
}
