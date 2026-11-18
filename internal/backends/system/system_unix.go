//go:build !windows

package system

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var (
	rePacketLoss = regexp.MustCompile(`(\d+(?:\.\d+)?)% packet loss`)
	reAverageRTT = regexp.MustCompile(`(?:rtt min/avg/max/mdev|round-trip min/avg/max/stddev) = [\d.]+/([\d.]+)/`)
)

func parsePingResult(target, out string, err error, bound bool) (*PingResult, error) {
	pr := &PingResult{}
	if m := rePacketLoss.FindStringSubmatch(out); m != nil {
		pr.PacketLoss, _ = strconv.ParseFloat(m[1], 64)
		pr.Reachable = pr.PacketLoss < 100
	} else if err != nil {
		return nil, fmt.Errorf("ping %s failed: %w", target, err)
	} else if bound {
		return nil, fmt.Errorf("source-bound ping to %s produced no packet statistics", target)
	}
	if m := reAverageRTT.FindStringSubmatch(out); m != nil {
		pr.AvgLatency = m[1]
	}
	return pr, nil
}

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
