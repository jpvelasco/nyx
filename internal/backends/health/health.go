// Package health provides network health checking via ping and MTU discovery.
package health

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/jpvelasco/nyx/internal/models"
)

// PingStats captures detailed ping statistics
type PingStats struct {
	Target   string  `json:"target"`
	Sent     int     `json:"sent"`
	Received int     `json:"received"`
	LossPct  float64 `json:"loss_pct"`
	AvgRTTMs float64 `json:"avg_rtt_ms"`
	MinRTTMs float64 `json:"min_rtt_ms"`
	MaxRTTMs float64 `json:"max_rtt_ms"`
}

// MTUResult captures MTU discovery results
type MTUResult struct {
	Target        string `json:"target"`
	DiscoveredMTU int    `json:"discovered_mtu"`
	RequestedMTU  int    `json:"requested_mtu,omitempty"`
}

// pingOutputParsers hold platform-specific regex patterns
var (
	rePktLossLinux   = regexp.MustCompile(`(\d+(?:\.\d+)?)% packet loss`)
	reAvgRTTLinux    = regexp.MustCompile(`rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/`)
	rePktLossWindows = regexp.MustCompile(`\((\d+)% loss\)`)
	reAvgRTTWindows  = regexp.MustCompile(`Average = ([\d.]+)ms`)
	reMinMaxWindows  = regexp.MustCompile(`Minimum = (\d+)ms, Maximum = (\d+)ms`)
	reRTTDarwin      = regexp.MustCompile(`min/avg/max/stddev = ([\d.]+)/([\d.]+)/([\d.]+)/`)
	rePktLossDarwin  = regexp.MustCompile(`(\d+(?:\.\d+)?)% packet loss`)
)

// PingCheck runs a ping with the specified count and returns detailed stats.
// A failed ping (host down, no route, firewall drop) yields StatusFail — a
// health finding — not StatusError. Only context cancellation is an
// execution error.
func PingCheck(ctx context.Context, target string, count int) (*models.CheckResult, *PingStats, error) {
	result := models.NewCheckResult("ping", "network_health", "system", target)

	out, err := runPing(ctx, target, count)
	result.Evidence = []string{out}

	if err != nil && ctx.Err() != nil {
		result.Status = models.StatusError
		result.Summary = fmt.Sprintf("ping cancelled: %v", ctx.Err())
		result.Finish()
		return result, nil, err
	}

	stats := parsePingOutput(out, target, count)

	// Convert stats to map for Observed
	statsMap := map[string]interface{}{
		"sent":       stats.Sent,
		"received":   stats.Received,
		"loss_pct":   stats.LossPct,
		"avg_rtt_ms": stats.AvgRTTMs,
	}
	if stats.MinRTTMs > 0 {
		statsMap["min_rtt_ms"] = stats.MinRTTMs
	}
	if stats.MaxRTTMs > 0 {
		statsMap["max_rtt_ms"] = stats.MaxRTTMs
	}
	result.Observed = statsMap

	// The target is unreachable: ping failed and/or the output confirms
	// total loss (some implementations exit 0 on 100% loss, e.g. busybox).
	// Report a Fail verdict consistent with the probe path, never Error.
	if summary, violation := classifyPingFailure(err, stats, target); violation != "" {
		result.Status = models.StatusFail
		result.Summary = summary
		result.Violations = append(result.Violations, violation)
		result.Finish()
		return result, stats, nil
	}

	result.Status = models.StatusPass
	result.Summary = fmt.Sprintf("ping %s: %d sent, %d received (%.1f%% loss), avg %.2fms",
		target, stats.Sent, stats.Received, stats.LossPct, stats.AvgRTTMs)
	result.Finish()
	return result, stats, nil
}

// CheckLatencyAndLoss runs 10 pings and checks if latency and loss are within limits.
// Fails if observed values exceed thresholds (when thresholds > 0).
// A failed ping (host down) already yields StatusFail from PingCheck and
// passes through untouched; only context cancellation surfaces StatusError.
func CheckLatencyAndLoss(ctx context.Context, target string, maxLatencyMs float64, maxLossPct float64) (*models.CheckResult, error) {
	result, stats, err := PingCheck(ctx, target, 10)

	// Set expected thresholds
	result.Expected = map[string]interface{}{
		"max_latency_ms": maxLatencyMs,
		"max_loss_pct":   maxLossPct,
	}

	// Ping failure verdicts (Fail/Error) pass through as-is — a dead host
	// must never be overwritten by threshold classification.
	if result.Status != models.StatusPass {
		result.Finish()
		return result, err
	}

	status, violations, summary := classifyLatencyLoss(stats, maxLatencyMs, maxLossPct)
	result.Status = status
	result.Violations = violations
	if summary != "" {
		result.Summary = summary
	}

	result.Finish()
	return result, nil
}

// classifyPingFailure builds the Fail verdict text for an unreachable target.
// The ping is considered failed when the command errored (exit code, DNS
// failure) or the output reports 100% loss (some implementations exit 0 on
// total loss). Returns an empty violation when the ping succeeded.
func classifyPingFailure(err error, stats *PingStats, target string) (summary, violation string) {
	if err == nil && stats.LossPct < 100 {
		return "", ""
	}
	if stats.LossPct >= 100 {
		return fmt.Sprintf("ping %s: %d sent, %d received (%.1f%% loss)",
			target, stats.Sent, stats.Received, stats.LossPct), "100% packet loss — host unreachable"
	}
	return fmt.Sprintf("ping %s failed: %v", target, err), fmt.Sprintf("ping error: %v", err)
}

// classifyLatencyLoss compares observed ping stats against thresholds.
// Thresholds <= 0 mean "don't check". Returns the resulting status, violations,
// and a summary (empty when no violations).
func classifyLatencyLoss(stats *PingStats, maxLatencyMs float64, maxLossPct float64) (models.Status, []string, string) {
	var violations []string

	// Check loss percentage
	if maxLossPct > 0 && stats.LossPct > maxLossPct {
		violations = append(violations, fmt.Sprintf("loss %.1f%% exceeds limit %.1f%%", stats.LossPct, maxLossPct))
	}

	// Check latency
	if maxLatencyMs > 0 && stats.AvgRTTMs > maxLatencyMs {
		violations = append(violations, fmt.Sprintf("latency %.1fms exceeds limit %.1fms", stats.AvgRTTMs, maxLatencyMs))
	}

	if len(violations) > 0 {
		return models.StatusFail, violations, fmt.Sprintf("health check failed: %s", strings.Join(violations, "; "))
	}
	return models.StatusPass, nil, ""
}

// ProbeMTU performs binary search to find the maximum MTU to a target.
// Returns StatusPass if discovered >= expected, StatusWarn if within 10%, StatusFail otherwise.
func ProbeMTU(ctx context.Context, target string, expectedMTU int) (*models.CheckResult, error) {
	result := models.NewCheckResult("ping", "network_health", "system", target)

	discoveredMTU, evidence := probeMTUBinarySearch(ctx, target)
	result.Evidence = evidence

	mtuResult := MTUResult{
		Target:        target,
		DiscoveredMTU: discoveredMTU,
		RequestedMTU:  expectedMTU,
	}
	mtuJSON, _ := json.Marshal(mtuResult)
	result.Observed = map[string]interface{}{
		"mtu": discoveredMTU,
	}
	result.Expected = map[string]interface{}{
		"mtu": expectedMTU,
	}

	// Determine status
	if discoveredMTU >= expectedMTU {
		result.Status = models.StatusPass
		result.Summary = fmt.Sprintf("MTU %d meets expected %d", discoveredMTU, expectedMTU)
	} else {
		minAcceptable := int(float64(expectedMTU) * 0.9)
		if discoveredMTU >= minAcceptable {
			result.Status = models.StatusWarn
			result.Summary = fmt.Sprintf("MTU %d is lower than expected %d but within 10%%", discoveredMTU, expectedMTU)
		} else {
			result.Status = models.StatusFail
			result.Summary = fmt.Sprintf("MTU %d is significantly lower than expected %d", discoveredMTU, expectedMTU)
			result.Violations = []string{fmt.Sprintf("MTU %d below 90%% threshold of %d", discoveredMTU, minAcceptable)}
		}
	}

	result.Evidence = append(result.Evidence, string(mtuJSON))
	result.Finish()
	return result, nil
}

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

// runPing executes the ping command with platform-appropriate flags
func runPing(ctx context.Context, target string, count int) (string, error) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		// #nosec G204 — ping is hardcoded, target from spec
		cmd = exec.CommandContext(ctx, "ping", "-n", fmt.Sprintf("%d", count), "-w", "2000", target) // nosemgrep
	case "darwin":
		// #nosec G204 — ping is hardcoded, target from spec
		cmd = exec.CommandContext(ctx, "ping", "-c", fmt.Sprintf("%d", count), "-W", "2000", target) // nosemgrep
	default: // linux
		// #nosec G204 — ping is hardcoded, target from spec
		cmd = exec.CommandContext(ctx, "ping", "-c", fmt.Sprintf("%d", count), "-W", "2", target) // nosemgrep
	}
	out, err := cmd.Output()
	return string(out), err
}

// parsePingOutput extracts ping stats from platform-specific output
func parsePingOutput(output string, target string, count int) *PingStats {
	stats := &PingStats{
		Target: target,
		Sent:   count,
	}

	switch runtime.GOOS {
	case "windows":
		parseWindowsPingOutput(output, stats)
	case "darwin":
		parseDarwinPingOutput(output, stats)
	default: // linux
		parseLinuxPingOutput(output, stats)
	}

	return stats
}

// parseLinuxPingOutput extracts ping stats from Linux ping output
func parseLinuxPingOutput(output string, stats *PingStats) {
	// Loss: "10 packets transmitted, 10 received, 0% packet loss"
	if m := rePktLossLinux.FindStringSubmatch(output); m != nil {
		loss, _ := strconv.ParseFloat(m[1], 64)
		stats.LossPct = loss
		stats.Received = stats.Sent - int(float64(stats.Sent)*loss/100)
	} else {
		stats.Received = stats.Sent
	}

	// RTT: "rtt min/avg/max/mdev = 0.123/0.456/0.789/0.123 ms"
	if m := reAvgRTTLinux.FindStringSubmatch(output); m != nil {
		minRTT, _ := strconv.ParseFloat(m[1], 64)
		avgRTT, _ := strconv.ParseFloat(m[2], 64)
		maxRTT, _ := strconv.ParseFloat(m[3], 64)
		stats.MinRTTMs = minRTT
		stats.AvgRTTMs = avgRTT
		stats.MaxRTTMs = maxRTT
	}
}

// parseWindowsPingOutput extracts ping stats from Windows ping output
func parseWindowsPingOutput(output string, stats *PingStats) {
	// Loss: "(0% loss)"
	if m := rePktLossWindows.FindStringSubmatch(output); m != nil {
		loss, _ := strconv.ParseFloat(m[1], 64)
		stats.LossPct = loss
		stats.Received = stats.Sent - int(float64(stats.Sent)*loss/100)
	} else {
		stats.Received = stats.Sent
	}

	// Average: "Average = 12ms"
	if m := reAvgRTTWindows.FindStringSubmatch(output); m != nil {
		avgRTT, _ := strconv.ParseFloat(m[1], 64)
		stats.AvgRTTMs = avgRTT
	}

	// Min/Max: "Minimum = 11ms, Maximum = 14ms"
	if m := reMinMaxWindows.FindStringSubmatch(output); m != nil {
		minRTT, _ := strconv.ParseFloat(m[1], 64)
		maxRTT, _ := strconv.ParseFloat(m[2], 64)
		stats.MinRTTMs = minRTT
		stats.MaxRTTMs = maxRTT
	}
}

// parseDarwinPingOutput extracts ping stats from macOS ping output
func parseDarwinPingOutput(output string, stats *PingStats) {
	// Loss: "0.0% packet loss"
	if m := rePktLossDarwin.FindStringSubmatch(output); m != nil {
		loss, _ := strconv.ParseFloat(m[1], 64)
		stats.LossPct = loss
		stats.Received = stats.Sent - int(float64(stats.Sent)*loss/100)
	} else {
		stats.Received = stats.Sent
	}

	// RTT: "min/avg/max/stddev = 0.123/0.456/0.789/0.123 ms"
	if m := reRTTDarwin.FindStringSubmatch(output); m != nil {
		minRTT, _ := strconv.ParseFloat(m[1], 64)
		avgRTT, _ := strconv.ParseFloat(m[2], 64)
		maxRTT, _ := strconv.ParseFloat(m[3], 64)
		stats.MinRTTMs = minRTT
		stats.AvgRTTMs = avgRTT
		stats.MaxRTTMs = maxRTT
	}
}

// probeMTUBinarySearch performs binary search to find max MTU
func probeMTUBinarySearch(ctx context.Context, target string) (int, []string) {
	return mtuBinarySearch(func(size int) bool { return canPing(ctx, target, size) })
}

// mtuBinarySearch finds the largest size in [576, 1500] that canPingFn accepts.
func mtuBinarySearch(canPingFn func(size int) bool) (int, []string) {
	var evidence []string
	low := 576
	high := 1500

	// Sanity check with max size first
	if canPingFn(high) {
		evidence = append(evidence, fmt.Sprintf("MTU probe: %d successful", high))
		return high, evidence
	}

	// Binary search for max working size
	result := low
	for low <= high {
		mid := (low + high) / 2
		if canPingFn(mid) {
			result = mid
			evidence = append(evidence, fmt.Sprintf("MTU probe: %d successful", mid))
			low = mid + 1
		} else {
			evidence = append(evidence, fmt.Sprintf("MTU probe: %d failed", mid))
			high = mid - 1
		}
	}

	return result, evidence
}

// canPing tests if a packet of specified size (with DF bit) can reach the target
func canPing(ctx context.Context, target string, size int) bool {
	// Adjust for IP header (20 bytes) and ICMP header (8 bytes)
	// We want to send a packet with payload of approximately 'size' bytes
	// The ping command's -s flag specifies data size (payload only)
	dataSize := size - 28 // 20 byte IP header + 8 byte ICMP header

	if dataSize < 0 {
		dataSize = 0
	}

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		// Windows: -f sets DF bit, -l sets packet size
		// #nosec G204 — ping is hardcoded, target from spec
		cmd = exec.CommandContext(ctx, "ping", "-n", "1", "-f", "-l", fmt.Sprintf("%d", dataSize), target) // nosemgrep
	case "darwin":
		// macOS: -D sets DF bit, -s sets packet size
		// #nosec G204 — ping is hardcoded, target from spec
		cmd = exec.CommandContext(ctx, "ping", "-c", "1", "-D", "-s", fmt.Sprintf("%d", dataSize), target) // nosemgrep
	default: // linux
		// Linux: -M do sets DF bit, -s sets packet size
		// #nosec G204 — ping is hardcoded, target from spec
		cmd = exec.CommandContext(ctx, "ping", "-c", "1", "-M", "do", "-s", fmt.Sprintf("%d", dataSize), target) // nosemgrep
	}

	out, err := cmd.Output()
	outStr := string(out)

	if err != nil {
		return false
	}

	return !isFragmentationError(outStr)
}

// isFragmentationError reports whether ping output indicates the packet could
// not be sent at the requested size (fragmentation needed, overlong, or total
// loss), which means the MTU is too large for the path.
func isFragmentationError(output string) bool {
	return strings.Contains(output, "Frag needed") || strings.Contains(output, "Message too long") ||
		strings.Contains(output, "no answer") || strings.Contains(output, "Destination Host Unreachable") ||
		strings.Contains(output, "100% loss") || strings.Contains(output, "100.0% loss")
}
