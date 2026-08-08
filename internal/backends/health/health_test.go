package health

import (
	"context"
	"encoding/json"
	"runtime"
	"strings"
	"testing"
	"time"
)

// -----------------------------------------------------------------------
// PingCheck tests
// -----------------------------------------------------------------------

func TestPingCheckLocalhost(t *testing.T) {
	// ping localhost should always succeed
	result, stats, err := PingCheck(context.Background(), "127.0.0.1", 3)
	if err != nil {
		t.Fatalf("PingCheck error: %v", err)
	}
	if result.CheckType != "network_health" {
		t.Errorf("expected check_type 'network_health', got %q", result.CheckType)
	}
	if result.Tool != "ping" {
		t.Errorf("expected tool 'ping', got %q", result.Tool)
	}
	if result.Target != "127.0.0.1" {
		t.Errorf("expected target '127.0.0.1', got %q", result.Target)
	}
	if result.Runner != "system" {
		t.Errorf("expected runner 'system', got %q", result.Runner)
	}
	if result.Status == "error" {
		t.Skipf("ping not available: %s", result.Summary)
	}
	if stats == nil {
		t.Fatal("expected non-nil stats")
	}
	if stats.Target != "127.0.0.1" {
		t.Errorf("expected stats target '127.0.0.1', got %q", stats.Target)
	}
	if stats.Sent != 3 {
		t.Errorf("expected 3 packets sent, got %d", stats.Sent)
	}
}

func TestPingCheckCancelled(t *testing.T) {
	// Cancel context immediately so ping never completes
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, stats, err := PingCheck(ctx, "127.0.0.1", 1)

	// Should return an error since context was cancelled
	if err == nil {
		t.Fatal("expected error from cancelled context")
	}
	if result == nil {
		t.Fatal("expected non-nil result even on cancelled context")
	}
	if result.Status != "error" {
		t.Errorf("expected status 'error' for cancelled ping, got %q", result.Status)
	}
	if !strings.Contains(result.Summary, "cancelled") {
		t.Errorf("expected summary to mention cancellation, got: %s", result.Summary)
	}
	// Stats may be nil or partial on cancellation
	if stats != nil && stats.Target != "127.0.0.1" {
		t.Errorf("expected stats target '127.0.0.1', got %q", stats.Target)
	}
}

func TestPingCheckTimeout(t *testing.T) {
	// Use a very short timeout — should trigger deadline exceeded
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()
	// Give the cancel a head start
	time.Sleep(2 * time.Millisecond)

	result, _, err := PingCheck(ctx, "127.0.0.1", 1)
	if err == nil {
		t.Fatal("expected error from timed-out context")
	}
	if result == nil {
		t.Fatal("expected non-nil result even on timeout")
	}
	if result.Status != "error" {
		t.Errorf("expected status 'error' for timed-out ping, got %q", result.Status)
	}
}

func TestPingCheckObservedFields(t *testing.T) {
	result, stats, err := PingCheck(context.Background(), "127.0.0.1", 2)
	if err != nil {
		t.Fatalf("PingCheck error: %v", err)
	}
	if result.Status == "error" {
		t.Skipf("ping not available: %s", result.Summary)
	}
	// Check observed fields
	if result.Observed == nil {
		t.Fatal("expected Observed map to be set")
	}
	if sent, ok := result.Observed["sent"].(int); !ok || sent != 2 {
		t.Errorf("expected observed sent=2, got %v", result.Observed["sent"])
	}
	if _, ok := result.Observed["received"]; !ok {
		t.Error("expected observed 'received' field")
	}
	if _, ok := result.Observed["loss_pct"]; !ok {
		t.Error("expected observed 'loss_pct' field")
	}
	if _, ok := result.Observed["avg_rtt_ms"]; !ok {
		t.Error("expected observed 'avg_rtt_ms' field")
	}
	// Stats should have received count
	if stats.Received != stats.Sent {
		t.Logf("warning: expected %d received == %d sent for localhost", stats.Received, stats.Sent)
	}
}

func TestPingCheckEvidence(t *testing.T) {
	result, _, err := PingCheck(context.Background(), "127.0.0.1", 1)
	if err != nil {
		t.Fatalf("PingCheck error: %v", err)
	}
	if result.Status == "error" {
		t.Skipf("ping not available: %s", result.Summary)
	}
	if len(result.Evidence) == 0 {
		t.Error("expected evidence to contain ping output")
	}
}

func TestPingCheckTiming(t *testing.T) {
	result, stats, err := PingCheck(context.Background(), "127.0.0.1", 1)
	if err != nil {
		t.Fatalf("PingCheck error: %v", err)
	}
	if result.Status == "error" {
		t.Skipf("ping not available: %s", result.Summary)
	}
	if result.StartedAt.IsZero() {
		t.Error("expected StartedAt to be set")
	}
	if result.FinishedAt.IsZero() {
		t.Error("expected FinishedAt to be set")
	}
	if result.DurationMs < 0 {
		t.Error("expected non-negative duration")
	}
	// Localhost should be fast
	if result.DurationMs > 5000 {
		t.Errorf("localhost ping took too long: %dms", result.DurationMs)
	}
	// RTT for localhost should be very low
	if stats.AvgRTTMs > 100 {
		t.Errorf("localhost avg RTT unexpectedly high: %.2fms", stats.AvgRTTMs)
	}
}

// -----------------------------------------------------------------------
// CheckLatencyAndLoss tests
// -----------------------------------------------------------------------

func TestCheckLatencyAndLossPass(t *testing.T) {
	// High threshold — localhost should easily pass
	result, err := CheckLatencyAndLoss(context.Background(), "127.0.0.1", 5000, 50)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status == "error" {
		t.Skipf("ping not available: %s", result.Summary)
	}
	if result.Status != "pass" {
		t.Errorf("expected pass for loose thresholds, got %s: %s", result.Status, result.Summary)
	}
	if result.Expected == nil {
		t.Fatal("expected Expected map to be set")
	}
	maxLat, ok := result.Expected["max_latency_ms"]
	if !ok {
		t.Error("expected max_latency_ms in Expected")
	}
	if maxLat != 5000.0 {
		t.Errorf("expected max_latency_ms 5000.0, got %v", maxLat)
	}
}

func TestCheckLatencyAndLossFail(t *testing.T) {
	// Test with max loss threshold of 0
	result, err := CheckLatencyAndLoss(context.Background(), "127.0.0.1", 5000, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status == "error" {
		t.Skipf("ping not available: %s", result.Summary)
	}
	// Verify Expected is properly set
	if result.Expected["max_loss_pct"] != 0.0 {
		t.Errorf("expected max_loss_pct 0 in Expected, got %v", result.Expected["max_loss_pct"])
	}
}

func TestCheckLatencyAndLossLatencyViolation(t *testing.T) {
	// Use a very low latency threshold — localhost should still be fast, but
	// if it exceeds 0.001ms, we should see a violation.
	// On most systems localhost ping is < 1ms, so set threshold extremely low.
	result, err := CheckLatencyAndLoss(context.Background(), "127.0.0.1", 0.001, 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status == "error" {
		t.Skipf("ping not available: %s", result.Summary)
	}
	// Localhost ping typically has nonzero RTT, so it should fail this threshold
	if result.Status == "fail" {
		found := false
		for _, v := range result.Violations {
			if strings.Contains(v, "latency") {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected latency violation in violations list")
		}
	} else {
		// If localhost is truly 0ms, it passes — that's also valid
		t.Logf("localhost latency was extremely low, no violation triggered")
	}
}

func TestCheckLatencyAndLossZeroThresholds(t *testing.T) {
	// Zero thresholds mean "don't check" — should always pass if ping succeeds
	result, err := CheckLatencyAndLoss(context.Background(), "127.0.0.1", 0, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status == "error" {
		t.Skipf("ping not available: %s", result.Summary)
	}
	if result.Status != "pass" {
		t.Errorf("expected pass with zero thresholds (no checks), got %s", result.Status)
	}
	if len(result.Violations) > 0 {
		t.Errorf("expected no violations with zero thresholds, got: %v", result.Violations)
	}
}

func TestCheckLatencyAndLossExpectedFields(t *testing.T) {
	result, err := CheckLatencyAndLoss(context.Background(), "127.0.0.1", 100, 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status == "error" {
		t.Skipf("ping not available: %s", result.Summary)
	}
	if result.Expected == nil {
		t.Fatal("expected Expected map")
	}
	if result.Expected["max_latency_ms"] != 100.0 {
		t.Errorf("expected max_latency_ms 100.0, got %v", result.Expected["max_latency_ms"])
	}
	if result.Expected["max_loss_pct"] != 5.0 {
		t.Errorf("expected max_loss_pct 5.0, got %v", result.Expected["max_loss_pct"])
	}
}

// -----------------------------------------------------------------------
// classifyLatencyLoss tests (pure threshold logic)
// -----------------------------------------------------------------------

func TestClassifyLatencyLoss(t *testing.T) {
	tests := []struct {
		name         string
		stats        *PingStats
		maxLatencyMs float64
		maxLossPct   float64
		wantStatus   string
		wantViolated bool
	}{
		{"no violations", &PingStats{LossPct: 0, AvgRTTMs: 5}, 100, 10, "pass", false},
		{"loss violation", &PingStats{LossPct: 50, AvgRTTMs: 5}, 100, 10, "fail", true},
		{"latency violation", &PingStats{LossPct: 0, AvgRTTMs: 500}, 100, 10, "fail", true},
		{"both violations", &PingStats{LossPct: 50, AvgRTTMs: 500}, 100, 10, "fail", true},
		{"zero thresholds skip checks", &PingStats{LossPct: 50, AvgRTTMs: 500}, 0, 0, "pass", false},
		{"threshold boundary not a violation", &PingStats{LossPct: 10, AvgRTTMs: 100}, 100, 10, "pass", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			status, violations, summary := classifyLatencyLoss(tc.stats, tc.maxLatencyMs, tc.maxLossPct)
			if string(status) != tc.wantStatus {
				t.Errorf("expected status %s, got %s", tc.wantStatus, status)
			}
			if tc.wantViolated {
				if len(violations) == 0 {
					t.Error("expected violations, got none")
				}
				if !strings.Contains(summary, "health check failed") {
					t.Errorf("expected summary to mention failure, got: %s", summary)
				}
			} else {
				if len(violations) != 0 {
					t.Errorf("expected no violations, got %v", violations)
				}
				if summary != "" {
					t.Errorf("expected empty summary, got: %s", summary)
				}
			}
		})
	}
}

func TestPingCheckUnreachable(t *testing.T) {
	// TEST-NET address — unreachable without cancelling the context, so
	// PingCheck should report StatusError via the ping error path.
	result, stats, err := PingCheck(context.Background(), "192.0.2.1", 1)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if err == nil {
		t.Skipf("unexpected success pinging TEST-NET: %s", result.Summary)
	}
	if result.Status != "error" {
		t.Errorf("expected status 'error', got %s", result.Status)
	}
	if !strings.Contains(result.Summary, "ping error") {
		t.Errorf("expected summary to mention ping error, got: %s", result.Summary)
	}
	if stats == nil {
		t.Fatal("expected non-nil stats on error path")
	}
	if stats.Sent != 1 {
		t.Errorf("expected sent 1, got %d", stats.Sent)
	}
}

// -----------------------------------------------------------------------
// ProbeMTU tests
// -----------------------------------------------------------------------

func TestProbeMTULocalhost(t *testing.T) {
	result, err := ProbeMTU(context.Background(), "127.0.0.1", 1500)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status == "error" {
		t.Skipf("ping not available: %s", result.Summary)
	}
	if result.CheckType != "network_health" {
		t.Errorf("expected check_type 'network_health', got %q", result.CheckType)
	}
	if result.Tool != "ping" {
		t.Errorf("expected tool 'ping', got %q", result.Tool)
	}
	if result.Target != "127.0.0.1" {
		t.Errorf("expected target '127.0.0.1', got %q", result.Target)
	}
	// Localhost loopback should support full MTU
	if mtu, ok := result.Observed["mtu"].(int); ok {
		if mtu < 576 {
			t.Errorf("discovered MTU %d is unrealistically low", mtu)
		}
	}
}

func TestProbeMTUPassStatus(t *testing.T) {
	// Use a low expected MTU that localhost should easily meet
	result, err := ProbeMTU(context.Background(), "127.0.0.1", 576)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status == "error" {
		t.Skipf("ping not available: %s", result.Summary)
	}
	if result.Status != "pass" {
		t.Errorf("expected pass for low MTU threshold, got %s: %s", result.Status, result.Summary)
	}
}

func TestProbeMTUExpectedFields(t *testing.T) {
	result, err := ProbeMTU(context.Background(), "127.0.0.1", 1500)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status == "error" {
		t.Skipf("ping not available: %s", result.Summary)
	}
	if result.Expected == nil {
		t.Fatal("expected Expected map")
	}
	if result.Expected["mtu"] != 1500 {
		t.Errorf("expected mtu 1500 in Expected, got %v", result.Expected["mtu"])
	}
}

func TestProbeMTUEvidence(t *testing.T) {
	result, err := ProbeMTU(context.Background(), "127.0.0.1", 1500)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status == "error" {
		t.Skipf("ping not available: %s", result.Summary)
	}
	if len(result.Evidence) == 0 {
		t.Error("expected evidence from MTU probes")
	}
	// Last evidence entry should be JSON MTUResult
	lastEvidence := result.Evidence[len(result.Evidence)-1]
	var mtuRes MTUResult
	if err := json.Unmarshal([]byte(lastEvidence), &mtuRes); err != nil {
		t.Fatalf("expected last evidence to be JSON MTUResult, got: %s", lastEvidence)
	}
	if mtuRes.Target != "127.0.0.1" {
		t.Errorf("expected MTUResult target '127.0.0.1', got %q", mtuRes.Target)
	}
	if mtuRes.RequestedMTU != 1500 {
		t.Errorf("expected MTUResult requested 1500, got %d", mtuRes.RequestedMTU)
	}
}

func TestProbeMTUWarnStatus(t *testing.T) {
	// Expected slightly above the loopback MTU (1500) — discovered 1500 is
	// within 10% of 1600, so the warn path should trigger.
	result, err := ProbeMTU(context.Background(), "127.0.0.1", 1600)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status == "error" {
		t.Skipf("ping not available: %s", result.Summary)
	}
	if result.Status == "fail" {
		t.Skipf("loopback MTU below 90%% of 1600 on this host: %s", result.Summary)
	}
	if result.Status != "warn" {
		t.Errorf("expected warn for MTU 1600 with 1500 discovered, got %s: %s", result.Status, result.Summary)
	}
}

func TestProbeMTUTiming(t *testing.T) {
	result, err := ProbeMTU(context.Background(), "127.0.0.1", 1500)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status == "error" {
		t.Skipf("ping not available: %s", result.Summary)
	}
	if result.StartedAt.IsZero() {
		t.Error("expected StartedAt to be set")
	}
	if result.FinishedAt.IsZero() {
		t.Error("expected FinishedAt to be set")
	}
	if result.DurationMs < 0 {
		t.Error("expected non-negative duration")
	}
}

// -----------------------------------------------------------------------
// parsePingOutput tests (platform-specific parsing)
// -----------------------------------------------------------------------

func TestParseLinuxPingOutput(t *testing.T) {
	output := `PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.042 ms
64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.038 ms

--- 127.0.0.1 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1003ms
rtt min/avg/max/mdev = 0.038/0.040/0.042/0.002 ms
`
	stats := &PingStats{Sent: 2}
	parseLinuxPingOutput(output, stats)
	if stats.LossPct != 0 {
		t.Errorf("expected 0%% loss, got %.1f%%", stats.LossPct)
	}
	if stats.Received != 2 {
		t.Errorf("expected received 2, got %d", stats.Received)
	}
	if stats.AvgRTTMs != 0.040 {
		t.Errorf("expected avg RTT 0.040, got %.3f", stats.AvgRTTMs)
	}
	if stats.MinRTTMs != 0.038 {
		t.Errorf("expected min RTT 0.038, got %.3f", stats.MinRTTMs)
	}
	if stats.MaxRTTMs != 0.042 {
		t.Errorf("expected max RTT 0.042, got %.3f", stats.MaxRTTMs)
	}
}

func TestParseLinuxPingOutputWithLoss(t *testing.T) {
	output := `PING 192.168.1.1 (192.168.1.1) 56(84) bytes of data.
64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=1.234 ms

--- 192.168.1.1 ping statistics ---
10 packets transmitted, 7 received, 30% packet loss, time 9003ms
rtt min/avg/max/mdev = 0.500/1.234/2.500/0.600 ms
`
	stats := &PingStats{Sent: 10}
	parseLinuxPingOutput(output, stats)
	if stats.LossPct != 30 {
		t.Errorf("expected 30%% loss, got %.1f%%", stats.LossPct)
	}
	if stats.Received != 7 {
		t.Errorf("expected received 7, got %d", stats.Received)
	}
	if stats.AvgRTTMs != 1.234 {
		t.Errorf("expected avg RTT 1.234, got %.3f", stats.AvgRTTMs)
	}
	if stats.MinRTTMs != 0.500 {
		t.Errorf("expected min RTT 0.500, got %.3f", stats.MinRTTMs)
	}
	if stats.MaxRTTMs != 2.500 {
		t.Errorf("expected max RTT 2.500, got %.3f", stats.MaxRTTMs)
	}
}

func TestParseLinuxPingOutput100PercentLoss(t *testing.T) {
	output := `PING 192.0.2.1 (192.0.2.1) 56(84) bytes of data.

--- 192.0.2.1 ping statistics ---
5 packets transmitted, 0 received, 100% packet loss, time 4003ms
`
	stats := &PingStats{Sent: 5}
	parseLinuxPingOutput(output, stats)
	if stats.LossPct != 100 {
		t.Errorf("expected 100%% loss, got %.1f%%", stats.LossPct)
	}
	if stats.Received != 0 {
		t.Errorf("expected received 0, got %d", stats.Received)
	}
	if stats.AvgRTTMs != 0 {
		t.Errorf("expected avg RTT 0 (no replies), got %.3f", stats.AvgRTTMs)
	}
}

func TestParseLinuxPingOutputDecimalLoss(t *testing.T) {
	output := `--- 10.0.0.1 ping statistics ---
10 packets transmitted, 9 received, 10.0% packet loss, time 9003ms
rtt min/avg/max/mdev = 1.000/2.500/5.000/1.200 ms
`
	stats := &PingStats{Sent: 10}
	parseLinuxPingOutput(output, stats)
	if stats.LossPct != 10.0 {
		t.Errorf("expected 10.0%% loss, got %.1f%%", stats.LossPct)
	}
	if stats.Received != 9 {
		t.Errorf("expected received 9 with 10%% loss, got %d", stats.Received)
	}
}

func TestParseLinuxPingOutputNoRTTLine(t *testing.T) {
	// Output with loss but no RTT line (all packets lost)
	output := `PING 10.10.10.1 (10.10.10.1) 56(84) bytes of data.

--- 10.10.10.1 ping statistics ---
3 packets transmitted, 0 received, 100% packet loss, time 2003ms
`
	stats := &PingStats{Sent: 3}
	parseLinuxPingOutput(output, stats)
	if stats.LossPct != 100 {
		t.Errorf("expected 100%% loss, got %.1f%%", stats.LossPct)
	}
	if stats.AvgRTTMs != 0 {
		t.Errorf("expected avg RTT 0, got %.3f", stats.AvgRTTMs)
	}
	// Min and Max should be 0 when no RTT line
	if stats.MinRTTMs != 0 {
		t.Errorf("expected min RTT 0, got %.3f", stats.MinRTTMs)
	}
	if stats.MaxRTTMs != 0 {
		t.Errorf("expected max RTT 0, got %.3f", stats.MaxRTTMs)
	}
}

func TestParsePingOutputDarwin(t *testing.T) {
	output := `PING 127.0.0.1 (127.0.0.1): 56 data bytes
64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0.042 ms
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.038 ms

--- 127.0.0.1 ping statistics ---
2 packets transmitted, 2 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 0.038/0.040/0.042/0.002 ms
`
	stats := &PingStats{Sent: 2}
	parseDarwinPingOutput(output, stats)
	if stats.LossPct != 0 {
		t.Errorf("expected 0%% loss, got %.1f%%", stats.LossPct)
	}
	if stats.Received != 2 {
		t.Errorf("expected received 2, got %d", stats.Received)
	}
	if stats.AvgRTTMs != 0.040 {
		t.Errorf("expected avg RTT 0.040, got %.3f", stats.AvgRTTMs)
	}
	if stats.MinRTTMs != 0.038 {
		t.Errorf("expected min RTT 0.038, got %.3f", stats.MinRTTMs)
	}
	if stats.MaxRTTMs != 0.042 {
		t.Errorf("expected max RTT 0.042, got %.3f", stats.MaxRTTMs)
	}
}

func TestParsePingOutputDarwinWithLoss(t *testing.T) {
	output := `--- 10.0.0.1 ping statistics ---
10 packets transmitted, 8 packets received, 20.0% packet loss
round-trip min/avg/max/stddev = 0.500/1.500/3.000/0.800 ms
`
	stats := &PingStats{Sent: 10}
	parseDarwinPingOutput(output, stats)
	if stats.LossPct != 20.0 {
		t.Errorf("expected 20.0%% loss, got %.1f%%", stats.LossPct)
	}
	if stats.Received != 8 {
		t.Errorf("expected received 8, got %d", stats.Received)
	}
}

func TestParsePingOutputDarwin100PercentLoss(t *testing.T) {
	output := `--- 192.0.2.1 ping statistics ---
5 packets transmitted, 0 packets received, 100.0% packet loss
`
	stats := &PingStats{Sent: 5}
	parseDarwinPingOutput(output, stats)
	if stats.LossPct != 100.0 {
		t.Errorf("expected 100.0%% loss, got %.1f%%", stats.LossPct)
	}
	if stats.Received != 0 {
		t.Errorf("expected received 0, got %d", stats.Received)
	}
}

func TestParsePingOutputDarwinNoRTTLine(t *testing.T) {
	output := `--- 192.0.2.1 ping statistics ---
3 packets transmitted, 0 packets received, 100.0% packet loss
`
	stats := &PingStats{Sent: 3}
	parseDarwinPingOutput(output, stats)
	if stats.AvgRTTMs != 0 {
		t.Errorf("expected avg RTT 0, got %.3f", stats.AvgRTTMs)
	}
}

func TestParsePingOutputWindows(t *testing.T) {
	output := `Ping statistics for 127.0.0.1:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 0ms, Maximum = 0ms, Average = 0ms
`
	stats := &PingStats{Sent: 4}
	parseWindowsPingOutput(output, stats)
	if stats.LossPct != 0 {
		t.Errorf("expected 0%% loss, got %.1f%%", stats.LossPct)
	}
	if stats.Received != 4 {
		t.Errorf("expected received 4, got %d", stats.Received)
	}
	if stats.AvgRTTMs != 0 {
		t.Errorf("expected avg RTT 0, got %.3f", stats.AvgRTTMs)
	}
	if stats.MinRTTMs != 0 {
		t.Errorf("expected min RTT 0, got %.3f", stats.MinRTTMs)
	}
	if stats.MaxRTTMs != 0 {
		t.Errorf("expected max RTT 0, got %.3f", stats.MaxRTTMs)
	}
}

func TestParsePingOutputWindowsWithLatency(t *testing.T) {
	output := `Ping statistics for 192.168.1.1:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 1ms, Maximum = 5ms, Average = 2ms
`
	stats := &PingStats{Sent: 4}
	parseWindowsPingOutput(output, stats)
	if stats.LossPct != 0 {
		t.Errorf("expected 0%% loss, got %.1f%%", stats.LossPct)
	}
	if stats.AvgRTTMs != 2 {
		t.Errorf("expected avg RTT 2, got %.3f", stats.AvgRTTMs)
	}
	if stats.MinRTTMs != 1 {
		t.Errorf("expected min RTT 1, got %.3f", stats.MinRTTMs)
	}
	if stats.MaxRTTMs != 5 {
		t.Errorf("expected max RTT 5, got %.3f", stats.MaxRTTMs)
	}
}

func TestParsePingOutputWindowsWithLoss(t *testing.T) {
	output := `Ping statistics for 192.0.2.1:
    Packets: Sent = 4, Received = 2, Lost = 2 (50% loss),
Approximate round trip times in milli-seconds:
    Minimum = 10ms, Maximum = 20ms, Average = 15ms
`
	stats := &PingStats{Sent: 4}
	parseWindowsPingOutput(output, stats)
	if stats.LossPct != 50 {
		t.Errorf("expected 50%% loss, got %.1f%%", stats.LossPct)
	}
	if stats.Received != 2 {
		t.Errorf("expected received 2, got %d", stats.Received)
	}
}

func TestParsePingOutputWindows100PercentLoss(t *testing.T) {
	output := `Ping statistics for 192.0.2.1:
    Packets: Sent = 4, Received = 0, Lost = 4 (100% loss),
`
	stats := &PingStats{Sent: 4}
	parseWindowsPingOutput(output, stats)
	if stats.LossPct != 100 {
		t.Errorf("expected 100%% loss, got %.1f%%", stats.LossPct)
	}
	if stats.Received != 0 {
		t.Errorf("expected received 0, got %d", stats.Received)
	}
}

func TestParsePingOutputWindowsNoStats(t *testing.T) {
	// Empty output — should not crash, defaults should apply
	stats := &PingStats{Sent: 4}
	parseWindowsPingOutput("", stats)
	if stats.LossPct != 0 {
		t.Errorf("expected 0%% loss for empty output, got %.1f%%", stats.LossPct)
	}
	if stats.Received != 4 {
		t.Errorf("expected received == sent for empty output, got %d", stats.Received)
	}
}

// -----------------------------------------------------------------------
// parsePingOutput dispatch test (runtime platform)
// -----------------------------------------------------------------------

func TestParseLinuxPingOutputNoLossLine(t *testing.T) {
	// Output without a packet-loss line — received should default to sent.
	output := `PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
rtt min/avg/max/mdev = 0.038/0.040/0.042/0.002 ms
`
	stats := &PingStats{Sent: 4}
	parseLinuxPingOutput(output, stats)
	if stats.Received != 4 {
		t.Errorf("expected received == sent (4) when no loss line, got %d", stats.Received)
	}
	if stats.LossPct != 0 {
		t.Errorf("expected 0%% loss, got %.1f%%", stats.LossPct)
	}
	if stats.AvgRTTMs != 0.040 {
		t.Errorf("expected avg RTT 0.040, got %.3f", stats.AvgRTTMs)
	}
}

func TestParsePingOutputDarwinNoLossLine(t *testing.T) {
	// Output without a packet-loss line — received should default to sent.
	output := `round-trip min/avg/max/stddev = 0.100/0.250/0.500/0.150 ms
`
	stats := &PingStats{Sent: 3}
	parseDarwinPingOutput(output, stats)
	if stats.Received != 3 {
		t.Errorf("expected received == sent (3) when no loss line, got %d", stats.Received)
	}
	if stats.LossPct != 0 {
		t.Errorf("expected 0%% loss, got %.1f%%", stats.LossPct)
	}
}

func TestParsePingOutputDispatchesCorrectPlatform(t *testing.T) {
	// Verify the dispatch routes to the right parser based on runtime.GOOS.
	// We can't change runtime.GOOS, so we test the current platform.
	var output string
	switch runtime.GOOS {
	case "windows":
		output = `Ping statistics for 10.0.0.1:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 1ms, Maximum = 3ms, Average = 2ms
`
	case "darwin":
		output = `--- 10.0.0.1 ping statistics ---
4 packets transmitted, 4 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 1.000/2.000/3.000/0.500 ms
`
	default: // linux
		output = `--- 10.0.0.1 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3003ms
rtt min/avg/max/mdev = 1.000/2.000/3.000/0.500 ms
`
	}

	stats := parsePingOutput(output, "10.0.0.1", 4)
	if stats.Target != "10.0.0.1" {
		t.Errorf("expected target '10.0.0.1', got %q", stats.Target)
	}
	if stats.Sent != 4 {
		t.Errorf("expected sent 4, got %d", stats.Sent)
	}
	if stats.LossPct != 0 {
		t.Errorf("expected 0%% loss, got %.1f%%", stats.LossPct)
	}
	if stats.Received != 4 {
		t.Errorf("expected received 4, got %d", stats.Received)
	}
	if stats.AvgRTTMs != 2.0 {
		t.Errorf("expected avg RTT 2.0, got %.3f", stats.AvgRTTMs)
	}
}

// -----------------------------------------------------------------------
// mtuBinarySearch tests (pure search logic)
// -----------------------------------------------------------------------

func TestMTUBinarySearch_AllSizesSucceed(t *testing.T) {
	mtu, evidence := mtuBinarySearch(func(int) bool { return true })
	if mtu != 1500 {
		t.Errorf("expected MTU 1500 when all sizes succeed, got %d", mtu)
	}
	if len(evidence) != 1 || !strings.Contains(evidence[0], "1500 successful") {
		t.Errorf("expected single 1500-successful evidence entry, got %v", evidence)
	}
}

func TestMTUBinarySearch_NoSizesSucceed(t *testing.T) {
	mtu, evidence := mtuBinarySearch(func(int) bool { return false })
	if mtu != 576 {
		t.Errorf("expected MTU 576 when no sizes succeed, got %d", mtu)
	}
	if len(evidence) == 0 {
		t.Error("expected evidence from failed probes")
	}
}

func TestMTUBinarySearch_PartialSizesSucceed(t *testing.T) {
	// Sizes up to 1200 work — search should converge on 1200 and produce
	// mixed success/failure evidence covering both loop branches.
	mtu, evidence := mtuBinarySearch(func(size int) bool { return size <= 1200 })
	if mtu != 1200 {
		t.Errorf("expected MTU 1200, got %d", mtu)
	}
	successful, failed := 0, 0
	for _, e := range evidence {
		if strings.Contains(e, "successful") {
			successful++
		}
		if strings.Contains(e, "failed") {
			failed++
		}
	}
	if successful == 0 || failed == 0 {
		t.Errorf("expected mixed evidence, got successful=%d failed=%d", successful, failed)
	}
}

// -----------------------------------------------------------------------
// isFragmentationError tests (pure output classification)
// -----------------------------------------------------------------------

func TestIsFragmentationError(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   bool
	}{
		{"frag needed", "Frag needed and DF set", true},
		{"message too long", "Message too long", true},
		{"no answer", "no answer yet for icmp_seq=1", true},
		{"destination unreachable", "Destination Host Unreachable", true},
		{"100 percent loss", "Packets: Sent = 4, Received = 0, Lost = 4 (100% loss),", true},
		{"100.0 percent loss", "Packets: Sent = 4, Received = 0, Lost = 4 (100.0% loss),", true},
		{"normal reply", "64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.042 ms", false},
		{"empty output", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isFragmentationError(tc.output); got != tc.want {
				t.Errorf("isFragmentationError(%q) = %v, want %v", tc.output, got, tc.want)
			}
		})
	}
}

// -----------------------------------------------------------------------
// probeMTUBinarySearch tests
// -----------------------------------------------------------------------

func TestProbeMTUBinarySearchLocalhost(t *testing.T) {
	mtu, evidence := probeMTUBinarySearch(context.Background(), "127.0.0.1")
	if mtu < 576 {
		t.Errorf("discovered MTU %d is below minimum 576", mtu)
	}
	if len(evidence) == 0 {
		t.Error("expected non-empty evidence from binary search")
	}
	// Evidence should contain probe results
	found := false
	for _, e := range evidence {
		if strings.Contains(e, "MTU probe:") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected evidence to contain MTU probe entries")
	}
}

func TestProbeMTUBinarySearchUnreachable(t *testing.T) {
	// Target that should not respond — binary search should still complete
	// with a low MTU (the low bound)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	mtu, evidence := probeMTUBinarySearch(ctx, "192.0.2.1")
	// Should return low (576) since no size succeeds
	if mtu != 576 {
		t.Logf("MTU for unreachable host: %d (expected 576)", mtu)
	}
	if len(evidence) == 0 {
		t.Error("expected non-empty evidence even for unreachable target")
	}
}

func TestProbeMTUBinarySearchCancellation(t *testing.T) {
	// Cancel early — should still return some result
	ctx, cancel := context.WithCancel(context.Background())
	// Don't cancel immediately — let the first probe (1500) run
	// but cancel after a short delay
	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()
	mtu, evidence := probeMTUBinarySearch(ctx, "127.0.0.1")
	// Should return something even if cancelled mid-search
	if mtu < 576 {
		t.Errorf("discovered MTU %d is below minimum 576", mtu)
	}
	_ = evidence
}

// -----------------------------------------------------------------------
// canPing tests
// -----------------------------------------------------------------------

func TestCanPingLocalhost(t *testing.T) {
	// Small packet should succeed
	if !canPing(context.Background(), "127.0.0.1", 576) {
		t.Error("expected canPing to succeed for localhost with 576 bytes")
	}
}

func TestCanPingLocalhostLargePacket(t *testing.T) {
	// Standard MTU should succeed on localhost
	if !canPing(context.Background(), "127.0.0.1", 1500) {
		t.Error("expected canPing to succeed for localhost with 1500 bytes")
	}
}

func TestCanPingUnreachableHost(t *testing.T) {
	// Should return false for unreachable host
	result := canPing(context.Background(), "192.0.2.1", 576)
	if result {
		t.Error("expected canPing to fail for unreachable host 192.0.2.1")
	}
}

func TestCanPingCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := canPing(ctx, "127.0.0.1", 576)
	// Should fail when context is cancelled
	if result {
		t.Error("expected canPing to fail with cancelled context")
	}
}

func TestCanPingTinyPacket(t *testing.T) {
	// Very small size — dataSize would be negative, clamped to 0
	result := canPing(context.Background(), "127.0.0.1", 10)
	if !result {
		t.Error("expected canPing to succeed with tiny packet size (clamped to 0)")
	}
}

// -----------------------------------------------------------------------
// runPing tests
// -----------------------------------------------------------------------

func TestRunPingLocalhost(t *testing.T) {
	output, err := runPing(context.Background(), "127.0.0.1", 1)
	if err != nil {
		t.Fatalf("runPing error: %v", err)
	}
	if output == "" {
		t.Error("expected non-empty ping output")
	}
}

func TestRunPingCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	output, err := runPing(ctx, "127.0.0.1", 1)
	if err == nil {
		t.Fatal("expected error from cancelled context")
	}
	// Output may be empty on cancellation
	_ = output
}

// -----------------------------------------------------------------------
// PingStats and MTUResult JSON serialization
// -----------------------------------------------------------------------

func TestPingStatsJSON(t *testing.T) {
	stats := &PingStats{
		Target:   "10.0.0.1",
		Sent:     10,
		Received: 8,
		LossPct:  20.0,
		AvgRTTMs: 1.5,
		MinRTTMs: 0.5,
		MaxRTTMs: 3.0,
	}
	data, err := json.Marshal(stats)
	if err != nil {
		t.Fatalf("failed to marshal PingStats: %v", err)
	}
	var decoded PingStats
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal PingStats: %v", err)
	}
	if decoded.Target != stats.Target {
		t.Errorf("target mismatch: %q vs %q", decoded.Target, stats.Target)
	}
	if decoded.Sent != stats.Sent {
		t.Errorf("sent mismatch: %d vs %d", decoded.Sent, stats.Sent)
	}
}

func TestMTUResultJSON(t *testing.T) {
	mtu := &MTUResult{
		Target:        "10.0.0.1",
		DiscoveredMTU: 1500,
		RequestedMTU:  1500,
	}
	data, err := json.Marshal(mtu)
	if err != nil {
		t.Fatalf("failed to marshal MTUResult: %v", err)
	}
	var decoded MTUResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal MTUResult: %v", err)
	}
	if decoded.Target != mtu.Target {
		t.Errorf("target mismatch: %q vs %q", decoded.Target, mtu.Target)
	}
	if decoded.DiscoveredMTU != mtu.DiscoveredMTU {
		t.Errorf("discovered MTU mismatch: %d vs %d", decoded.DiscoveredMTU, mtu.DiscoveredMTU)
	}
}

// -----------------------------------------------------------------------
// Regex pattern tests
// -----------------------------------------------------------------------

func TestRegexLinuxPacketLoss(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"0% packet loss", "0"},
		{"50% packet loss", "50"},
		{"100% packet loss", "100"},
		{"10.5% packet loss", "10.5"},
		{"0.0% packet loss", "0.0"},
	}
	for _, tc := range tests {
		m := rePktLossLinux.FindStringSubmatch(tc.input)
		if m == nil {
			t.Errorf("rePktLossLinux failed to match: %q", tc.input)
			continue
		}
		if m[1] != tc.want {
			t.Errorf("rePktLossLinux: got %q, want %q for %q", m[1], tc.want, tc.input)
		}
	}
}

func TestRegexLinuxRTT(t *testing.T) {
	input := "rtt min/avg/max/mdev = 0.123/0.456/0.789/0.100 ms"
	m := reAvgRTTLinux.FindStringSubmatch(input)
	if m == nil {
		t.Fatal("reAvgRTTLinux failed to match")
	}
	if m[1] != "0.123" {
		t.Errorf("min RTT: got %q, want 0.123", m[1])
	}
	if m[2] != "0.456" {
		t.Errorf("avg RTT: got %q, want 0.456", m[2])
	}
	if m[3] != "0.789" {
		t.Errorf("max RTT: got %q, want 0.789", m[3])
	}
}

func TestRegexWindowsPacketLoss(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"(0% loss)", "0"},
		{"(50% loss)", "50"},
		{"(100% loss)", "100"},
	}
	for _, tc := range tests {
		m := rePktLossWindows.FindStringSubmatch(tc.input)
		if m == nil {
			t.Errorf("rePktLossWindows failed to match: %q", tc.input)
			continue
		}
		if m[1] != tc.want {
			t.Errorf("rePktLossWindows: got %q, want %q for %q", m[1], tc.want, tc.input)
		}
	}
}

func TestRegexWindowsRTT(t *testing.T) {
	input := "Average = 12ms"
	m := reAvgRTTWindows.FindStringSubmatch(input)
	if m == nil {
		t.Fatal("reAvgRTTWindows failed to match")
	}
	if m[1] != "12" {
		t.Errorf("avg RTT: got %q, want 12", m[1])
	}
}

func TestRegexWindowsMinMax(t *testing.T) {
	input := "Minimum = 10ms, Maximum = 20ms"
	m := reMinMaxWindows.FindStringSubmatch(input)
	if m == nil {
		t.Fatal("reMinMaxWindows failed to match")
	}
	if m[1] != "10" {
		t.Errorf("min RTT: got %q, want 10", m[1])
	}
	if m[2] != "20" {
		t.Errorf("max RTT: got %q, want 20", m[2])
	}
}

func TestRegexDarwinRTT(t *testing.T) {
	input := "min/avg/max/stddev = 0.100/0.250/0.500/0.150 ms"
	m := reRTTDarwin.FindStringSubmatch(input)
	if m == nil {
		t.Fatal("reRTTDarwin failed to match")
	}
	if m[1] != "0.100" {
		t.Errorf("min RTT: got %q, want 0.100", m[1])
	}
	if m[2] != "0.250" {
		t.Errorf("avg RTT: got %q, want 0.250", m[2])
	}
	if m[3] != "0.500" {
		t.Errorf("max RTT: got %q, want 0.500", m[3])
	}
}

func TestRegexDarwinPacketLoss(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"0.0% packet loss", "0.0"},
		{"25.0% packet loss", "25.0"},
		{"100.0% packet loss", "100.0"},
	}
	for _, tc := range tests {
		m := rePktLossDarwin.FindStringSubmatch(tc.input)
		if m == nil {
			t.Errorf("rePktLossDarwin failed to match: %q", tc.input)
			continue
		}
		if m[1] != tc.want {
			t.Errorf("rePktLossDarwin: got %q, want %q for %q", m[1], tc.want, tc.input)
		}
	}
}

func TestRegexNoMatch(t *testing.T) {
	// Verify regexes don't match unrelated text
	if rePktLossLinux.FindStringSubmatch("no match here") != nil {
		t.Error("rePktLossLinux should not match unrelated text")
	}
	if rePktLossWindows.FindStringSubmatch("no match here") != nil {
		t.Error("rePktLossWindows should not match unrelated text")
	}
	if rePktLossDarwin.FindStringSubmatch("no match here") != nil {
		t.Error("rePktLossDarwin should not match unrelated text")
	}
}

// -----------------------------------------------------------------------
// ProbeMTU status edge cases
// -----------------------------------------------------------------------

func TestProbeMTUWarningThreshold(t *testing.T) {
	// We can't easily force a warn status without mocking, but we can verify
	// the status logic by checking the result structure.
	result, err := ProbeMTU(context.Background(), "127.0.0.1", 576)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status == "error" {
		t.Skipf("ping not available: %s", result.Summary)
	}
	// Localhost with 576 should pass (discovered >= expected)
	if result.Status != "pass" {
		t.Errorf("expected pass for MTU 576, got %s", result.Status)
	}
}

func TestProbeMTUFailStatus(t *testing.T) {
	// Use a very high expected MTU — localhost won't reach it, so should fail
	// The binary search on localhost finds the real MTU (typically 1500),
	// which is far below 9999, triggering the fail path.
	result, err := ProbeMTU(context.Background(), "127.0.0.1", 9999)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status == "error" {
		t.Skipf("ping not available: %s", result.Summary)
	}
	// Discovered MTU should be < 9999, triggering fail path
	if result.Status != "fail" {
		t.Errorf("expected fail for MTU 9999, got %s: %s", result.Status, result.Summary)
	}
	if len(result.Violations) == 0 {
		t.Error("expected violations for fail status")
	}
}

// -----------------------------------------------------------------------
// CheckLatencyAndLoss error path
// -----------------------------------------------------------------------

func TestCheckLatencyAndLossErrorPath(t *testing.T) {
	// Cancel context so PingCheck returns error status
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := CheckLatencyAndLoss(ctx, "127.0.0.1", 100, 5)
	// Should propagate the error
	if err == nil {
		t.Fatal("expected error from cancelled context")
	}
	if result == nil {
		t.Fatal("expected non-nil result even on error")
	}
	if result.Status != "error" {
		t.Errorf("expected status 'error', got %q", result.Status)
	}
	// Expected should still be set even on error
	if result.Expected == nil {
		t.Fatal("expected Expected map even on error path")
	}
	if result.Expected["max_latency_ms"] != 100.0 {
		t.Errorf("expected max_latency_ms in Expected, got %v", result.Expected["max_latency_ms"])
	}
}

// -----------------------------------------------------------------------
// Summary format tests
// -----------------------------------------------------------------------

func TestPingCheckSummaryFormat(t *testing.T) {
	result, _, err := PingCheck(context.Background(), "127.0.0.1", 2)
	if err != nil {
		t.Fatalf("PingCheck error: %v", err)
	}
	if result.Status == "error" {
		t.Skipf("ping not available: %s", result.Summary)
	}
	// Summary should contain key info
	if !strings.Contains(result.Summary, "127.0.0.1") {
		t.Error("expected summary to contain target")
	}
	if !strings.Contains(result.Summary, "loss") {
		t.Error("expected summary to mention loss")
	}
}

func TestProbeMTUSummaryContainsMTU(t *testing.T) {
	result, err := ProbeMTU(context.Background(), "127.0.0.1", 1500)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status == "error" {
		t.Skipf("ping not available: %s", result.Summary)
	}
	if !strings.Contains(result.Summary, "MTU") {
		t.Error("expected summary to mention MTU")
	}
}
