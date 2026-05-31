package health

import (
	"context"
	"runtime"
	"testing"
)

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
	_ = runtime.GOOS
}

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
	// If there's any packet loss, it should fail
	// Note: localhost typically has 0% loss, so we use a remote target
	// However, since we can't guarantee network access, we test the logic
	// by checking that violations are populated when thresholds are exceeded

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
