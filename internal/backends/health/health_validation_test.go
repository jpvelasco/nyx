package health

import (
	"context"
	"testing"

	"github.com/jpvelasco/nyx/internal/models"
)

// Invalid ping targets must be rejected as StatusError before any ping
// subprocess is spawned.

func TestPingCheck_InvalidTarget_DashPrefixed(t *testing.T) {
	result, stats, err := PingCheck(context.Background(), "-n 3", 5)
	if err == nil {
		t.Fatal("expected error for dash-prefixed target")
	}
	if result.Status != models.StatusError {
		t.Fatalf("expected status error, got %s", result.Status)
	}
	if stats != nil {
		t.Errorf("expected nil stats for invalid target, got %+v", stats)
	}
}

func TestPingCheck_InvalidTarget_NotHostOrIP(t *testing.T) {
	result, _, err := PingCheck(context.Background(), "10.0.0.0/24", 1)
	if err == nil {
		t.Fatal("expected error for CIDR target")
	}
	if result.Status != models.StatusError {
		t.Fatalf("expected status error, got %s", result.Status)
	}
}

func TestPingCheck_ValidTarget_NotRejected(t *testing.T) {
	// A valid IP must not trip validation (ping may still fail/skip if the
	// host is unreachable, but it must not be an input-validation error).
	result, _, err := PingCheck(context.Background(), "127.0.0.1", 1)
	if result.Status == models.StatusError {
		t.Fatalf("valid target rejected as error: %s", result.Summary)
	}
	_ = err
}

func TestProbeMTU_InvalidTarget(t *testing.T) {
	result, err := ProbeMTU(context.Background(), "-w 2000", 1500)
	if err == nil {
		t.Fatal("expected error for dash-prefixed target")
	}
	if result.Status != models.StatusError {
		t.Fatalf("expected status error, got %s", result.Status)
	}
}
