package dns

import (
	"context"
	"testing"

	"github.com/velasco-jp/nyx/internal/models"
)

func TestResolveLocalhost(t *testing.T) {
	// localhost should always resolve to 127.0.0.1
	result, err := Resolve(context.Background(), "localhost", "")
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}
	if result.Status == models.StatusError {
		t.Skipf("DNS resolution not available in this environment: %s", result.Summary)
	}
	if result.CheckType != "dns_check" {
		t.Errorf("expected check_type 'dns_check', got %q", result.CheckType)
	}
	obs, ok := result.Observed["ips"]
	if !ok {
		t.Error("expected 'ips' in Observed")
	}
	_ = obs
}

func TestResolveExpectMatch(t *testing.T) {
	// localhost should resolve to 127.0.0.1
	result, err := ResolveExpect(context.Background(), "localhost", "", "127.0.0.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status == models.StatusError {
		t.Skipf("DNS not available: %s", result.Summary)
	}
	if result.Status != models.StatusPass {
		t.Errorf("expected pass for localhost→127.0.0.1, got %s: %s", result.Status, result.Summary)
	}
}

func TestResolveExpectMismatch(t *testing.T) {
	result, err := ResolveExpect(context.Background(), "localhost", "", "1.2.3.4")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status == models.StatusError {
		t.Skipf("DNS not available: %s", result.Summary)
	}
	if result.Status != models.StatusFail {
		t.Errorf("expected fail for localhost→1.2.3.4 mismatch, got %s", result.Status)
	}
	if len(result.Violations) == 0 {
		t.Error("expected violations for mismatch")
	}
}
