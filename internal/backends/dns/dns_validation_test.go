package dns

import (
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/models"
)

// Invalid query/server values must be rejected as StatusError before any
// resolver or dig subprocess is touched.

func TestResolve_InvalidQuery_DashPrefixed(t *testing.T) {
	result, ips, err := resolve(dnsCtx(), "-n", "")
	if err == nil {
		t.Fatal("expected error for dash-prefixed query")
	}
	if result.Status != models.StatusError {
		t.Fatalf("expected status error, got %s", result.Status)
	}
	if len(ips) != 0 {
		t.Errorf("expected no IPs for invalid query, got %v", ips)
	}
}

func TestResolve_InvalidServer_AtPrefixed(t *testing.T) {
	result, _, err := resolve(dnsCtx(), "nas.example", "@8.8.8.8")
	if err == nil {
		t.Fatal("expected error for @-prefixed server")
	}
	if result.Status != models.StatusError {
		t.Fatalf("expected status error, got %s", result.Status)
	}
}

func TestResolve_InvalidQuery_NotHostOrIP(t *testing.T) {
	result, _, err := resolve(dnsCtx(), "host with space", "")
	if err == nil {
		t.Fatal("expected error for whitespace query")
	}
	if result.Status != models.StatusError {
		t.Fatalf("expected status error, got %s", result.Status)
	}
}

func TestResolveExpect_InvalidQuery(t *testing.T) {
	result, err := ResolveExpect(dnsCtx(), "-n", "", "10.0.0.1")
	if err == nil {
		t.Fatal("expected error for invalid query")
	}
	if result.Status != models.StatusError {
		t.Fatalf("expected status error, got %s", result.Status)
	}
}

func TestCheckDNSSEC_InvalidQuery(t *testing.T) {
	result, err := CheckDNSSEC(dnsCtx(), "+short", "")
	if err == nil {
		t.Fatal("expected error for +prefixed query")
	}
	if result.Status != models.StatusError {
		t.Fatalf("expected status error, got %s", result.Status)
	}
}

func TestCheckDNSSEC_InvalidServer(t *testing.T) {
	result, err := CheckDNSSEC(dnsCtx(), "nas.example", "-n")
	if err == nil {
		t.Fatal("expected error for dash-prefixed server")
	}
	if result.Status != models.StatusError {
		t.Fatalf("expected status error, got %s", result.Status)
	}
}

func TestResolve_ValidQuery_NotRejected(t *testing.T) {
	// A valid query must not trip validation (resolution may still skip on
	// no network, but it must not be an input-validation error).
	result, _, _ := resolve(dnsCtx(), "localhost", "")
	if result.Status == models.StatusError {
		// localhost resolution failing for environmental reasons is acceptable,
		// but the summary must not be the validation message.
		if containsInvalidInput(result.Summary) {
			t.Fatalf("valid query rejected as invalid input: %s", result.Summary)
		}
	}
}

func containsInvalidInput(s string) bool {
	return strings.Contains(s, "must not start with") || strings.Contains(s, "is neither a valid IP address nor a hostname")
}
