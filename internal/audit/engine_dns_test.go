package audit

import (
	"context"
	"testing"

	"github.com/jpvelasco/nyx/internal/backends"
	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/models"
)

// --- runDNSCheck ---

func TestRunDNSCheck_BasicResolve(t *testing.T) {
	r := models.NewCheckResult("dns", "dns_check", "dns", "example.com")
	r.Status = models.StatusPass
	r.Observed = map[string]interface{}{"ips": []interface{}{"93.184.216.34"}}
	r.Finish()

	spec := &intent.Spec{
		Version: 1, Site: "test",
		Assertions: []intent.Assertion{{Type: "dns_check", Query: "example.com"}},
	}
	mock := &backends.MockBackend{ResolveResult: r}
	eng := NewEngine(spec)
	eng.Backend = mock
	result, err := eng.runDNSCheck(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusPass {
		t.Errorf("expected pass, got %s", result.Status)
	}
	// The query expectation must be populated for drift-key disambiguation.
	if result.Expected["query"] != "example.com" {
		t.Errorf("expected Expected[\"query\"] = example.com, got %v", result.Expected["query"])
	}
}

func TestRunDNSCheck_ResolveExpect(t *testing.T) {
	r := models.NewCheckResult("dns", "dns_check", "dns", "example.com")
	r.Status = models.StatusPass
	r.Finish()

	spec := &intent.Spec{
		Version: 1, Site: "test",
		Assertions: []intent.Assertion{{Type: "dns_check", Query: "example.com", ExpectIP: "93.184.216.34"}},
	}
	mock := &backends.MockBackend{ResolveExpectResult: r}
	eng := NewEngine(spec)
	eng.Backend = mock
	result, err := eng.runDNSCheck(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusPass {
		t.Errorf("expected pass, got %s", result.Status)
	}
}

func TestRunDNSCheck_DNSSEC(t *testing.T) {
	r := models.NewCheckResult("dns", "dns_check", "dns", "example.com")
	r.Status = models.StatusPass
	r.Finish()

	dnssecR := models.NewCheckResult("dig", "dns_check", "dns", "example.com")
	dnssecR.Status = models.StatusPass
	dnssecR.Evidence = []string{"DNSSEC validated"}
	dnssecR.Finish()

	spec := &intent.Spec{
		Version: 1, Site: "test",
		Assertions: []intent.Assertion{{Type: "dns_check", Query: "example.com", DNSSEC: true}},
	}
	mock := &backends.MockBackend{ResolveResult: r, DNSSECResult: dnssecR}
	eng := NewEngine(spec)
	eng.Backend = mock
	result, err := eng.runDNSCheck(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusPass {
		t.Errorf("expected pass with DNSSEC, got %s", result.Status)
	}
}

func TestRunDNSCheck_DNSSEC_Fail(t *testing.T) {
	r := models.NewCheckResult("dns", "dns_check", "dns", "example.com")
	r.Status = models.StatusPass
	r.Finish()

	dnssecR := models.NewCheckResult("dig", "dns_check", "dns", "example.com")
	dnssecR.Status = models.StatusFail
	dnssecR.Summary = "DNSSEC validation failed"
	dnssecR.Finish()

	spec := &intent.Spec{
		Version: 1, Site: "test",
		Assertions: []intent.Assertion{{Type: "dns_check", Query: "example.com", DNSSEC: true}},
	}
	mock := &backends.MockBackend{ResolveResult: r, DNSSECResult: dnssecR}
	eng := NewEngine(spec)
	eng.Backend = mock
	result, err := eng.runDNSCheck(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusFail {
		t.Errorf("expected fail due to DNSSEC, got %s", result.Status)
	}
}
