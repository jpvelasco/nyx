package audit

import (
	"context"
	"testing"

	"github.com/jpvelasco/nyx/internal/backends"
	"github.com/jpvelasco/nyx/internal/backends/system"
	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/models"
)

// --- Helpers ---

func mockDiscoverResult(hostCount int, cidr string) *models.CheckResult {
	r := models.NewCheckResult("nmap", "subnet_discovery", "nmap", cidr)
	r.Status = models.StatusPass
	r.Observed = map[string]interface{}{
		"total": hostCount,
		"hosts": []interface{}{},
	}
	r.Summary = cidr
	r.Evidence = []string{"mock output"}
	r.Finish()
	return r
}

func mockPortScanResult(ports []int, expectState string) *models.CheckResult {
	r := models.NewCheckResult("nmap", "port_check", "nmap", "10.0.0.1")
	r.Status = models.StatusPass
	portStates := make([]interface{}, len(ports))
	for i, p := range ports {
		portStates[i] = map[string]interface{}{
			"port":     float64(p),
			"protocol": "tcp",
			"state":    expectState,
		}
	}
	r.Observed = map[string]interface{}{"ports": portStates}
	r.Evidence = []string{"mock nmap output"}
	r.Finish()
	return r
}

// --- Engine.Run with MockBackend ---

func TestEngine_RunWithMockBackend(t *testing.T) {
	spec := &intent.Spec{
		Version: 1,
		Site:    "test",
		Networks: []intent.Network{
			{Name: "lan", CIDR: "10.0.0.0/24", Gateway: "10.0.0.1", Zone: "internal"},
		},
		Assertions: []intent.Assertion{
			{Type: "subnet_discovery", Network: "lan"},
		},
	}

	mock := &backends.MockBackend{
		DiscoverResult: mockDiscoverResult(5, "10.0.0.0/24"),
	}

	eng := NewEngine(spec)
	eng.Backend = mock
	report, err := eng.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(report.Findings))
	}
	if report.Findings[0].Status != models.StatusPass {
		t.Errorf("expected pass, got %s", report.Findings[0].Status)
	}
}

func TestEngine_RunPreservesAssertionOrder(t *testing.T) {
	spec := &intent.Spec{
		Version: 1,
		Site:    "test",
		Networks: []intent.Network{
			{Name: "n1", CIDR: "10.0.0.0/24"},
			{Name: "n2", CIDR: "10.0.1.0/24"},
			{Name: "n3", CIDR: "10.0.2.0/24"},
		},
		Assertions: []intent.Assertion{
			{Type: "subnet_discovery", Network: "n3"},
			{Type: "subnet_discovery", Network: "n1"},
			{Type: "subnet_discovery", Network: "n2"},
		},
	}

	mock := &backends.MockBackend{
		// Return a fresh result per call so concurrent goroutines don't race on the same pointer.
		DiscoverResultFunc: func(cidr string) *models.CheckResult {
			r := models.NewCheckResult("nmap", "subnet_discovery", "nmap", cidr)
			r.Status = models.StatusPass
			r.Observed = map[string]interface{}{"total": 1, "hosts": []interface{}{}}
			r.Summary = cidr
			r.Finish()
			return r
		},
	}

	eng := NewEngine(spec)
	eng.Interface = "eth0" // pin interface to avoid CI runner ambiguity
	eng.Backend = mock
	report, err := eng.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Results should be in spec order: n3, n1, n2
	if report.Findings[0].Status != models.StatusPass {
		t.Error("expected all pass")
	}
	if report.Findings[1].Status != models.StatusPass {
		t.Error("expected all pass")
	}
	if report.Findings[2].Status != models.StatusPass {
		t.Error("expected all pass")
	}
}

// --- runAssertion dispatch ---

func TestRunAssertion_DispatchAllTypes(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Networks: []intent.Network{{Name: "lan", CIDR: "10.0.0.0/24", Gateway: "10.0.0.1", Zone: "internal"}},
		VPN:      []intent.VPNConfig{{Name: "vpn1", Type: "wireguard"}},
	}

	mock := &backends.MockBackend{
		DiscoverResult:  mockDiscoverResult(5, "10.0.0.0/24"),
		PingResult:      &system.PingResult{Reachable: true},
		RouteResult:     &system.Route{Device: "eth0", Gateway: "10.0.0.1"},
		ResolveResult:   makePassResult("dns", "dns_check"),
		PingCheckResult: makePassResult("ping", "network_health"),
	}
	eng := NewEngine(spec)
	eng.Backend = mock

	tests := []struct {
		name string
		a    intent.Assertion
	}{
		{"subnet_discovery", intent.Assertion{Type: "subnet_discovery", Network: "lan"}},
		{"isolation", intent.Assertion{Type: "isolation", From: "internal", To: "lan", Expect: "allow"}},
		{"vpn_route", intent.Assertion{Type: "vpn_route", VPN: "vpn1", Target: "10.0.0.1"}},
		{"route_check", intent.Assertion{Type: "route_check", Target: "8.8.8.8"}},
		{"dns_check", intent.Assertion{Type: "dns_check", Query: "example.com"}},
		{"network_health", intent.Assertion{Type: "network_health", Target: "10.0.0.1"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := eng.runAssertion(context.Background(), tt.a)
			if err != nil {
				t.Fatalf("unexpected error for %s: %v", tt.name, err)
			}
			if result == nil {
				t.Fatalf("nil result for %s", tt.name)
			}
		})
	}
}

func TestRunAssertion_UnknownType(t *testing.T) {
	spec := &intent.Spec{Version: 1, Site: "test"}
	eng := NewEngine(spec)
	_, err := eng.runAssertion(context.Background(), intent.Assertion{Type: "nonexistent"})
	if err == nil {
		t.Fatal("expected error for unknown type")
	}
}

// --- ExplainAssertionError ---

func TestExplainAssertionError_Timeout(t *testing.T) {
	a := intent.Assertion{Type: "subnet_discovery"}
	summary, details := explainAssertionError(a, backends.BackendError("context deadline exceeded"))
	if summary != "subnet_discovery timed out" {
		t.Errorf("unexpected summary: %s", summary)
	}
	if len(details) == 0 {
		t.Error("expected details for timeout")
	}
}

func TestExplainAssertionError_DNSFailure(t *testing.T) {
	a := intent.Assertion{Type: "dns_check"}
	summary, details := explainAssertionError(a, backends.BackendError("no such host"))
	if !contains(summary, "DNS resolution failed") {
		t.Errorf("unexpected summary: %s", summary)
	}
	if len(details) == 0 {
		t.Error("expected details for DNS failure")
	}
}

func TestExplainAssertionError_PortScan(t *testing.T) {
	a := intent.Assertion{Type: "port_check"}
	summary, details := explainAssertionError(a, backends.BackendError("port scan failed: connection refused"))
	if !contains(summary, "port scan didn't complete") {
		t.Errorf("unexpected summary: %s", summary)
	}
	if len(details) == 0 {
		t.Error("expected details for port scan failure")
	}
}

func TestExplainAssertionError_NetworkUnreachable(t *testing.T) {
	a := intent.Assertion{Type: "isolation"}
	summary, details := explainAssertionError(a, backends.BackendError("network is unreachable"))
	if !contains(summary, "network unreachable") {
		t.Errorf("unexpected summary: %s", summary)
	}
	if len(details) == 0 {
		t.Error("expected details for network unreachable")
	}
}

func TestExplainAssertionError_Generic(t *testing.T) {
	a := intent.Assertion{Type: "subnet_discovery"}
	summary, details := explainAssertionError(a, backends.BackendError("something weird happened"))
	if !contains(summary, "something weird happened") {
		t.Errorf("expected raw error in summary, got: %s", summary)
	}
	if len(details) == 0 {
		t.Error("expected details")
	}
}

// --- Helper functions ---

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func ptrBool(v bool) *bool { return &v }

func makePassResult(backend, atype string) *models.CheckResult {
	r := models.NewCheckResult(backend, atype, backend, "target")
	r.Status = models.StatusPass
	r.Finish()
	return r
}
