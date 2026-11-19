package audit

import (
	"context"
	"testing"

	"github.com/jpvelasco/nyx/internal/backends"
	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/models"
)

// --- runDiscovery ---

func TestRunDiscovery_HostCountExceedsMax(t *testing.T) {
	maxHosts := 3
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Networks:   []intent.Network{{Name: "lan", CIDR: "10.0.0.0/24"}},
		Assertions: []intent.Assertion{{Type: "subnet_discovery", Network: "lan", ExpectHostsMax: &maxHosts}},
	}

	mock := &backends.MockBackend{
		DiscoverResult: mockDiscoverResult(10, "10.0.0.0/24"),
	}

	eng := NewEngine(spec)
	eng.Backend = mock
	result, err := eng.runDiscovery(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusFail {
		t.Errorf("expected fail, got %s", result.Status)
	}
	if len(result.Violations) == 0 {
		t.Error("expected violations")
	}
}

func TestRunDiscovery_HostCountBelowMin(t *testing.T) {
	minHosts := 5
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Networks:   []intent.Network{{Name: "lan", CIDR: "10.0.0.0/24"}},
		Assertions: []intent.Assertion{{Type: "subnet_discovery", Network: "lan", ExpectHostsMin: &minHosts}},
	}

	mock := &backends.MockBackend{
		DiscoverResult: mockDiscoverResult(2, "10.0.0.0/24"),
	}

	eng := NewEngine(spec)
	eng.Backend = mock
	result, err := eng.runDiscovery(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusFail {
		t.Errorf("expected fail, got %s", result.Status)
	}
}

func TestRunDiscovery_HostCountWithinBounds(t *testing.T) {
	minHosts := 1
	maxHosts := 10
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Networks:   []intent.Network{{Name: "lan", CIDR: "10.0.0.0/24"}},
		Assertions: []intent.Assertion{{Type: "subnet_discovery", Network: "lan", ExpectHostsMin: &minHosts, ExpectHostsMax: &maxHosts}},
	}

	mock := &backends.MockBackend{
		DiscoverResult: mockDiscoverResult(5, "10.0.0.0/24"),
	}

	eng := NewEngine(spec)
	eng.Backend = mock
	result, err := eng.runDiscovery(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusPass {
		t.Errorf("expected pass, got %s: %s", result.Status, result.Summary)
	}
}

func TestRunDiscovery_NetworkNotFound(t *testing.T) {
	spec := &intent.Spec{Version: 1, Site: "test", Networks: []intent.Network{{Name: "lan", CIDR: "10.0.0.0/24"}}}
	a := intent.Assertion{Type: "subnet_discovery", Network: "nonexistent"}
	eng := NewEngine(spec)
	_, err := eng.runDiscovery(context.Background(), a)
	if err == nil {
		t.Fatal("expected error for missing network")
	}
}

func TestRunDiscovery_BackendError(t *testing.T) {
	spec := &intent.Spec{Version: 1, Site: "test", Networks: []intent.Network{{Name: "lan", CIDR: "10.0.0.0/24"}}}
	a := intent.Assertion{Type: "subnet_discovery", Network: "lan"}
	eng := NewEngine(spec)
	eng.Backend = &backends.MockBackend{DiscoverErr: backends.BackendError("nmap not found")}
	_, err := eng.runDiscovery(context.Background(), a)
	if err == nil {
		t.Fatal("expected error from backend")
	}
}

func TestRunDiscovery_InvalidCIDR(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Networks:   []intent.Network{{Name: "bad", CIDR: "not-a-cidr"}},
		Assertions: []intent.Assertion{{Type: "subnet_discovery", Network: "bad"}},
	}
	eng := NewEngine(spec)
	eng.Backend = &backends.MockBackend{}
	_, err := eng.runDiscovery(context.Background(), spec.Assertions[0])
	if err == nil {
		t.Fatal("expected probe-set selection error for invalid CIDR")
	}
}

func TestRunDiscovery_ProbeSetForRoutedNetwork(t *testing.T) {
	// 203.0.113.0/24 is documentation space — never directly-attached, so
	// the engine must pick the ICMP echo probe set for it.
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Networks:   []intent.Network{{Name: "routed", CIDR: "203.0.113.0/24"}},
		Assertions: []intent.Assertion{{Type: "subnet_discovery", Network: "routed"}},
	}
	eng := NewEngine(spec)
	eng.Backend = &backends.MockBackend{
		DiscoverResultFunc: func(string) *models.CheckResult {
			return mockDiscoverResult(1, "203.0.113.0/24")
		},
	}
	result, err := eng.runDiscovery(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusPass {
		t.Errorf("expected pass, got %s: %s", result.Status, result.Summary)
	}
}

func TestRunDiscovery_ScanModeOverride(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Networks:   []intent.Network{{Name: "lan", CIDR: "10.0.0.0/24"}},
		Assertions: []intent.Assertion{{Type: "subnet_discovery", Network: "lan", ScanMode: "aggressive", ScanTiming: 5, ScanMinRate: 1000}},
	}
	mock := &backends.MockBackend{
		DiscoverResult: mockDiscoverResult(3, "10.0.0.0/24"),
	}
	eng := NewEngine(spec)
	eng.Backend = mock
	result, err := eng.runDiscovery(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusPass {
		t.Errorf("expected pass, got %s", result.Status)
	}
}
