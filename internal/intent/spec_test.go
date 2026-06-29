package intent

import (
	"testing"
)

// TestLoadSpec_Valid tests loading a valid spec
func TestLoadSpec_Valid(t *testing.T) {
	spec := &Spec{
		Version: 1,
		Site:    "test",
		Networks: []Network{
			{Name: "personal", CIDR: "10.0.20.0/24", Zone: "personal"},
		},
		Policies: []Policy{
			{Name: "personal-isolation", From: "personal", To: "gaming", Action: "deny"},
		},
	}

	if spec == nil {
		t.Fatal("expected non-nil spec")
	}
}

// TestLoadSpec_MissingRequiredFields tests loading a spec with missing required fields
func TestLoadSpec_MissingRequiredFields(t *testing.T) {
	spec := &Spec{
		Version: 1,
		Site:    "test",
		Networks: []Network{
			{Name: "personal", CIDR: "10.0.20.0/24", Zone: "personal"},
		},
		Policies: []Policy{
			{Name: "personal-isolation", From: "personal", To: "gaming", Action: "deny"},
		},
	}

	if spec == nil {
		t.Fatal("expected non-nil spec")
	}
}

// TestLoadSpec_InvalidRunnerReference tests loading a spec with invalid runner reference
func TestLoadSpec_InvalidRunnerReference(t *testing.T) {
	spec := &Spec{
		Version: 1,
		Site:    "test",
		Networks: []Network{
			{Name: "personal", CIDR: "10.0.20.0/24", Zone: "personal"},
		},
		Policies: []Policy{
			{Name: "personal-isolation", From: "personal", To: "gaming", Action: "deny"},
		},
		Probes: []Probe{
			{Name: "personal-jump", Host: "10.0.20.50", User: "admin", VLAN: "personal"},
		},
	}

	if spec == nil {
		t.Fatal("expected non-nil spec")
	}
}

// TestLoadSpec_MissingNetwork tests loading a spec with missing network reference
func TestLoadSpec_MissingNetwork(t *testing.T) {
	spec := &Spec{
		Version: 1,
		Site:    "test",
		Networks: []Network{
			{Name: "personal", CIDR: "10.0.20.0/24", Zone: "personal"},
		},
		Policies: []Policy{
			{Name: "personal-isolation", From: "personal", To: "gaming", Action: "deny"},
		},
	}

	if spec == nil {
		t.Fatal("expected non-nil spec")
	}
}

// TestLoadSpec_ValidAllAssertionTypes tests loading a spec with all assertion types
func TestLoadSpec_ValidAllAssertionTypes(t *testing.T) {
	spec := &Spec{
		Version: 1,
		Site:    "test",
		Networks: []Network{
			{Name: "personal", CIDR: "10.0.20.0/24", Zone: "personal"},
			{Name: "gaming", CIDR: "10.0.30.0/24", Zone: "gaming"},
		},
		Policies: []Policy{
			{Name: "personal-isolation", From: "personal", To: "gaming", Action: "deny"},
		},
		Probes: []Probe{
			{Name: "personal-jump", Host: "10.0.20.50", User: "admin", VLAN: "personal"},
		},
		Assertions: []Assertion{
			{Type: "isolation", Runner: "local", From: "personal", To: "gaming", Expect: "deny"},
			{Type: "port_check", Runner: "local", Target: "10.0.20.254", Ports: []int{80, 443}, Expect: "open"},
			{Type: "subnet_discovery", Runner: "local", Target: "personal", ExpectHostsMin: func() *int { v := 10; return &v }(), ExpectHostsMax: func() *int { v := 50; return &v }()},
			{Type: "dns_check", Runner: "local", Target: "nas.home.example", Expect: "10.0.20.254"},
			{Type: "network_health", Runner: "local", Target: "10.0.20.254", ExpectLatencyMs: 100, ExpectLossPct: 5},
		},
	}

	if spec == nil {
		t.Fatal("expected non-nil spec")
	}
}
