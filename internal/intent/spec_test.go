package intent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- ParseSpec ---

func TestParseSpec_Valid(t *testing.T) {
	yaml := `
version: 1
site: test-site
networks:
  - name: personal
    cidr: 10.0.20.0/24
    gateway: 10.0.20.1
    zone: personal
policies:
  - name: block-gaming
    from: personal
    to: gaming
    action: deny
assertions:
  - type: subnet_discovery
    network: personal
`
	spec, err := ParseSpec([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if spec.Site != "test-site" {
		t.Errorf("expected site 'test-site', got %q", spec.Site)
	}
	if len(spec.Networks) != 1 {
		t.Fatalf("expected 1 network, got %d", len(spec.Networks))
	}
	if spec.Networks[0].Name != "personal" {
		t.Errorf("expected network name 'personal', got %q", spec.Networks[0].Name)
	}
}

func TestParseSpec_BadYAML(t *testing.T) {
	_, err := ParseSpec([]byte("{{not yaml}}"))
	if err == nil {
		t.Fatal("expected error for bad YAML")
	}
}

// --- ValidateSpec ---

func TestValidateSpec_BadVersion(t *testing.T) {
	spec := &Spec{Version: 99, Site: "test"}
	err := ValidateSpec(spec)
	if err == nil {
		t.Fatal("expected error for bad version")
	}
	if !contains(err.Error(), "unsupported spec version") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateSpec_MissingSite(t *testing.T) {
	spec := &Spec{Version: 1}
	err := ValidateSpec(spec)
	if err == nil {
		t.Fatal("expected error for missing site")
	}
}

func TestValidateSpec_NetworkMissingName(t *testing.T) {
	spec := &Spec{Version: 1, Site: "test", Networks: []Network{{CIDR: "10.0.0.0/24"}}}
	err := ValidateSpec(spec)
	if err == nil {
		t.Fatal("expected error for network without name")
	}
	if !contains(err.Error(), "name is required") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateSpec_NetworkDuplicateName(t *testing.T) {
	spec := &Spec{Version: 1, Site: "test", Networks: []Network{
		{Name: "dup", CIDR: "10.0.0.0/24"},
		{Name: "dup", CIDR: "10.0.1.0/24"},
	}}
	err := ValidateSpec(spec)
	if err == nil {
		t.Fatal("expected error for duplicate network name")
	}
	if !contains(err.Error(), "duplicate name") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateSpec_NetworkBadCIDR(t *testing.T) {
	spec := &Spec{Version: 1, Site: "test", Networks: []Network{{Name: "bad", CIDR: "not-a-cidr"}}}
	err := ValidateSpec(spec)
	if err == nil {
		t.Fatal("expected error for bad CIDR")
	}
}

func TestValidateSpec_NetworkBadGateway(t *testing.T) {
	spec := &Spec{Version: 1, Site: "test", Networks: []Network{{Name: "bad", CIDR: "10.0.0.0/24", Gateway: "not-an-ip"}}}
	err := ValidateSpec(spec)
	if err == nil {
		t.Fatal("expected error for bad gateway")
	}
}

func TestValidateSpec_VPNMissingName(t *testing.T) {
	spec := &Spec{Version: 1, Site: "test", VPN: []VPNConfig{{Type: "wireguard"}}}
	err := ValidateSpec(spec)
	if err == nil {
		t.Fatal("expected error for VPN without name")
	}
}

func TestValidateSpec_VPNMissingType(t *testing.T) {
	spec := &Spec{Version: 1, Site: "test", VPN: []VPNConfig{{Name: "vpn1"}}}
	err := ValidateSpec(spec)
	if err == nil {
		t.Fatal("expected error for VPN without type")
	}
}

func TestValidateSpec_ProbeMissingFields(t *testing.T) {
	spec := &Spec{Version: 1, Site: "test", Probes: []Probe{{}}}
	err := ValidateSpec(spec)
	if err == nil {
		t.Fatal("expected error for probe without name")
	}
}

func TestValidateSpec_ProbeDuplicateName(t *testing.T) {
	spec := &Spec{Version: 1, Site: "test", Probes: []Probe{
		{Name: "p", Host: "1.2.3.4", User: "u"},
		{Name: "p", Host: "5.6.7.8", User: "u"},
	}}
	err := ValidateSpec(spec)
	if err == nil {
		t.Fatal("expected error for duplicate probe name")
	}
}

func TestValidateSpec_PolicyBadAction(t *testing.T) {
	spec := &Spec{Version: 1, Site: "test", Policies: []Policy{{Name: "p", Action: "bounce"}}}
	err := ValidateSpec(spec)
	if err == nil {
		t.Fatal("expected error for bad policy action")
	}
}

func TestValidateSpec_PolicyMissingName(t *testing.T) {
	spec := &Spec{Version: 1, Site: "test", Policies: []Policy{{Action: "allow"}}}
	err := ValidateSpec(spec)
	if err == nil {
		t.Fatal("expected error for policy without name")
	}
}

func TestValidateSpec_UnknownAssertionType(t *testing.T) {
	spec := &Spec{Version: 1, Site: "test", Assertions: []Assertion{{Type: "fake_type"}}}
	err := ValidateSpec(spec)
	if err == nil {
		t.Fatal("expected error for unknown assertion type")
	}
}

// --- Assertion-specific validation ---

func TestValidateSpec_SubnetDiscoveryMissingNetwork(t *testing.T) {
	spec := &Spec{Version: 1, Site: "test", Assertions: []Assertion{{Type: "subnet_discovery"}}}
	err := ValidateSpec(spec)
	if err == nil {
		t.Fatal("expected error")
	}
	if !contains(err.Error(), "network is required") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateSpec_SubnetDiscoveryMinMaxInverted(t *testing.T) {
	minHosts := 50
	maxHosts := 10
	spec := &Spec{Version: 1, Site: "test", Networks: []Network{{Name: "n", CIDR: "10.0.0.0/24"}},
		Assertions: []Assertion{{Type: "subnet_discovery", Network: "n", ExpectHostsMin: &minHosts, ExpectHostsMax: &maxHosts}}}
	err := ValidateSpec(spec)
	if err == nil {
		t.Fatal("expected error for min > max")
	}
}

func TestValidateSpec_IsolationMissingFields(t *testing.T) {
	a := Assertion{Type: "isolation"}
	spec := &Spec{Version: 1, Site: "test", Assertions: []Assertion{a}}
	err := ValidateSpec(spec)
	if err == nil {
		t.Fatal("expected error for missing 'from'")
	}
}

func TestValidateSpec_IsolationMissingTo(t *testing.T) {
	spec := &Spec{Version: 1, Site: "test", Assertions: []Assertion{{Type: "isolation", From: "a"}}}
	err := ValidateSpec(spec)
	if err == nil {
		t.Fatal("expected error for missing 'to'")
	}
}

func TestValidateSpec_IsolationMissingExpect(t *testing.T) {
	spec := &Spec{Version: 1, Site: "test", Assertions: []Assertion{{Type: "isolation", From: "a", To: "b"}}}
	err := ValidateSpec(spec)
	if err == nil {
		t.Fatal("expected error for missing 'expect'")
	}
}

func TestValidateSpec_IsolationValid(t *testing.T) {
	spec := &Spec{Version: 1, Site: "test", Assertions: []Assertion{{Type: "isolation", From: "a", To: "b", Expect: "deny"}}}
	if err := ValidateSpec(spec); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateSpec_IsolationInvalidExpect(t *testing.T) {
	// A misspelled expectation must be a validation error: runtime
	// treats any non-"deny" value as allow, so a typo would silently
	// reverse the assertion's verdict.
	for _, expect := range []string{"dney", "denied", "allowed", "DENY", ""} {
		spec := &Spec{Version: 1, Site: "test", Assertions: []Assertion{{Type: "isolation", From: "a", To: "b", Expect: expect}}}
		err := ValidateSpec(spec)
		if err == nil {
			t.Errorf("isolation expect=%q should be rejected", expect)
		}
	}
	for _, expect := range []string{"deny", "allow"} {
		spec := &Spec{Version: 1, Site: "test", Assertions: []Assertion{{Type: "isolation", From: "a", To: "b", Expect: expect}}}
		if err := ValidateSpec(spec); err != nil {
			t.Errorf("isolation expect=%q should be valid: %v", expect, err)
		}
	}
}

func TestValidateSpec_PortCheckInvalidExpect(t *testing.T) {
	// A misspelled expectation must be a validation error: runtime
	// treats any non-"open" value as closed, so a typo would silently
	// reverse the assertion's verdict.
	for _, expect := range []string{"opne", "opened", "CLOSED", "filtered"} {
		spec := &Spec{Version: 1, Site: "test", Assertions: []Assertion{{Type: "port_check", Target: "1.2.3.4", Ports: []int{80}, Expect: expect}}}
		err := ValidateSpec(spec)
		if err == nil {
			t.Errorf("port_check expect=%q should be rejected", expect)
		}
	}
	for _, expect := range []string{"open", "closed"} {
		spec := &Spec{Version: 1, Site: "test", Assertions: []Assertion{{Type: "port_check", Target: "1.2.3.4", Ports: []int{80}, Expect: expect}}}
		if err := ValidateSpec(spec); err != nil {
			t.Errorf("port_check expect=%q should be valid: %v", expect, err)
		}
	}
}

func TestValidateSpec_ACLCheckInvalidExpect(t *testing.T) {
	// A misspelled expectation must be a validation error: runtime
	// treats any non-"enforced" value as not_enforced, so a typo would
	// silently reverse the assertion's verdict.
	for _, expect := range []string{"enfroced", "enforce", "NOT_ENFORCED", "off"} {
		spec := &Spec{Version: 1, Site: "test", Assertions: []Assertion{{Type: "acl_check", Provider: "omada", Policy: "p", Expect: expect}}}
		err := ValidateSpec(spec)
		if err == nil {
			t.Errorf("acl_check expect=%q should be rejected", expect)
		}
	}
	for _, expect := range []string{"enforced", "not_enforced"} {
		spec := &Spec{Version: 1, Site: "test", Assertions: []Assertion{{Type: "acl_check", Provider: "omada", Policy: "p", Expect: expect}}}
		if err := ValidateSpec(spec); err != nil {
			t.Errorf("acl_check expect=%q should be valid: %v", expect, err)
		}
	}
}

func TestValidateSpec_VPNRouteMissingFields(t *testing.T) {
	spec := &Spec{Version: 1, Site: "test", Assertions: []Assertion{{Type: "vpn_route"}}}
	err := ValidateSpec(spec)
	if err == nil {
		t.Fatal("expected error for missing vpn")
	}
}

func TestValidateSpec_VPNRouteMissingTarget(t *testing.T) {
	spec := &Spec{Version: 1, Site: "test", Assertions: []Assertion{{Type: "vpn_route", VPN: "vpn1"}}}
	err := ValidateSpec(spec)
	if err == nil {
		t.Fatal("expected error for missing target")
	}
}

func TestValidateSpec_RouteCheckMissingTarget(t *testing.T) {
	spec := &Spec{Version: 1, Site: "test", Assertions: []Assertion{{Type: "route_check"}}}
	err := ValidateSpec(spec)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateSpec_PortCheckMissingFields(t *testing.T) {
	spec := &Spec{Version: 1, Site: "test", Assertions: []Assertion{{Type: "port_check"}}}
	err := ValidateSpec(spec)
	if err == nil {
		t.Fatal("expected error for missing target")
	}
}

func TestValidateSpec_PortCheckMissingPorts(t *testing.T) {
	spec := &Spec{Version: 1, Site: "test", Assertions: []Assertion{{Type: "port_check", Target: "1.2.3.4"}}}
	err := ValidateSpec(spec)
	if err == nil {
		t.Fatal("expected error for missing ports")
	}
}

func TestValidateSpec_PortCheckMissingExpect(t *testing.T) {
	spec := &Spec{Version: 1, Site: "test", Assertions: []Assertion{{Type: "port_check", Target: "1.2.3.4", Ports: []int{80}}}}
	err := ValidateSpec(spec)
	if err == nil {
		t.Fatal("expected error for missing expect")
	}
}

func TestValidateSpec_DNSCheckMissingQuery(t *testing.T) {
	spec := &Spec{Version: 1, Site: "test", Assertions: []Assertion{{Type: "dns_check"}}}
	err := ValidateSpec(spec)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateSpec_NetworkHealthMissingTarget(t *testing.T) {
	spec := &Spec{Version: 1, Site: "test", Assertions: []Assertion{{Type: "network_health"}}}
	err := ValidateSpec(spec)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateSpec_ACLCheckMissingFields(t *testing.T) {
	spec := &Spec{Version: 1, Site: "test", Assertions: []Assertion{{Type: "acl_check"}}}
	err := ValidateSpec(spec)
	if err == nil {
		t.Fatal("expected error for missing provider")
	}
}

func TestValidateSpec_ACLCheckValid(t *testing.T) {
	spec := &Spec{Version: 1, Site: "test",
		Policies:   []Policy{{Name: "p1", Action: "deny"}},
		Assertions: []Assertion{{Type: "acl_check", Provider: "omada", Policy: "p1", Expect: "enforced"}}}
	if err := ValidateSpec(spec); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateSpec_NatCheckMissingProvider(t *testing.T) {
	spec := &Spec{Version: 1, Site: "test",
		Assertions: []Assertion{{Type: "nat_check", NatMode: "disabled"}}}
	err := ValidateSpec(spec)
	if err == nil || !contains(err.Error(), "provider") {
		t.Errorf("error = %v, want provider required", err)
	}
}

func TestValidateSpec_NatCheckBadProvider(t *testing.T) {
	spec := &Spec{Version: 1, Site: "test",
		Assertions: []Assertion{{Type: "nat_check", Provider: "fortinet", NatMode: "disabled"}}}
	if err := ValidateSpec(spec); err == nil {
		t.Fatal("expected error for unsupported provider")
	}
}

func TestValidateSpec_NatCheckMissingMode(t *testing.T) {
	spec := &Spec{Version: 1, Site: "test",
		Assertions: []Assertion{{Type: "nat_check", Provider: "opnsense"}}}
	err := ValidateSpec(spec)
	if err == nil || !contains(err.Error(), "nat_mode") {
		t.Errorf("error = %v, want nat_mode required", err)
	}
}

func TestValidateSpec_NatCheckBadMode(t *testing.T) {
	spec := &Spec{Version: 1, Site: "test",
		Assertions: []Assertion{{Type: "nat_check", Provider: "opnsense", NatMode: "turbo"}}}
	if err := ValidateSpec(spec); err == nil {
		t.Fatal("expected error for invalid nat_mode")
	}
}

func TestValidateSpec_NatCheckValid(t *testing.T) {
	spec := &Spec{Version: 1, Site: "test",
		Assertions: []Assertion{
			{Type: "nat_check", Provider: "opnsense", NatMode: "disabled"},
			{Type: "nat_check", Provider: "opnsense", NatMode: "bridge"},
			{Type: "nat_check", Provider: "omada", NatMode: "present"},
		}}
	if err := ValidateSpec(spec); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateSpec_InventoryValid(t *testing.T) {
	spec := &Spec{Version: 1, Site: "test", Inventory: &Inventory{
		ControllerVersion: "6.4.5.1",
		Devices:           []InventoryDevice{{Type: "gateway", Name: "GW-CORE", Upgrade: true}},
		NetworkGateways:   map[string]string{"trusted": "GW-CORE"},
		ACLScopes:         []ACLScopeStatus{{Scope: "gateway", RuleCount: 1}},
	}}
	if err := ValidateSpec(spec); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateSpec_InventoryDeviceMissingName(t *testing.T) {
	spec := &Spec{Version: 1, Site: "test", Inventory: &Inventory{
		Devices: []InventoryDevice{{Type: "gateway"}},
	}}
	err := ValidateSpec(spec)
	if err == nil || !contains(err.Error(), "inventory.devices[0]") {
		t.Errorf("error = %v, want inventory.devices[0] name required", err)
	}
}

func TestValidateSpec_InventoryBadDeviceType(t *testing.T) {
	spec := &Spec{Version: 1, Site: "test", Inventory: &Inventory{
		Devices: []InventoryDevice{{Type: "router", Name: "x"}},
	}}
	err := ValidateSpec(spec)
	if err == nil || !contains(err.Error(), "type must be gateway, switch, or ap") {
		t.Errorf("error = %v, want bad device type", err)
	}
}

func TestValidateSpec_InventoryBadScope(t *testing.T) {
	spec := &Spec{Version: 1, Site: "test", Inventory: &Inventory{
		ACLScopes: []ACLScopeStatus{{Scope: "wan"}},
	}}
	err := ValidateSpec(spec)
	if err == nil || !contains(err.Error(), "scope must be 'gateway' or 'switch'") {
		t.Errorf("error = %v, want bad acl scope", err)
	}
}

// --- Runner validation ---

func TestValidateSpec_BadRunnerReference(t *testing.T) {
	spec := &Spec{Version: 1, Site: "test",
		Networks:   []Network{{Name: "n", CIDR: "10.0.0.0/24"}},
		Assertions: []Assertion{{Type: "subnet_discovery", Network: "n", Runner: "nonexistent"}}}
	err := ValidateSpec(spec)
	if err == nil {
		t.Fatal("expected error for bad runner reference")
	}
	if !contains(err.Error(), "not declared in probes") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateSpec_LocalRunnerAllowed(t *testing.T) {
	spec := &Spec{Version: 1, Site: "test",
		Networks:   []Network{{Name: "n", CIDR: "10.0.0.0/24"}},
		Assertions: []Assertion{{Type: "subnet_discovery", Network: "n", Runner: "local"}}}
	if err := ValidateSpec(spec); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateSpec_ValidRunnerReference(t *testing.T) {
	spec := &Spec{Version: 1, Site: "test",
		Networks:   []Network{{Name: "n", CIDR: "10.0.0.0/24"}},
		Probes:     []Probe{{Name: "probe1", Host: "10.0.0.1", User: "admin"}},
		Assertions: []Assertion{{Type: "subnet_discovery", Network: "n", Runner: "probe1"}}}
	if err := ValidateSpec(spec); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- Spec helper methods ---

func TestSpec_NetworkByName(t *testing.T) {
	spec := &Spec{Networks: []Network{
		{Name: "personal", CIDR: "10.0.0.0/24"},
		{Name: "guest", CIDR: "10.0.1.0/24"},
	}}
	n := spec.NetworkByName("guest")
	if n == nil {
		t.Fatal("expected to find 'guest'")
	}
	if n.CIDR != "10.0.1.0/24" {
		t.Errorf("expected CIDR 10.0.1.0/24, got %q", n.CIDR)
	}
	if spec.NetworkByName("missing") != nil {
		t.Error("expected nil for missing network")
	}
}

func TestSpec_VPNByName(t *testing.T) {
	spec := &Spec{VPN: []VPNConfig{
		{Name: "work", Type: "wireguard"},
		{Name: "home", Type: "openvpn"},
	}}
	v := spec.VPNByName("home")
	if v == nil {
		t.Fatal("expected to find 'home'")
	}
	if v.Type != "openvpn" {
		t.Errorf("expected type 'openvpn', got %q", v.Type)
	}
}

func TestSpec_NetworkByZone(t *testing.T) {
	spec := &Spec{Networks: []Network{
		{Name: "a", CIDR: "10.0.0.0/24", Zone: "trusted"},
		{Name: "b", CIDR: "10.0.1.0/24", Zone: "trusted"},
		{Name: "c", CIDR: "10.0.2.0/24", Zone: "untrusted"},
	}}
	nets := spec.NetworkByZone("trusted")
	if len(nets) != 2 {
		t.Fatalf("expected 2 networks in 'trusted', got %d", len(nets))
	}
	if len(spec.NetworkByZone("nonexistent")) != 0 {
		t.Error("expected empty slice for nonexistent zone")
	}
}

func TestSpec_ProbeByName(t *testing.T) {
	spec := &Spec{Probes: []Probe{
		{Name: "probe1", Host: "10.0.0.1", User: "admin"},
	}}
	p := spec.ProbeByName("probe1")
	if p == nil {
		t.Fatal("expected to find 'probe1'")
	}
	if p.Host != "10.0.0.1" {
		t.Errorf("expected host 10.0.0.1, got %q", p.Host)
	}
}

// --- ParseSpec full round-trip ---

func TestParseSpec_FullSpec(t *testing.T) {
	yaml := `
version: 1
site: mylab
networks:
  - name: lan
    cidr: 192.168.1.0/24
    gateway: 192.168.1.1
    zone: internal
  - name: guest
    cidr: 192.168.2.0/24
    gateway: 192.168.2.1
    zone: external
vpn:
  - name: work
    type: wireguard
    expected_routes:
      - 10.0.0.0/8
probes:
  - name: jumpbox
    host: 192.168.1.50
    user: admin
policies:
  - name: block-guest
    from: guest
    to: lan
    action: deny
assertions:
  - type: subnet_discovery
    network: lan
    expect_hosts_min: 5
    expect_hosts_max: 50
  - type: isolation
    from: guest
    to: internal
    expect: deny
    runner: jumpbox
  - type: port_check
    target: 192.168.1.1
    ports: [80, 443]
    expect: open
  - type: dns_check
    query: nas.lan
  - type: network_health
    target: 192.168.1.1
    expect_latency_ms: 100
  - type: vpn_route
    vpn: work
    target: 10.0.0.1
    expect_tunnel: true
  - type: route_check
    target: 8.8.8.8
`
	spec, err := ParseSpec([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if spec.Site != "mylab" {
		t.Errorf("expected site 'mylab', got %q", spec.Site)
	}
	if len(spec.Networks) != 2 {
		t.Fatalf("expected 2 networks, got %d", len(spec.Networks))
	}
	if len(spec.VPN) != 1 {
		t.Fatalf("expected 1 VPN, got %d", len(spec.VPN))
	}
	if len(spec.Probes) != 1 {
		t.Fatalf("expected 1 probe, got %d", len(spec.Probes))
	}
	if len(spec.Policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(spec.Policies))
	}
	if len(spec.Assertions) != 7 {
		t.Fatalf("expected 7 assertions, got %d", len(spec.Assertions))
	}
	// Verify host bounds parsed correctly
	a := spec.Assertions[0]
	if *a.ExpectHostsMin != 5 || *a.ExpectHostsMax != 50 {
		t.Errorf("expected min=5 max=50, got min=%d max=%d", *a.ExpectHostsMin, *a.ExpectHostsMax)
	}
	// Verify isolation runner
	a2 := spec.Assertions[1]
	if a2.Runner != "jumpbox" {
		t.Errorf("expected runner 'jumpbox', got %q", a2.Runner)
	}
}

// --- Probe validation edge cases ---

func TestValidateSpec_ProbeMissingHost(t *testing.T) {
	spec := &Spec{Version: 1, Site: "test", Probes: []Probe{{Name: "p1", User: "u"}}}
	err := ValidateSpec(spec)
	if err == nil {
		t.Fatal("expected error for probe without host")
	}
	if !contains(err.Error(), "'host' is required") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateSpec_ProbeMissingUser(t *testing.T) {
	spec := &Spec{Version: 1, Site: "test", Probes: []Probe{{Name: "p1", Host: "1.2.3.4"}}}
	err := ValidateSpec(spec)
	if err == nil {
		t.Fatal("expected error for probe without user")
	}
	if !contains(err.Error(), "'user' is required") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateSpec_ProbeBadPort(t *testing.T) {
	spec := &Spec{Version: 1, Site: "test", Probes: []Probe{{Name: "p1", Host: "1.2.3.4", User: "u", Port: 70000}}}
	err := ValidateSpec(spec)
	if err == nil {
		t.Fatal("expected error for probe port out of range")
	}
	if !contains(err.Error(), "'port' must be 1-65535") {
		t.Errorf("unexpected error: %v", err)
	}
}

// --- acl_check validation edge cases ---

func TestValidateSpec_ACLCheckMissingPolicy(t *testing.T) {
	spec := &Spec{Version: 1, Site: "test",
		Policies:   []Policy{{Name: "p1", Action: "deny"}},
		Assertions: []Assertion{{Type: "acl_check", Provider: "omada", Expect: "enforced"}},
	}
	err := ValidateSpec(spec)
	if err == nil {
		t.Fatal("expected error for missing policy")
	}
	if !contains(err.Error(), "policy") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateSpec_ACLCheckMissingExpect(t *testing.T) {
	spec := &Spec{Version: 1, Site: "test",
		Policies:   []Policy{{Name: "p1", Action: "deny"}},
		Assertions: []Assertion{{Type: "acl_check", Provider: "omada", Policy: "p1"}},
	}
	err := ValidateSpec(spec)
	if err == nil {
		t.Fatal("expected error for missing expect")
	}
	if !contains(err.Error(), "expect") {
		t.Errorf("unexpected error: %v", err)
	}
}

// --- ParseSpec: validation error after successful YAML parse ---

func TestParseSpec_ValidationError(t *testing.T) {
	yaml := `
version: 99
site: test
`
	_, err := ParseSpec([]byte(yaml))
	if err == nil {
		t.Fatal("expected validation error for bad version")
	}
}

// --- LoadSpec ---

func TestLoadSpec_Success(t *testing.T) {
	yaml := `
version: 1
site: test-site
networks:
  - name: lan
    cidr: 192.168.1.0/24
    gateway: 192.168.1.1
    zone: internal
assertions:
  - type: subnet_discovery
    network: lan
`
	dir := t.TempDir()
	path := filepath.Join(dir, "spec.yml")
	if err := os.WriteFile(path, []byte(yaml), 0600); err != nil {
		t.Fatalf("failed to write temp spec: %v", err)
	}
	spec, err := LoadSpec(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if spec.Site != "test-site" {
		t.Errorf("expected site 'test-site', got %q", spec.Site)
	}
}

func TestLoadSpec_FileNotFound(t *testing.T) {
	_, err := LoadSpec(filepath.Join(os.TempDir(), "nonexistent_file_12345.yml"))
	if err == nil {
		t.Fatal("expected error for non-existent file")
	}
}

// --- Spec helper methods: not-found cases ---

func TestSpec_VPNByName_NotFound(t *testing.T) {
	spec := &Spec{VPN: []VPNConfig{
		{Name: "work", Type: "wireguard"},
	}}
	if spec.VPNByName("nonexistent") != nil {
		t.Error("expected nil for missing VPN")
	}
}

func TestSpec_ProbeByName_NotFound(t *testing.T) {
	spec := &Spec{Probes: []Probe{
		{Name: "probe1", Host: "10.0.0.1", User: "admin"},
	}}
	if spec.ProbeByName("nonexistent") != nil {
		t.Error("expected nil for missing probe")
	}
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

func TestValidateSpec_NetworkHealthProbeRejectsMTU(t *testing.T) {
	// The probe network_health command measures reachability, latency, and
	// loss — it cannot measure MTU, so declaring expect_mtu with a remote
	// runner is rejected at validation instead of silently ignored (#187).
	spec := &Spec{Version: 1, Site: "test", Assertions: []Assertion{
		{Type: "network_health", Target: "10.0.40.1", Runner: "iot-probe", ExpectMTU: 1500},
	}}
	err := ValidateSpec(spec)
	if err == nil {
		t.Fatal("probe network_health with expect_mtu should be rejected")
	}
	if !strings.Contains(err.Error(), "expect_mtu") {
		t.Errorf("error should name expect_mtu, got: %v", err)
	}
	// Local-runner assertions keep MTU support.
	local := &Spec{Version: 1, Site: "test", Assertions: []Assertion{
		{Type: "network_health", Target: "10.0.40.1", ExpectMTU: 1500},
	}}
	if err := ValidateSpec(local); err != nil {
		t.Errorf("local network_health with expect_mtu should be valid: %v", err)
	}
}

func TestValidateSpec_DNSCheckProbeRejectsDNSSEC(t *testing.T) {
	// The probe dns_check command is nslookup, which never performs DNSSEC
	// validation, so declaring dnssec with a probe runner is rejected at
	// validation instead of silently passing without the requested
	// validation (#269).
	probes := []Probe{{Name: "iot-probe", Host: "127.0.0.1", User: "probe"}}
	spec := &Spec{Version: 1, Site: "test", Probes: probes, Assertions: []Assertion{
		{Type: "dns_check", Runner: "iot-probe", Query: "service.example", DNSSEC: true},
	}}
	err := ValidateSpec(spec)
	if err == nil {
		t.Fatal("probe dns_check with dnssec should be rejected")
	}
	for _, want := range []string{"dnssec", "iot-probe"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should name %q, got: %v", want, err)
		}
	}
	// Omitted runner (local execution) keeps DNSSEC support (#173).
	omitted := &Spec{Version: 1, Site: "test", Assertions: []Assertion{
		{Type: "dns_check", Query: "service.example", DNSSEC: true},
	}}
	if err := ValidateSpec(omitted); err != nil {
		t.Errorf("local dns_check with dnssec should be valid: %v", err)
	}
	// Explicit local runner keeps DNSSEC support.
	local := &Spec{Version: 1, Site: "test", Assertions: []Assertion{
		{Type: "dns_check", Runner: "local", Query: "service.example", DNSSEC: true},
	}}
	if err := ValidateSpec(local); err != nil {
		t.Errorf("runner:local dns_check with dnssec should be valid: %v", err)
	}
	// Probe runners without dnssec keep plain resolution checks.
	plain := &Spec{Version: 1, Site: "test", Probes: probes, Assertions: []Assertion{
		{Type: "dns_check", Runner: "iot-probe", Query: "service.example", ExpectIP: "10.0.40.10"},
	}}
	if err := ValidateSpec(plain); err != nil {
		t.Errorf("probe dns_check without dnssec should be valid: %v", err)
	}
}

func TestParseSpec_DNSCheckProbeRejectsDNSSEC(t *testing.T) {
	// End-to-end: the repro spec from #269 must be rejected by ParseSpec,
	// which is what LoadSpec and every CLI/MCP entry point use.
	data := []byte(`version: 1
site: test
probes:
  - name: iot-probe
    host: 127.0.0.1
    user: probe
    vlan: iot
assertions:
  - type: dns_check
    runner: iot-probe
    query: service.example
    dnssec: true
`)
	if _, err := ParseSpec(data); err == nil {
		t.Fatal("ParseSpec should reject dns_check with a probe runner and dnssec: true")
	}
}

// --- ParseSpec: strict field decoding (#273) ---

func TestParseSpec_UnknownAssertionFieldRejected(t *testing.T) {
	// Exact repro from #273: a misspelled assertion field used to be
	// silently dropped, zeroing the limit and weakening the audit.
	data := []byte(`version: 1
site: test
assertions:
  - type: network_health
    target: 10.0.40.1
    expect_latncy_ms: 1
`)
	_, err := ParseSpec(data)
	if err == nil {
		t.Fatal("ParseSpec should reject the unknown field expect_latncy_ms")
	}
	if !contains(err.Error(), "expect_latncy_ms") {
		t.Fatalf("error should name the unknown field expect_latncy_ms, got: %v", err)
	}
}

func TestParseSpec_UnknownFieldRejected(t *testing.T) {
	// Unknown fields at every structural level are rejected and named
	// (AC-2). Free-form map keys are the only exempt surface.
	cases := []struct {
		name    string
		yaml    string
		unknown string
	}{
		{
			name:    "top-level",
			yaml:    "version: 1\nsite: test\nassertionz: []\n",
			unknown: "assertionz",
		},
		{
			name: "network",
			yaml: `version: 1
site: test
networks:
  - name: servers
    cidr: 10.0.40.0/24
    vlan_id: 40
`,
			unknown: "vlan_id",
		},
		{
			name: "probe",
			yaml: `version: 1
site: test
probes:
  - name: iot-probe
    host: 127.0.0.1
    user: probe
    password: hunter2
`,
			unknown: "password",
		},
		{
			name: "policy",
			yaml: `version: 1
site: test
policies:
  - name: p1
    from: personal
    to: servers
    action: deny
    description: blocks stuff
`,
			unknown: "description",
		},
		{
			name: "assertion",
			yaml: `version: 1
site: test
assertions:
  - type: port_check
    target: 10.0.40.1
    ports: [22]
    expect: open
    expect_ports: [22]
`,
			unknown: "expect_ports",
		},
		{
			name: "inventory",
			yaml: `version: 1
site: test
inventory:
  controller_version: "6.0"
  devicesx: []
`,
			unknown: "devicesx",
		},
		{
			name: "inventory acl scope",
			yaml: `version: 1
site: test
inventory:
  acl_scopes:
    - scoop: gateway
      rule_count: 3
`,
			unknown: "scoop",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseSpec([]byte(tc.yaml))
			if err == nil {
				t.Fatalf("ParseSpec should reject the unknown field %s", tc.unknown)
			}
			if !contains(err.Error(), tc.unknown) {
				t.Fatalf("error should name the unknown field %s, got: %v", tc.unknown, err)
			}
		})
	}
}

func TestParseSpec_FreeFormMapKeysRetained(t *testing.T) {
	// inventory.network_gateways is a free-form name→gateway map: its keys
	// are data, not structure, so strict decoding must not police them.
	data := []byte(`version: 1
site: test
inventory:
  network_gateways:
    servers: 10.0.40.1
    iot: 10.0.60.1
`)
	spec, err := ParseSpec(data)
	if err != nil {
		t.Fatalf("free-form network_gateways keys should parse: %v", err)
	}
	if len(spec.Inventory.NetworkGateways) != 2 {
		t.Fatalf("expected 2 network gateways, got %d", len(spec.Inventory.NetworkGateways))
	}
	if spec.Inventory.NetworkGateways["servers"] != "10.0.40.1" {
		t.Fatalf("gateway value not preserved: %v", spec.Inventory.NetworkGateways)
	}
}

func TestParseSpec_ExtraDocumentRejected(t *testing.T) {
	// The spec is one document; a second nonempty document is invalid and
	// must be reported instead of silently ignored (AC-5).
	data := []byte(`version: 1
site: test
---
version: 2
site: other
`)
	_, err := ParseSpec(data)
	if err == nil {
		t.Fatal("ParseSpec should reject a second document")
	}
	if !contains(err.Error(), "one document") {
		t.Fatalf("error should say the spec must be one document, got: %v", err)
	}
}

func TestParseSpec_TrailingMalformedRejected(t *testing.T) {
	// Malformed input after the spec document is invalid (AC-5).
	data := []byte("version: 1\nsite: test\n---\n{broken\n")
	_, err := ParseSpec(data)
	if err == nil {
		t.Fatal("ParseSpec should reject malformed trailing input")
	}
	if !contains(err.Error(), "parsing spec YAML") {
		t.Fatalf("error should be a parse error, got: %v", err)
	}
}

func TestParseSpec_TrailingEmptyDocumentRejected(t *testing.T) {
	// A trailing document marker starts an extra (empty) document, which
	// still breaks the one-document contract and is rejected.
	data := []byte("version: 1\nsite: test\n---\n")
	_, err := ParseSpec(data)
	if err == nil {
		t.Fatal("ParseSpec should reject a trailing empty document")
	}
	if !contains(err.Error(), "one document") {
		t.Fatalf("error should say the spec must be one document, got: %v", err)
	}
}

func TestParseSpec_EmptyInputSemanticError(t *testing.T) {
	// Empty input reaches ValidateSpec with the zero spec, so the error is
	// the usual semantic one (AC-4).
	_, err := ParseSpec([]byte(""))
	if err == nil {
		t.Fatal("ParseSpec should reject an empty spec")
	}
	if !contains(err.Error(), "unsupported spec version") {
		t.Fatalf("empty input should yield the semantic version error, got: %v", err)
	}
}

func TestParseSpec_RepoFixturesStillParse(t *testing.T) {
	// Shipped examples and testdata fixtures are valid current specs and
	// must keep parsing (AC-3).
	for _, path := range []string{"../../testdata/valid_spec.yaml", "../../examples/homelab.yaml"} {
		t.Run(path, func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("reading fixture: %v", err)
			}
			if _, err := ParseSpec(data); err != nil {
				t.Fatalf("fixture %s should parse: %v", path, err)
			}
		})
	}
}

func TestLoadSpec_RepoFixture(t *testing.T) {
	// LoadSpec shares ParseSpec's strictness on a real fixture file.
	if _, err := LoadSpec("../../testdata/valid_spec.yaml"); err != nil {
		t.Fatalf("testdata/valid_spec.yaml should load: %v", err)
	}
}

func TestLoadSpec_SemanticInvalidFixture(t *testing.T) {
	// The invalid fixture trips semantic validation, not strict decoding:
	// the error must stay meaningful (AC-4).
	_, err := LoadSpec("../../testdata/invalid_spec.yaml")
	if err == nil {
		t.Fatal("invalid_spec.yaml should not load")
	}
	if !contains(err.Error(), "invalid CIDR") {
		t.Fatalf("semantic error should name the bad CIDR, got: %v", err)
	}
}

func TestLoadSpec_UnknownFieldRejected(t *testing.T) {
	// The public LoadSpec path (temp file) rejects unknown fields (AC-6).
	path := filepath.Join(t.TempDir(), "spec.yaml")
	data := []byte(`version: 1
site: test
assertions:
  - type: network_health
    target: 10.0.40.1
    expect_latncy_ms: 1
`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("writing spec: %v", err)
	}
	if _, err := LoadSpec(path); err == nil {
		t.Fatal("LoadSpec should reject the unknown field expect_latncy_ms")
	}
}
