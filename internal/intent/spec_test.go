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
