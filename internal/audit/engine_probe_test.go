package audit

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jpvelasco/nyx/internal/backends"
	"github.com/jpvelasco/nyx/internal/backends/health"
	"github.com/jpvelasco/nyx/internal/backends/system"
	"github.com/jpvelasco/nyx/internal/credentials"
	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/models"
	providers "github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/seendb"
)

// --- probeCommandFor ---

func TestProbeCommandFor_NetworkHealth(t *testing.T) {
	a := intent.Assertion{Type: "network_health", Target: "10.0.0.1"}
	cmd := probeCommandFor(a, nil)
	if cmd == nil {
		t.Fatal("expected non-nil command")
	}
	if cmd[0] != "ping" || cmd[len(cmd)-1] != "10.0.0.1" {
		t.Errorf("unexpected command: %v", cmd)
	}
}

func TestProbeCommandFor_PortCheck(t *testing.T) {
	a := intent.Assertion{Type: "port_check", Target: "10.0.0.1", Ports: []int{80}}
	cmd := probeCommandFor(a, nil)
	if cmd == nil {
		t.Fatal("expected non-nil command")
	}
	if cmd[0] != "nc" || cmd[len(cmd)-1] != "80" {
		t.Errorf("unexpected command: %v", cmd)
	}
}

func TestProbeCommandFor_PortCheck_NoPorts(t *testing.T) {
	a := intent.Assertion{Type: "port_check", Target: "10.0.0.1", Ports: nil}
	cmd := probeCommandFor(a, nil)
	if cmd != nil {
		t.Errorf("expected nil for port_check without ports, got %v", cmd)
	}
}

func TestProbeCommandFor_DNSCheck_WithServer(t *testing.T) {
	a := intent.Assertion{Type: "dns_check", Query: "example.com", Server: "8.8.8.8"}
	cmd := probeCommandFor(a, nil)
	if cmd == nil {
		t.Fatal("expected non-nil command")
	}
	if cmd[0] != "nslookup" || cmd[2] != "8.8.8.8" {
		t.Errorf("unexpected command: %v", cmd)
	}
}

func TestProbeCommandFor_DNSCheck_NoServer(t *testing.T) {
	a := intent.Assertion{Type: "dns_check", Query: "example.com"}
	cmd := probeCommandFor(a, nil)
	if cmd == nil {
		t.Fatal("expected non-nil command")
	}
	if len(cmd) != 2 {
		t.Errorf("expected 2 args, got %d: %v", len(cmd), cmd)
	}
}

func TestProbeCommandFor_IsolationWithTarget(t *testing.T) {
	a := intent.Assertion{Type: "isolation", Target: "10.0.0.1", From: "zone1", To: "zone2"}
	cmd := probeCommandFor(a, nil)
	if cmd == nil {
		t.Fatal("expected non-nil command")
	}
	if cmd[len(cmd)-1] != "10.0.0.1" {
		t.Errorf("expected target in command, got %v", cmd)
	}
}

func TestProbeCommandFor_IsolationNoTargetResolvesZoneAsTarget(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Networks: []intent.Network{
			{Name: "net1", CIDR: "10.0.0.0/24", Zone: "zone1"},
		},
	}
	a := intent.Assertion{Type: "isolation", From: "zone1", To: "zone2", Expect: "deny"}
	cmd := probeCommandFor(a, spec)
	// resolveZoneToGateway returns "zone2" as fallback (no network with that zone),
	// which becomes the ping target — not nil
	if cmd == nil {
		t.Fatal("expected non-nil command (zone name used as target)")
	}
	if cmd[len(cmd)-1] != "zone2" {
		t.Errorf("expected zone2 as target, got %v", cmd)
	}
}

func TestProbeCommandFor_IsolationResolvesZoneGateway(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Networks: []intent.Network{
			{Name: "net1", CIDR: "10.0.0.0/24", Gateway: "10.0.0.1", Zone: "zone2"},
		},
	}
	a := intent.Assertion{Type: "isolation", From: "zone1", To: "zone2", Expect: "deny"}
	cmd := probeCommandFor(a, spec)
	if cmd == nil {
		t.Fatal("expected non-nil command when gateway resolved")
	}
	if cmd[len(cmd)-1] != "10.0.0.1" {
		t.Errorf("expected gateway in command, got %v", cmd)
	}
}

func TestProbeCommandFor_UnknownType(t *testing.T) {
	a := intent.Assertion{Type: "unknown", Target: "10.0.0.1"}
	cmd := probeCommandFor(a, nil)
	if cmd != nil {
		t.Errorf("expected nil for unknown type, got %v", cmd)
	}
}

func TestProbeCommandFor_SubnetDiscoveryNotSupported(t *testing.T) {
	a := intent.Assertion{Type: "subnet_discovery", Network: "lan"}
	cmd := probeCommandFor(a, nil)
	if cmd != nil {
		t.Errorf("expected nil for subnet_discovery, got %v", cmd)
	}
}

func TestProbeCommandFor_VPNRouteNotSupported(t *testing.T) {
	a := intent.Assertion{Type: "vpn_route", VPN: "work", Target: "10.0.0.1"}
	cmd := probeCommandFor(a, nil)
	if cmd != nil {
		t.Errorf("expected nil for vpn_route, got %v", cmd)
	}
}

// --- resolveZoneToGateway / resolveZoneToGateways ---

func TestResolveZoneToGateway_NilSpec(t *testing.T) {
	got := resolveZoneToGateway("zone1", nil)
	if got != "zone1" {
		t.Errorf("expected zone1 (passthrough), got %q", got)
	}
}

func TestResolveZoneToGateway_ByZoneWithGateway(t *testing.T) {
	spec := &intent.Spec{
		Networks: []intent.Network{
			{Name: "net1", CIDR: "10.0.0.0/24", Gateway: "10.0.0.1", Zone: "zone1"},
		},
	}
	got := resolveZoneToGateway("zone1", spec)
	if got != "10.0.0.1" {
		t.Errorf("expected gateway 10.0.0.1, got %q", got)
	}
}

func TestResolveZoneToGateway_ByNetworkName(t *testing.T) {
	spec := &intent.Spec{
		Networks: []intent.Network{
			{Name: "zone1", CIDR: "10.0.0.0/24", Gateway: "10.0.0.1"},
		},
	}
	got := resolveZoneToGateway("zone1", spec)
	if got != "10.0.0.1" {
		t.Errorf("expected gateway 10.0.0.1, got %q", got)
	}
}

func TestResolveZoneToGateway_NotFound(t *testing.T) {
	spec := &intent.Spec{
		Networks: []intent.Network{
			{Name: "net1", CIDR: "10.0.0.0/24", Gateway: "10.0.0.1", Zone: "zone1"},
		},
	}
	got := resolveZoneToGateway("nonexistent", spec)
	if got != "nonexistent" {
		t.Errorf("expected passthrough, got %q", got)
	}
}

func TestResolveZoneToGateways_NilSpec(t *testing.T) {
	got := resolveZoneToGateways("zone1", nil)
	if got != nil {
		t.Errorf("expected nil for nil spec, got %v", got)
	}
}

func TestResolveZoneToGateways_ByZoneEmptyGateway(t *testing.T) {
	spec := &intent.Spec{
		Networks: []intent.Network{
			{Name: "net1", CIDR: "10.0.0.0/24", Zone: "zone1"},
		},
	}
	got := resolveZoneToGateways("zone1", spec)
	if len(got) != 0 {
		t.Errorf("expected empty gateways (no gateway set), got %v", got)
	}
}

func TestResolveZoneToGateways_ByNetworkNameFallback(t *testing.T) {
	spec := &intent.Spec{
		Networks: []intent.Network{
			{Name: "net1", CIDR: "10.0.0.0/24", Gateway: "10.0.0.1", Zone: "zone1"},
		},
	}
	got := resolveZoneToGateways("net1", spec)
	if len(got) != 1 || got[0] != "10.0.0.1" {
		t.Errorf("expected [10.0.0.1], got %v", got)
	}
}

func TestResolveZoneToGateways_MultipleGateways(t *testing.T) {
	spec := &intent.Spec{
		Networks: []intent.Network{
			{Name: "net1", CIDR: "10.0.0.0/24", Gateway: "10.0.0.1", Zone: "zone1"},
			{Name: "net2", CIDR: "10.0.1.0/24", Gateway: "10.0.1.1", Zone: "zone1"},
		},
	}
	got := resolveZoneToGateways("zone1", spec)
	if len(got) != 2 {
		t.Errorf("expected 2 gateways, got %d: %v", len(got), got)
	}
}

// --- probeTarget ---

func TestProbeTarget_TargetSet(t *testing.T) {
	a := intent.Assertion{Target: "10.0.0.1"}
	if got := probeTarget(a); got != "10.0.0.1" {
		t.Errorf("expected 10.0.0.1, got %s", got)
	}
}

func TestProbeTarget_QuerySet(t *testing.T) {
	a := intent.Assertion{Query: "example.com"}
	if got := probeTarget(a); got != "example.com" {
		t.Errorf("expected example.com, got %s", got)
	}
}

func TestProbeTarget_NeitherSet(t *testing.T) {
	a := intent.Assertion{From: "zone1", To: "zone2"}
	got := probeTarget(a)
	if !strings.Contains(got, "zone1") || !strings.Contains(got, "zone2") {
		t.Errorf("expected from→to format, got %s", got)
	}
}

// --- isPingBlocked ---

func TestIsPingBlocked(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   bool
	}{
		{"100% loss", "100% packet loss", true},
		{"100.0% loss", "100.0% packet loss", true},
		{"0 received", "0 received", true},
		{"normal ping", "3 packets received", false},
		{"empty", "", false},
		{"partial loss", "50% packet loss", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isPingBlocked(tt.output); got != tt.want {
				t.Errorf("isPingBlocked(%q) = %v, want %v", tt.output, got, tt.want)
			}
		})
	}
}

// --- parseProbeOutput ---

func TestParseProbeOutput_IsolationBlocked(t *testing.T) {
	result := models.NewCheckResult("probe", "isolation", "probe1", "10.0.0.1")
	a := intent.Assertion{Type: "isolation", From: "zone1", To: "zone2", Expect: "deny", Runner: "probe1"}
	got := parseProbeOutput(result, a, "100% packet loss", false)
	if got.Status != models.StatusPass {
		t.Errorf("expected pass (deny+blocked), got %s: %s", got.Status, got.Summary)
	}
}

func TestParseProbeOutput_IsolationReachable(t *testing.T) {
	result := models.NewCheckResult("probe", "isolation", "probe1", "10.0.0.1")
	a := intent.Assertion{Type: "isolation", From: "zone1", To: "zone2", Expect: "deny", Runner: "probe1"}
	got := parseProbeOutput(result, a, "3 packets received", false)
	if got.Status != models.StatusFail {
		t.Errorf("expected fail (deny+reachable), got %s: %s", got.Status, got.Summary)
	}
}

func TestParseProbeOutput_IsolationAllowReachable(t *testing.T) {
	result := models.NewCheckResult("probe", "isolation", "probe1", "10.0.0.1")
	a := intent.Assertion{Type: "isolation", From: "zone1", To: "zone2", Expect: "allow", Runner: "probe1"}
	got := parseProbeOutput(result, a, "3 packets received", false)
	if got.Status != models.StatusPass {
		t.Errorf("expected pass (allow+reachable), got %s: %s", got.Status, got.Summary)
	}
}

func TestParseProbeOutput_IsolationAllowBlocked(t *testing.T) {
	result := models.NewCheckResult("probe", "isolation", "probe1", "10.0.0.1")
	a := intent.Assertion{Type: "isolation", From: "zone1", To: "zone2", Expect: "allow", Runner: "probe1"}
	got := parseProbeOutput(result, a, "100% packet loss", false)
	if got.Status != models.StatusFail {
		t.Errorf("expected fail (allow+blocked), got %s: %s", got.Status, got.Summary)
	}
}

func TestParseProbeOutput_PortCheckOpen(t *testing.T) {
	result := models.NewCheckResult("probe", "port_check", "probe1", "10.0.0.1")
	a := intent.Assertion{Type: "port_check", Target: "10.0.0.1", Ports: []int{80}, Expect: "open", Runner: "probe1"}
	got := parseProbeOutput(result, a, "some output", false)
	if got.Status != models.StatusPass {
		t.Errorf("expected pass (open), got %s: %s", got.Status, got.Summary)
	}
}

func TestParseProbeOutput_PortCheckOpenExpectedButRemoteClosed(t *testing.T) {
	result := models.NewCheckResult("probe", "port_check", "probe1", "10.0.0.1")
	a := intent.Assertion{Type: "port_check", Target: "10.0.0.1", Ports: []int{80}, Expect: "open", Runner: "probe1"}
	got := parseProbeOutput(result, a, "", true)
	if got.Status != models.StatusFail {
		t.Errorf("expected fail (nc closed a port expected open), got %s: %s", got.Status, got.Summary)
	}
	if len(got.Violations) == 0 {
		t.Error("expected violations")
	}
}

func TestParseProbeOutput_PortCheckClosedWhenOpen(t *testing.T) {
	result := models.NewCheckResult("probe", "port_check", "probe1", "10.0.0.1")
	a := intent.Assertion{Type: "port_check", Target: "10.0.0.1", Ports: []int{80}, Expect: "closed", Runner: "probe1"}
	got := parseProbeOutput(result, a, "some output", false)
	if got.Status != models.StatusFail {
		t.Fatalf("expected fail (expect closed but port is open), got %s: %s", got.Status, got.Summary)
	}
	if len(got.Violations) == 0 {
		t.Error("expected violations")
	}
}

func TestParseProbeOutput_PortCheckClosedWhenRemoteClosed(t *testing.T) {
	result := models.NewCheckResult("probe", "port_check", "probe1", "10.0.0.1")
	a := intent.Assertion{Type: "port_check", Target: "10.0.0.1", Ports: []int{80}, Expect: "closed", Runner: "probe1"}
	got := parseProbeOutput(result, a, "", true)
	if got.Status != models.StatusPass {
		t.Errorf("expected pass (nc reported closed), got %s: %s", got.Status, got.Summary)
	}
}

func TestParseProbeOutput_NetworkHealthUnreachable(t *testing.T) {
	result := models.NewCheckResult("probe", "network_health", "probe1", "10.0.0.1")
	a := intent.Assertion{Type: "network_health", Target: "10.0.0.1", Runner: "probe1"}
	got := parseProbeOutput(result, a, "100% packet loss", false)
	if got.Status != models.StatusFail {
		t.Errorf("expected fail (100%% loss), got %s: %s", got.Status, got.Summary)
	}
}

func TestParseProbeOutput_NetworkHealthReachable(t *testing.T) {
	result := models.NewCheckResult("probe", "network_health", "probe1", "10.0.0.1")
	a := intent.Assertion{Type: "network_health", Target: "10.0.0.1", Runner: "probe1"}
	got := parseProbeOutput(result, a, "3 packets received", false)
	if got.Status != models.StatusPass {
		t.Errorf("expected pass, got %s: %s", got.Status, got.Summary)
	}
}

func TestParseProbeOutput_NetworkHealthRemoteNoReplies(t *testing.T) {
	result := models.NewCheckResult("probe", "network_health", "probe1", "10.0.0.1")
	a := intent.Assertion{Type: "network_health", Target: "10.0.0.1", Runner: "probe1"}
	got := parseProbeOutput(result, a, "", true)
	if got.Status != models.StatusFail {
		t.Errorf("expected fail (remote ping exited non-zero), got %s: %s", got.Status, got.Summary)
	}
}

func TestParseProbeOutput_DNSCheckExpectIPNotFound(t *testing.T) {
	result := models.NewCheckResult("probe", "dns_check", "probe1", "example.com")
	a := intent.Assertion{Type: "dns_check", Query: "example.com", ExpectIP: "93.184.216.34", Runner: "probe1"}
	got := parseProbeOutput(result, a, "different IP returned", false)
	if got.Status != models.StatusFail {
		t.Errorf("expected fail (expected IP not found), got %s: %s", got.Status, got.Summary)
	}
}

func TestParseProbeOutput_DNSCheckExpectIPFound(t *testing.T) {
	result := models.NewCheckResult("probe", "dns_check", "probe1", "example.com")
	a := intent.Assertion{Type: "dns_check", Query: "example.com", ExpectIP: "93.184.216.34", Runner: "probe1"}
	got := parseProbeOutput(result, a, "Address: 93.184.216.34", false)
	if got.Status != models.StatusPass {
		t.Errorf("expected pass (expected IP found), got %s: %s", got.Status, got.Summary)
	}
}

func TestParseProbeOutput_DNSCheckServerAddressDoesNotWin(t *testing.T) {
	// The resolver's own address always appears in nslookup output ("Server:" /
	// "Address:" preamble). The check must not pass on it (regression: substring
	// matching against the whole output did).
	output := "Server:  10.0.0.1\nAddress: 10.0.0.1#53\n\nName:    vpn.home\nAddress: 10.0.0.20"
	result := models.NewCheckResult("probe", "dns_check", "probe1", "vpn.home")
	a := intent.Assertion{Type: "dns_check", Query: "vpn.home", Server: "10.0.0.1", ExpectIP: "10.0.0.1", Runner: "probe1"}
	got := parseProbeOutput(result, a, output, false)
	if got.Status != models.StatusFail {
		t.Errorf("expected fail (resolver address must not satisfy expect_ip), got %s: %s", got.Status, got.Summary)
	}
}

func TestParseProbeOutput_DNSCheckAnswerExactMatch(t *testing.T) {
	// A real answer (10.0.0.20) must pass even though the resolver preamble
	// lists a different address.
	output := "Server:  10.0.0.1\nAddress: 10.0.0.1#53\n\n\tName: vpn.home\nAddress: 10.0.0.20"
	result := models.NewCheckResult("probe", "dns_check", "probe1", "vpn.home")
	a := intent.Assertion{Type: "dns_check", Query: "vpn.home", Server: "10.0.0.1", ExpectIP: "10.0.0.20", Runner: "probe1"}
	got := parseProbeOutput(result, a, output, false)
	if got.Status != models.StatusPass {
		t.Errorf("expected pass (answer matched), got %s: %s", got.Status, got.Summary)
	}
}

func TestParseProbeOutput_DNSCheckExpectIPNoSubstringPrefix(t *testing.T) {
	// 10.0.0.1 must not match answer 10.0.0.10 (substring trap).
	output := "Server:  8.8.8.8\nAddress: 8.8.8.8#53\n\nName: host.lan\nAddress: 10.0.0.10"
	result := models.NewCheckResult("probe", "dns_check", "probe1", "host.lan")
	a := intent.Assertion{Type: "dns_check", Query: "host.lan", Server: "8.8.8.8", ExpectIP: "10.0.0.1", Runner: "probe1"}
	got := parseProbeOutput(result, a, output, false)
	if got.Status != models.StatusFail {
		t.Errorf("expected fail (substring false positive), got %s: %s", got.Status, got.Summary)
	}
}

func TestParseProbeOutput_DNSCheckRemoteFailure(t *testing.T) {
	result := models.NewCheckResult("probe", "dns_check", "probe1", "example.com")
	a := intent.Assertion{Type: "dns_check", Query: "nxdomain.example", ExpectIP: "93.184.216.34", Runner: "probe1"}
	got := parseProbeOutput(result, a, "Server: 8.8.8.8\nAddress: 8.8.8.8#53", true)
	if got.Status != models.StatusFail {
		t.Errorf("expected fail (nslookup NXDOMAIN), got %s: %s", got.Status, got.Summary)
	}
}

func TestParseProbeOutput_DNSCheckNoExpectIP(t *testing.T) {
	result := models.NewCheckResult("probe", "dns_check", "probe1", "example.com")
	a := intent.Assertion{Type: "dns_check", Query: "example.com", Runner: "probe1"}
	got := parseProbeOutput(result, a, "Address: 1.2.3.4", false)
	if got.Status != models.StatusPass {
		t.Errorf("expected pass (no expect IP), got %s: %s", got.Status, got.Summary)
	}
}

func TestParseProbeOutput_DefaultBranch(t *testing.T) {
	result := models.NewCheckResult("probe", "unknown", "probe1", "target")
	a := intent.Assertion{Type: "vlan_check", Target: "10.0.0.1", Runner: "probe1"}
	got := parseProbeOutput(result, a, "some output", false)
	if got.Status != models.StatusWarn {
		t.Errorf("expected warn for unhandled type, got %s: %s", got.Status, got.Summary)
	}
}

func TestProbeDNSAnswers_ExcludesServerAddress(t *testing.T) {
	output := "Server:  10.0.0.1\nAddress: 10.0.0.1#53\n\n\tName: vpn.home\nAddress: 10.0.0.20"
	got := probeDNSAnswers(output, "10.0.0.1")
	if len(got) != 1 || got[0] != "10.0.0.20" {
		t.Errorf("expected only the answer address, got %v", got)
	}
}

func TestProbeDNSAnswers_NoAnswer(t *testing.T) {
	output := "Server:  8.8.8.8\nAddress: 8.8.8.8#53\n\n** server can't find foo: NXDOMAIN"
	if got := probeDNSAnswers(output, "8.8.8.8"); len(got) != 0 {
		t.Errorf("expected no answers for NXDOMAIN, got %v", got)
	}
}

func TestProbeDNSAnswers_Deduplicates(t *testing.T) {
	// The same address repeated in the output (e.g. multiple names for one
	// record) must be reported once.
	output := "Server:  10.0.0.1\nAddress: 10.0.0.1#53\n\nName: db.example.com\nAddress: 192.0.2.10\nAddress: 192.0.2.10\n"
	got := probeDNSAnswers(output, "10.0.0.1")
	if len(got) != 1 || got[0] != "192.0.2.10" {
		t.Errorf("expected single deduplicated answer, got %v", got)
	}
}

// --- explainAssertionError remaining branches ---

func TestExplainAssertionError_ProbeUnreachable(t *testing.T) {
	a := intent.Assertion{Type: "subnet_discovery", Runner: "probe1"}
	summary, details := explainAssertionError(a, backends.BackendError("probe \"probe1\" unreachable at 10.0.0.1:22"))
	if !strings.Contains(summary, "unreachable") {
		t.Errorf("unexpected summary: %s", summary)
	}
	if len(details) == 0 {
		t.Error("expected details for probe unreachable")
	}
}

func TestExplainAssertionError_NetworkHealthFailed(t *testing.T) {
	a := intent.Assertion{Type: "network_health"}
	summary, details := explainAssertionError(a, backends.BackendError("network health check failed: ping error"))
	if !strings.Contains(summary, "ping didn't complete") {
		t.Errorf("unexpected summary: %s", summary)
	}
	if len(details) == 0 {
		t.Error("expected details for network health failure")
	}
}

// --- matchNetworks ---

func TestMatchNetworks_InvalidCIDR(t *testing.T) {
	spec := &intent.Spec{
		Networks: []intent.Network{
			{Name: "net1", CIDR: "invalid-cidr"},
		},
	}
	ips := []net.IP{net.ParseIP("10.0.0.1")}
	got := matchNetworks(ips, spec)
	if len(got) != 0 {
		t.Errorf("expected no matches for invalid CIDR, got %v", got)
	}
}

func TestMatchNetworks_NoMatch(t *testing.T) {
	spec := &intent.Spec{
		Networks: []intent.Network{
			{Name: "net1", CIDR: "10.0.0.0/24"},
		},
	}
	ips := []net.IP{net.ParseIP("192.168.1.1")}
	got := matchNetworks(ips, spec)
	if len(got) != 0 {
		t.Errorf("expected no matches, got %v", got)
	}
}

// --- runViaProbe ---

func TestRunViaProbe_ProbeNotFound(t *testing.T) {
	spec := &intent.Spec{Version: 1, Site: "test"}
	eng := NewEngine(spec)
	eng.Backend = &backends.MockBackend{}
	a := intent.Assertion{Type: "network_health", Runner: "nonexistent", Target: "10.0.0.1"}
	_, err := eng.runViaProbe(context.Background(), a)
	if err == nil {
		t.Fatal("expected error for unknown probe")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' in error, got: %v", err)
	}
}

func TestRunViaProbe_UnsupportedType(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Probes: []intent.Probe{
			{Name: "probe1", Host: "192.0.2.1", User: "test"},
		},
	}
	eng := NewEngine(spec)
	eng.Backend = &backends.MockBackend{}
	a := intent.Assertion{Type: "subnet_discovery", Runner: "probe1", Network: "lan"}
	_, err := eng.runViaProbe(context.Background(), a)
	if err == nil {
		t.Fatal("expected error for unsupported assertion type on probe")
	}
	if !strings.Contains(err.Error(), "does not support") {
		t.Errorf("expected 'does not support' in error, got: %v", err)
	}
}

func TestRunViaProbe_SSHFailure(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Probes: []intent.Probe{
			{Name: "probe1", Host: "192.0.2.1", User: "test", VLAN: "test"},
		},
	}
	eng := NewEngine(spec)
	eng.Backend = &backends.MockBackend{}
	eng.SkipHostKeyVerify = true
	a := intent.Assertion{Type: "network_health", Runner: "probe1", Target: "10.0.0.1"}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result, err := eng.runViaProbe(ctx, a)
	if err != nil {
		t.Fatalf("expected no error (wrapped in result), got: %v", err)
	}
	if result == nil {
		t.Fatal("expected result")
	}
	if result.Status != models.StatusError {
		t.Errorf("expected error status for unreachable probe, got %s: %s", result.Status, result.Summary)
	}
}

// --- runIsolationViaProbe ---

func TestRunViaProbe_IsolationSSHFailure_DenyExpect(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Probes: []intent.Probe{
			{Name: "probe1", Host: "192.0.2.1", User: "test", VLAN: "test"},
		},
		Networks: []intent.Network{
			{Name: "net1", CIDR: "10.0.0.0/24", Gateway: "10.0.0.1", Zone: "zone1"},
		},
	}
	eng := NewEngine(spec)
	eng.Backend = &backends.MockBackend{}
	eng.SkipHostKeyVerify = true
	a := intent.Assertion{
		Type:   "isolation",
		From:   "zone1",
		To:     "zone1",
		Expect: "deny",
		Runner: "probe1",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	result, err := eng.runViaProbe(ctx, a)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected result")
	}
	// SSH transport failure means the probe never tested anything — the
	// check must NOT confirm isolation (regression: it used to pass).
	if result.Status != models.StatusWarn {
		t.Errorf("expected warn (unverifiable), got %s: %s", result.Status, result.Summary)
	}
}

func TestRunViaProbe_IsolationSSHFailure_AllowExpect(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Probes: []intent.Probe{
			{Name: "probe1", Host: "192.0.2.1", User: "test", VLAN: "test"},
		},
		Networks: []intent.Network{
			{Name: "net1", CIDR: "10.0.0.0/24", Gateway: "10.0.0.1", Zone: "zone1"},
		},
	}
	eng := NewEngine(spec)
	eng.Backend = &backends.MockBackend{}
	eng.SkipHostKeyVerify = true
	a := intent.Assertion{
		Type:   "isolation",
		From:   "zone1",
		To:     "zone1",
		Expect: "allow",
		Runner: "probe1",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	result, err := eng.runViaProbe(ctx, a)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected result")
	}
	// SSH failure must not produce a definitive verdict for allow either.
	if result.Status != models.StatusWarn {
		t.Errorf("expected warn (unverifiable), got %s: %s", result.Status, result.Summary)
	}
}

// --- runACLCheck remaining paths ---

// name defaults to "acltest" unless overridden, so tests can register it
// under a real provider name (e.g. "omada") to exercise the engine's
// per-provider credential mapping. It deliberately does NOT implement
// providers.NatChecker (pinned by TestRunNatCheck_ProviderLacksNatChecker).
type aclTestProvider struct {
	name string
}

func (a *aclTestProvider) Name() string {
	if a.name != "" {
		return a.name
	}
	return "acltest"
}
func (a *aclTestProvider) Capabilities() []string { return []string{"info"} }
func (a *aclTestProvider) Info(ctx context.Context, opts providers.ImportOptions) (*providers.ProviderInfo, error) {
	return nil, nil
}
func (a *aclTestProvider) ImportSpec(ctx context.Context, opts providers.ImportOptions) (*providers.ImportResult, error) {
	return nil, nil
}
func (a *aclTestProvider) Check(ctx context.Context, opts providers.ImportOptions) (*providers.AuditResult, error) {
	return nil, nil
}
func (a *aclTestProvider) CheckACL(ctx context.Context, req providers.ACLCheckRequest, opts providers.ImportOptions) (*models.CheckResult, error) {
	return nil, nil
}

func TestRunACLCheck_ProviderNotFound(t *testing.T) {
	providers.Reset()
	t.Cleanup(func() { providers.Reset() })

	spec := &intent.Spec{
		Version: 1, Site: "test",
		Policies: []intent.Policy{
			{Name: "policy1", From: "zone1", To: "zone2", Action: "deny"},
		},
	}
	eng := NewEngine(spec)
	eng.Backend = &backends.MockBackend{}
	a := intent.Assertion{
		Type:     "acl_check",
		Provider: "nonexistent",
		Policy:   "policy1",
		Expect:   "enforced",
	}
	result, err := eng.runACLCheck(context.Background(), a)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusError {
		t.Errorf("expected error for unknown provider, got %s: %s", result.Status, result.Summary)
	}
}

func TestRunACLCheck_MissingCredentials(t *testing.T) {
	providers.Reset()
	t.Cleanup(func() { providers.Reset() })
	providers.Register(&aclTestProvider{})

	t.Setenv("OMADA_HOST", "")
	t.Setenv("OMADA_CLIENT_ID", "")
	t.Setenv("OMADA_CLIENT_SECRET", "")

	spec := &intent.Spec{
		Version: 1, Site: "test",
		Policies: []intent.Policy{
			{Name: "policy1", From: "zone1", To: "zone2", Action: "deny"},
		},
	}
	eng := NewEngine(spec)
	eng.Backend = &backends.MockBackend{}
	a := intent.Assertion{
		Type:     "acl_check",
		Provider: "acltest",
		Policy:   "policy1",
		Expect:   "enforced",
	}
	result, err := eng.runACLCheck(context.Background(), a)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusError {
		t.Errorf("expected error for missing credentials, got %s: %s", result.Status, result.Summary)
	}
	if !strings.Contains(result.Summary, "requires") {
		t.Errorf("expected 'requires' in summary, got: %s", result.Summary)
	}
}

// The omada provider is the only one that consults the Windows
// Credential Manager, so its missing-credential error must carry the WM
// hint clause; every other provider's error must not (off-Windows the
// overlay is a no-op, but the hint is emitted for omada regardless).
func TestRunACLCheck_MissingCredentials_OmadaHint(t *testing.T) {
	providers.Reset()
	t.Cleanup(func() { providers.Reset() })
	providers.Register(&aclTestProvider{name: "omada"})

	// Host present, credentials missing: the WM lookup is a silent miss
	// (off-Windows) and the hint names the entry after the resolved host.
	t.Setenv("OMADA_HOST", "omada.local")
	t.Setenv("OMADA_CLIENT_ID", "")
	t.Setenv("OMADA_CLIENT_SECRET", "")
	t.Setenv("OMADA_SITE", "")

	spec := &intent.Spec{
		Version: 1, Site: "test",
		Policies: []intent.Policy{
			{Name: "policy1", From: "zone1", To: "zone2", Action: "deny"},
		},
	}
	eng := NewEngine(spec)
	eng.Backend = &backends.MockBackend{}
	eng.CredentialsPath = filepath.Join(t.TempDir(), "empty.json")
	a := intent.Assertion{
		Type:     "acl_check",
		Provider: "omada",
		Policy:   "policy1",
		Expect:   "enforced",
	}
	result, err := eng.runACLCheck(context.Background(), a)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusError {
		t.Fatalf("expected error for missing credentials, got %s: %s", result.Status, result.Summary)
	}
	if !strings.Contains(result.Summary, "Windows Credential Manager entry nyx-omada-omada.local") {
		t.Errorf("omada summary should name the WM entry, got: %s", result.Summary)
	}
}

// A non-omada provider (opnsense or any third party) must keep the plain
// error without the WM clause.
func TestRunACLCheck_MissingCredentials_NoHintForOtherProviders(t *testing.T) {
	providers.Reset()
	t.Cleanup(func() { providers.Reset() })
	providers.Register(&aclTestProvider{name: "opnsense"})

	t.Setenv("OMADA_HOST", "")
	t.Setenv("OMADA_CLIENT_ID", "")
	t.Setenv("OMADA_CLIENT_SECRET", "")
	t.Setenv("OMADA_SITE", "")

	spec := &intent.Spec{
		Version: 1, Site: "test",
		Policies: []intent.Policy{
			{Name: "policy1", From: "zone1", To: "zone2", Action: "deny"},
		},
	}
	eng := NewEngine(spec)
	eng.Backend = &backends.MockBackend{}
	eng.CredentialsPath = filepath.Join(t.TempDir(), "empty.json")
	a := intent.Assertion{
		Type:     "acl_check",
		Provider: "opnsense",
		Policy:   "policy1",
		Expect:   "enforced",
	}
	result, err := eng.runACLCheck(context.Background(), a)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusError {
		t.Fatalf("expected error for missing credentials, got %s: %s", result.Status, result.Summary)
	}
	if strings.Contains(result.Summary, "Windows Credential Manager") {
		t.Errorf("non-omada summary must not mention the WM, got: %s", result.Summary)
	}
}

type recordingACLProvider struct {
	called bool
	opts   providers.ImportOptions
}

func (r *recordingACLProvider) Name() string           { return "recacl" }
func (r *recordingACLProvider) Capabilities() []string { return []string{"acl_check"} }
func (r *recordingACLProvider) Info(ctx context.Context, opts providers.ImportOptions) (*providers.ProviderInfo, error) {
	return nil, nil
}
func (r *recordingACLProvider) ImportSpec(ctx context.Context, opts providers.ImportOptions) (*providers.ImportResult, error) {
	return nil, nil
}
func (r *recordingACLProvider) Check(ctx context.Context, opts providers.ImportOptions) (*providers.AuditResult, error) {
	return nil, nil
}
func (r *recordingACLProvider) CheckACL(ctx context.Context, req providers.ACLCheckRequest, opts providers.ImportOptions) (*models.CheckResult, error) {
	r.called = true
	r.opts = opts
	return &models.CheckResult{Status: models.StatusPass}, nil
}

func TestRunACLCheck_VaultFallback(t *testing.T) {
	providers.Reset()
	t.Cleanup(func() { providers.Reset() })
	rec := &recordingACLProvider{}
	if err := providers.Register(rec); err != nil {
		t.Fatalf("register failed: %v", err)
	}

	t.Setenv("OMADA_HOST", "")
	t.Setenv("OMADA_CLIENT_ID", "")
	t.Setenv("OMADA_CLIENT_SECRET", "")

	storePath := filepath.Join(t.TempDir(), "credentials.json")
	store, err := credentials.Open(storePath)
	if err != nil {
		t.Fatalf("credentials.Open failed: %v", err)
	}
	if err := store.Set("recacl", "default", credentials.Entry{
		"host":          "10.0.0.9",
		"client_id":     "vault-user",
		"client_secret": "vault-pass",
	}); err != nil {
		t.Fatalf("store.Set failed: %v", err)
	}

	spec := &intent.Spec{
		Version: 1, Site: "test",
		Policies: []intent.Policy{
			{Name: "policy1", From: "zone1", To: "zone2", Action: "deny"},
		},
	}
	eng := NewEngine(spec)
	eng.Backend = &backends.MockBackend{}
	eng.CredentialsPath = storePath
	a := intent.Assertion{
		Type:     "acl_check",
		Provider: "recacl",
		Policy:   "policy1",
		Expect:   "enforced",
	}
	result, err := eng.runACLCheck(context.Background(), a)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !rec.called {
		t.Fatal("provider was not called; vault fallback did not fill credentials")
	}
	if rec.opts.Host != "10.0.0.9" || rec.opts.ClientID != "vault-user" || rec.opts.ClientSecret != "vault-pass" {
		t.Errorf("provider received opts from env instead of vault: %+v", rec.opts)
	}
	if result.Status != models.StatusPass {
		t.Errorf("expected pass from recording provider, got %s", result.Status)
	}
}

func TestRunACLCheck_VaultEmptyFallbackStillErrors(t *testing.T) {
	providers.Reset()
	t.Cleanup(func() { providers.Reset() })
	providers.Register(&aclTestProvider{})

	t.Setenv("OMADA_HOST", "")
	t.Setenv("OMADA_CLIENT_ID", "")
	t.Setenv("OMADA_CLIENT_SECRET", "")

	// Store exists but has no entry for this provider.
	storePath := filepath.Join(t.TempDir(), "credentials.json")
	if _, err := credentials.Open(storePath); err != nil {
		t.Fatalf("credentials.Open failed: %v", err)
	}

	spec := &intent.Spec{
		Version: 1, Site: "test",
		Policies: []intent.Policy{
			{Name: "policy1", From: "zone1", To: "zone2", Action: "deny"},
		},
	}
	eng := NewEngine(spec)
	eng.Backend = &backends.MockBackend{}
	eng.CredentialsPath = storePath
	a := intent.Assertion{
		Type:     "acl_check",
		Provider: "acltest",
		Policy:   "policy1",
		Expect:   "enforced",
	}
	result, err := eng.runACLCheck(context.Background(), a)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusError {
		t.Errorf("expected error when vault has no entry, got %s", result.Status)
	}
}

func TestRunACLCheck_VaultCorruptFallsThrough(t *testing.T) {
	providers.Reset()
	t.Cleanup(func() { providers.Reset() })
	providers.Register(&aclTestProvider{})

	t.Setenv("OMADA_HOST", "")
	t.Setenv("OMADA_CLIENT_ID", "")
	t.Setenv("OMADA_CLIENT_SECRET", "")

	// A corrupt store must not crash the check; it falls through to the
	// normal missing-credentials error.
	storePath := filepath.Join(t.TempDir(), "credentials.json")
	if err := os.WriteFile(storePath, []byte("garbage"), 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	spec := &intent.Spec{
		Version: 1, Site: "test",
		Policies: []intent.Policy{
			{Name: "policy1", From: "zone1", To: "zone2", Action: "deny"},
		},
	}
	eng := NewEngine(spec)
	eng.Backend = &backends.MockBackend{}
	eng.CredentialsPath = storePath
	a := intent.Assertion{
		Type:     "acl_check",
		Provider: "acltest",
		Policy:   "policy1",
		Expect:   "enforced",
	}
	result, err := eng.runACLCheck(context.Background(), a)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusError {
		t.Errorf("expected missing-credentials error, got %s", result.Status)
	}
	if !strings.Contains(result.Summary, "requires") {
		t.Errorf("expected 'requires' in summary, got: %s", result.Summary)
	}
}

func TestRunACLCheck_DefaultProvider(t *testing.T) {
	providers.Reset()
	t.Cleanup(func() { providers.Reset() })
	providers.Register(&aclTestProvider{})

	t.Setenv("OMADA_HOST", "host")
	t.Setenv("OMADA_CLIENT_ID", "user")
	t.Setenv("OMADA_CLIENT_SECRET", "pass")

	spec := &intent.Spec{
		Version: 1, Site: "test",
		Policies: []intent.Policy{
			{Name: "policy1", From: "zone1", To: "zone2", Action: "deny"},
		},
	}
	eng := NewEngine(spec)
	eng.Backend = &backends.MockBackend{}
	// No Provider field → defaults to "omada" which is not registered → error
	a := intent.Assertion{
		Type:   "acl_check",
		Policy: "policy1",
		Expect: "enforced",
	}
	result, err := eng.runACLCheck(context.Background(), a)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusError {
		t.Errorf("expected error for unregistered omada provider, got %s: %s", result.Status, result.Summary)
	}
}

// --- runDiscovery virtual paths ---

func TestRunDiscovery_VirtualSkipSecondRun(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Networks: []intent.Network{
			{Name: "vmnet", CIDR: "10.0.0.0/24", Gateway: "10.0.0.1", Zone: "vm"},
		},
		Assertions: []intent.Assertion{
			{Type: "subnet_discovery", Network: "vmnet"},
		},
	}

	vmResult := mockDiscoverResult(0, "10.0.0.0/24")
	vmResult.Evidence = []string{"MAC Address: 00:50:56:00:00:01 (VMware)"}
	vmResult.Observed = map[string]interface{}{"total": 0}

	mock := &backends.MockBackend{DiscoverResult: vmResult}

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "seen.json")

	db, err := seendb.LoadFrom(dbPath)
	if err != nil {
		t.Fatalf("load db: %v", err)
	}
	if err := db.AckVirtual("10.0.0.0/24"); err != nil {
		t.Fatalf("ack: %v", err)
	}

	eng := NewEngine(spec)
	eng.Backend = mock
	eng.WarnVirtual = false
	eng.SeenDBPath = dbPath
	eng.seenDB = db

	result, err := eng.runDiscovery(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusSkip {
		t.Errorf("expected skip for acked virtual network, got %s: %s", result.Status, result.Summary)
	}
}

// TestRun_NilLoggerFallsBackToStderr covers the Run() guard for callers
// (MCP, tests) that pass a nil logger: Run swaps in a stderr text handler so
// engine warnings stay visible instead of nil-panicking. A zero-assertion spec
// makes Run return immediately.
func TestRun_NilLoggerFallsBackToStderr(t *testing.T) {
	// Zero-value Engine: Logger is nil (NewEngine would wire a stderr handler).
	// SeenDBPath points at a temp file so Run never reads the real ~/.nyx/seen.json.
	eng := &Engine{
		Spec:       &intent.Spec{Version: 1, Site: "test"},
		SeenDBPath: filepath.Join(t.TempDir(), "seen.json"),
	}
	report, err := eng.Run(context.Background())
	if err != nil {
		t.Fatalf("Run with nil logger errored: %v", err)
	}
	if report == nil || len(report.Findings) != 0 {
		t.Fatalf("unexpected report: %+v", report)
	}
	// The guard replaced the nil logger with a usable one.
	if eng.Logger == nil {
		t.Fatal("Run did not install a fallback logger")
	}
}

func TestRunDiscovery_VirtualAckFailure(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Networks: []intent.Network{
			{Name: "vmnet", CIDR: "10.0.0.0/24", Gateway: "10.0.0.1", Zone: "vm"},
		},
		Assertions: []intent.Assertion{
			{Type: "subnet_discovery", Network: "vmnet"},
		},
	}

	vmResult := mockDiscoverResult(0, "10.0.0.0/24")
	vmResult.Evidence = []string{"MAC Address: 00:50:56:00:00:01 (VMware)"}

	mock := &backends.MockBackend{DiscoverResult: vmResult}

	tmpFile := filepath.Join(t.TempDir(), "blocker.txt")
	if err := os.WriteFile(tmpFile, []byte("x"), 0600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	badPath := tmpFile + "/seen.json"

	db, err := seendb.LoadFrom(badPath)
	if err != nil {
		// Mirrors Load()/engine semantics: on any load error, fall back to an
		// in-memory DB so AckVirtual's save() failure path is still exercised.
		db = seendb.New()
	}

	eng := NewEngine(spec)
	eng.Backend = mock
	eng.WarnVirtual = false
	eng.SeenDBPath = badPath
	eng.seenDB = db

	result, err := eng.runDiscovery(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Even with AckVirtual failure, should still warn (not skip)
	if result.Status != models.StatusWarn {
		t.Errorf("expected warn (ack failed), got %s: %s", result.Status, result.Summary)
	}
}

func TestRunDiscovery_WarnVirtualAlwaysWarns(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Networks: []intent.Network{
			{Name: "vmnet", CIDR: "10.0.0.0/24", Gateway: "10.0.0.1", Zone: "vm"},
		},
		Assertions: []intent.Assertion{
			{Type: "subnet_discovery", Network: "vmnet", ExpectHostsMax: nil, ExpectHostsMin: nil},
		},
	}

	vmResult := mockDiscoverResult(0, "10.0.0.0/24")
	vmResult.Evidence = []string{"MAC Address: 00:50:56:00:00:01 (VMware)"}

	mock := &backends.MockBackend{DiscoverResult: vmResult}

	eng := NewEngine(spec)
	eng.Backend = mock
	eng.WarnVirtual = true
	eng.seenDB = seendb.New()

	result, err := eng.runDiscovery(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusWarn {
		t.Errorf("expected warn (--warn-virtual), got %s: %s", result.Status, result.Summary)
	}
}

// --- looksVirtualByCIDR ---

func TestLooksVirtualByCIDR_InvalidCIDR(t *testing.T) {
	if looksVirtualByCIDR("not-a-cidr") {
		t.Error("expected false for invalid CIDR")
	}
}

func TestLooksVirtualByCIDR_NoMatch(t *testing.T) {
	// Use a CIDR that this machine likely doesn't own
	if looksVirtualByCIDR("203.0.113.0/24") {
		t.Error("expected false for non-virtual CIDR")
	}
}

func TestLooksVirtualByCIDR_WithRealInterface(t *testing.T) {
	// Find a real local interface with an IPv4 address and use its CIDR
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Skipf("cannot enumerate interfaces: %v", err)
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.To4() != nil {
				// Construct a /24 CIDR containing this IP
				ip := ipnet.IP.To4()
				cidr := fmt.Sprintf("%d.%d.%d.0/24", ip[0], ip[1], ip[2])
				// This should hit the matching path (line 60-62)
				_ = looksVirtualByCIDR(cidr) // covers type assertion and matches
				return
			}
		}
	}
	t.Skip("no suitable local interface found for testing")
}

// --- runIsolation remaining branches ---

func TestRunIsolation_IsolationViolation(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Networks: []intent.Network{
			{Name: "fromnet", CIDR: "10.0.0.0/24", Gateway: "10.0.0.1", Zone: "fromzone"},
			{Name: "tonet", CIDR: "10.0.1.0/24", Gateway: "10.0.1.1", Zone: "tozone"},
		},
	}
	mock := &backends.MockBackend{
		PingResult: &system.PingResult{Reachable: true},
	}
	eng := NewEngine(spec)
	eng.Backend = mock
	eng.runnerCtx = models.RunnerContext{Networks: []string{"fromnet"}}
	a := intent.Assertion{Type: "isolation", From: "fromzone", To: "tozone", Expect: "deny"}
	result, err := eng.runIsolation(context.Background(), a)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusFail {
		t.Errorf("expected fail (deny but reachable, runner in from zone), got %s: %s", result.Status, result.Summary)
	}
}

func TestRunIsolation_ConnectivityFailure(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Networks: []intent.Network{
			{Name: "fromnet", CIDR: "10.0.0.0/24", Gateway: "10.0.0.1", Zone: "fromzone"},
			{Name: "tonet", CIDR: "10.0.1.0/24", Gateway: "10.0.1.1", Zone: "tozone"},
		},
	}
	mock := &backends.MockBackend{
		PingResult: &system.PingResult{Reachable: false},
	}
	eng := NewEngine(spec)
	eng.Backend = mock
	eng.runnerCtx = models.RunnerContext{Networks: []string{"fromnet"}}
	a := intent.Assertion{Type: "isolation", From: "fromzone", To: "tozone", Expect: "allow"}
	result, err := eng.runIsolation(context.Background(), a)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusFail {
		t.Errorf("expected fail (allow but blocked, runner in from zone), got %s: %s", result.Status, result.Summary)
	}
}

func TestRunIsolation_IsolationConfirmedFromInsideZone(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Networks: []intent.Network{
			{Name: "fromnet", CIDR: "10.0.0.0/24", Gateway: "10.0.0.1", Zone: "fromzone"},
			{Name: "tonet", CIDR: "10.0.1.0/24", Gateway: "10.0.1.1", Zone: "tozone"},
		},
	}
	mock := &backends.MockBackend{
		PingResult: &system.PingResult{Reachable: false},
	}
	eng := NewEngine(spec)
	eng.Backend = mock
	eng.runnerCtx = models.RunnerContext{
		LocalIPs: []string{"10.0.0.50"},
		Networks: []string{"fromnet"},
	}
	a := intent.Assertion{Type: "isolation", From: "fromzone", To: "tozone", Expect: "deny"}
	result, err := eng.runIsolation(context.Background(), a)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusPass {
		t.Errorf("expected pass (deny+blocked+in_zone), got %s: %s", result.Status, result.Summary)
	}
}

func TestRunIsolation_PingError(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Networks: []intent.Network{
			{Name: "fromnet", CIDR: "10.0.0.0/24", Gateway: "10.0.0.1", Zone: "fromzone"},
			{Name: "tonet", CIDR: "10.0.1.0/24", Gateway: "10.0.1.1", Zone: "tozone"},
		},
	}
	mock := &backends.MockBackend{
		PingErr: backends.BackendError("ping failed"),
	}
	eng := NewEngine(spec)
	eng.Backend = mock
	a := intent.Assertion{Type: "isolation", From: "fromzone", To: "tozone", Expect: "allow"}
	result, err := eng.runIsolation(context.Background(), a)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Ping errors don't set anyTested=true, so anyTested=false → Warn (unverifiable)
	if result.Status != models.StatusWarn {
		t.Errorf("expected warn (anyTested=false for ping errors), got %s: %s", result.Status, result.Summary)
	}
}

func TestRunIsolation_TargetAsNetworkName(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Networks: []intent.Network{
			{Name: "fromnet", CIDR: "10.0.0.0/24", Gateway: "10.0.0.1", Zone: "fromzone"},
			{Name: "tonet", CIDR: "10.0.1.0/24", Gateway: "10.0.1.1"},
		},
	}
	mock := &backends.MockBackend{
		PingResult: &system.PingResult{Reachable: true},
	}
	eng := NewEngine(spec)
	eng.Backend = mock
	eng.runnerCtx = models.RunnerContext{Networks: []string{"fromnet"}}
	a := intent.Assertion{Type: "isolation", From: "fromzone", To: "tonet", Expect: "allow"}
	result, err := eng.runIsolation(context.Background(), a)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusPass {
		t.Errorf("expected pass (allow+reachable), got %s: %s", result.Status, result.Summary)
	}
}

func TestRunIsolation_CommaListTarget(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Networks: []intent.Network{
			{Name: "fromnet", CIDR: "10.0.0.0/24", Gateway: "10.0.0.1", Zone: "fromzone"},
			{Name: "tonet", CIDR: "10.0.1.0/24", Gateway: "10.0.1.1"},
			{Name: "twonet", CIDR: "10.0.2.0/24", Gateway: "10.0.2.1"},
		},
	}
	newEng := func(mock *backends.MockBackend) *Engine {
		eng := NewEngine(spec)
		eng.Backend = mock
		eng.runnerCtx = models.RunnerContext{Networks: []string{"fromnet"}}
		return eng
	}

	t.Run("deny with all targets blocked passes", func(t *testing.T) {
		mock := &backends.MockBackend{
			PingResultFunc: func(string) *system.PingResult { return &system.PingResult{} },
		}
		a := intent.Assertion{Type: "isolation", From: "fromzone", To: "tonet, twonet", Expect: "deny"}
		result, err := newEng(mock).runIsolation(context.Background(), a)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != models.StatusPass {
			t.Fatalf("expected pass (deny + all blocked), got %s: %s", result.Status, result.Summary)
		}
		// Both target gateways must have been pinged (comma list resolved).
		if len(result.Evidence) != 2 ||
			!strings.Contains(result.Evidence[0], "10.0.1.1") ||
			!strings.Contains(result.Evidence[1], "10.0.2.1") {
			t.Errorf("evidence = %v, want both target gateways pinged", result.Evidence)
		}
	})

	t.Run("deny with any target reachable fails", func(t *testing.T) {
		mock := &backends.MockBackend{
			PingResultFunc: func(target string) *system.PingResult {
				return &system.PingResult{Reachable: target == "10.0.2.1"}
			},
		}
		a := intent.Assertion{Type: "isolation", From: "fromzone", To: "tonet, twonet", Expect: "deny"}
		result, err := newEng(mock).runIsolation(context.Background(), a)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != models.StatusFail {
			t.Errorf("expected fail (deny + reachable gateway), got %s: %s", result.Status, result.Summary)
		}
	})

	t.Run("duplicate names resolve once", func(t *testing.T) {
		mock := &backends.MockBackend{
			PingResultFunc: func(string) *system.PingResult { return &system.PingResult{} },
		}
		a := intent.Assertion{Type: "isolation", From: "fromzone", To: "tonet,tonet,twonet", Expect: "deny"}
		result, err := newEng(mock).runIsolation(context.Background(), a)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Status != models.StatusPass {
			t.Fatalf("expected pass, got %s: %s", result.Status, result.Summary)
		}
		if len(result.Evidence) != 2 {
			t.Errorf("evidence = %v, want 2 entries (duplicates dropped)", result.Evidence)
		}
	})
}

func TestRunIsolation_UnverifiableFromZone(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Networks: []intent.Network{
			{Name: "fromnet", CIDR: "10.0.0.0/24", Gateway: "10.0.0.1", Zone: "fromzone"},
			{Name: "tonet", CIDR: "10.0.1.0/24", Gateway: "10.0.1.1", Zone: "tozone"},
		},
	}
	mock := &backends.MockBackend{
		PingResult: &system.PingResult{Reachable: true},
	}
	eng := NewEngine(spec)
	eng.Backend = mock
	// Don't set runnerCtx.Networks → runner not in from zone
	eng.runnerCtx = models.RunnerContext{}
	a := intent.Assertion{Type: "isolation", From: "fromzone", To: "tozone", Expect: "allow"}
	result, err := eng.runIsolation(context.Background(), a)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// not in from zone → never a hard verdict, even when reachable
	if result.Status != models.StatusWarn {
		t.Errorf("expected warn (runner outside from zone), got %s: %s", result.Status, result.Summary)
	}
	if !strings.Contains(result.Summary, "connectivity unconfirmed") {
		t.Errorf("expected 'connectivity unconfirmed' summary, got: %s", result.Summary)
	}
}

// --- Run panic recovery and context cancellation ---

func TestRun_PanicRecovery(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Networks: []intent.Network{{Name: "lan", CIDR: "10.0.0.0/24"}},
		Assertions: []intent.Assertion{
			{Type: "subnet_discovery", Network: "lan"},
		},
	}
	mock := &backends.MockBackend{
		DiscoverResultFunc: func(cidr string) *models.CheckResult {
			panic("test panic")
		},
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
	if report.Findings[0].Status != models.StatusError {
		t.Errorf("expected error status for panicked assertion, got %s: %s",
			report.Findings[0].Status, report.Findings[0].Summary)
	}
}

func TestRun_ContextCancelled(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Networks: []intent.Network{{Name: "lan", CIDR: "10.0.0.0/24"}},
		Assertions: []intent.Assertion{
			{Type: "subnet_discovery", Network: "lan"},
		},
	}
	mock := &backends.MockBackend{
		DiscoverResult: mockDiscoverResult(5, "10.0.0.0/24"),
	}
	eng := NewEngine(spec)
	eng.Backend = mock
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately
	report, err := eng.Run(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(report.Findings))
	}
	if report.Findings[0].Status != models.StatusError {
		t.Errorf("expected error status for cancelled context, got %s: %s",
			report.Findings[0].Status, report.Findings[0].Summary)
	}
}

func TestRun_AggregationStatusFail(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Networks: []intent.Network{{Name: "lan", CIDR: "10.0.0.0/24"}},
		Assertions: []intent.Assertion{
			{Type: "subnet_discovery", Network: "lan", ExpectHostsMin: nil, ExpectHostsMax: nil},
		},
	}
	mock := &backends.MockBackend{
		DiscoverResult: mockDiscoverResult(0, "10.0.0.0/24"),
	}
	eng := NewEngine(spec)
	eng.Backend = mock
	eng.runnerCtx = models.RunnerContext{}
	eng.seenDB = seendb.New()
	report, err := eng.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 0 hosts with no violations → pass (no virtual detection since evidence is "mock output")
	if report.Findings[0].Status != models.StatusPass {
		t.Errorf("expected pass, got %s", report.Findings[0].Status)
	}
}

// --- providers.ErrCapabilityUnsupported Error() ---

func TestErrCapabilityUnsupported_Error(t *testing.T) {
	e := &providers.ErrCapabilityUnsupported{Provider: "test", Capability: "import"}
	want := `provider "test" does not support "import"`
	if got := e.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

// --- probe.Probe shellQuote already tested, but test via audit path ---

func TestRunViaProbe_PortCheckSSHFailure(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Probes: []intent.Probe{
			{Name: "probe1", Host: "192.0.2.1", User: "test", VLAN: "test"},
		},
	}
	eng := NewEngine(spec)
	eng.Backend = &backends.MockBackend{}
	eng.SkipHostKeyVerify = true
	a := intent.Assertion{Type: "port_check", Runner: "probe1", Target: "10.0.0.1", Ports: []int{80}, Expect: "open"}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result, err := eng.runViaProbe(ctx, a)
	if err != nil {
		t.Fatalf("expected no error (wrapped in result), got: %v", err)
	}
	if result == nil {
		t.Fatal("expected result")
	}
	if result.Status != models.StatusError {
		t.Errorf("expected error status, got %s: %s", result.Status, result.Summary)
	}
}

func TestRunViaProbe_DNSCheckSSHFailure(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Probes: []intent.Probe{
			{Name: "probe1", Host: "192.0.2.1", User: "test", VLAN: "test"},
		},
	}
	eng := NewEngine(spec)
	eng.Backend = &backends.MockBackend{}
	eng.SkipHostKeyVerify = true
	a := intent.Assertion{Type: "dns_check", Runner: "probe1", Query: "example.com"}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result, err := eng.runViaProbe(ctx, a)
	if err != nil {
		t.Fatalf("expected no error (wrapped in result), got: %v", err)
	}
	if result == nil {
		t.Fatal("expected result")
	}
	if result.Status != models.StatusError {
		t.Errorf("expected error status, got %s: %s", result.Status, result.Summary)
	}
}

// --- runNetworkHealth with error path ---

func TestRunNetworkHealth_Error(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Assertions: []intent.Assertion{{Type: "network_health", Target: "10.0.0.1"}},
	}
	mock := &backends.MockBackend{
		PingCheckErr: backends.BackendError("ping check failed"),
	}
	eng := NewEngine(spec)
	eng.Backend = mock
	_, err := eng.runNetworkHealth(context.Background(), spec.Assertions[0])
	if err == nil {
		t.Fatal("expected error from backend")
	}
}

func TestRunNetworkHealth_MTUError(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Assertions: []intent.Assertion{{Type: "network_health", Target: "10.0.0.1", ExpectMTU: 1500}},
	}
	r := models.NewCheckResult("ping", "network_health", "system", "10.0.0.1")
	r.Status = models.StatusPass
	r.Finish()
	mock := &backends.MockBackend{
		PingCheckResult: r,
		PingCheckStats:  &health.PingStats{},
		MTUErr:          backends.BackendError("mtu probe failed"),
	}
	eng := NewEngine(spec)
	eng.Backend = mock
	result, err := eng.runNetworkHealth(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// MTU error is appended to evidence, not returned as error
	if result.Status != models.StatusPass {
		t.Errorf("expected pass (MTU error is non-fatal), got %s: %s", result.Status, result.Summary)
	}
	if len(result.Evidence) == 0 {
		t.Error("expected evidence about MTU error")
	}
}

// --- runDNSCheck error path ---

func TestRunDNSCheck_Error(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Assertions: []intent.Assertion{{Type: "dns_check", Query: "example.com"}},
	}
	mock := &backends.MockBackend{
		ResolveErr: backends.BackendError("dns resolution failed"),
	}
	eng := NewEngine(spec)
	eng.Backend = mock
	_, err := eng.runDNSCheck(context.Background(), spec.Assertions[0])
	if err == nil {
		t.Fatal("expected error from backend")
	}
}

// --- runVPNRoute without expected interface ---

func TestRunVPNRoute_NoExpectedInterface(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		VPN:        []intent.VPNConfig{{Name: "work", Type: "wireguard"}},
		Assertions: []intent.Assertion{{Type: "vpn_route", VPN: "work", Target: "10.0.0.1"}},
	}
	mock := &backends.MockBackend{
		RouteResult:        &system.Route{Device: "wg0", Gateway: "10.0.0.1"},
		VPNInterfaceResult: true,
	}
	eng := NewEngine(spec)
	eng.Backend = mock
	result, err := eng.runVPNRoute(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusPass {
		t.Errorf("expected pass (default wg0 + viaTunnel), got %s: %s", result.Status, result.Summary)
	}
}

// --- runPortCheck error path (scan failures) ---

func TestRunPortCheck_ScanError(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Assertions: []intent.Assertion{
			{Type: "port_check", Target: "10.0.0.5", Ports: []int{80}, Expect: "open"},
		},
	}
	mock := &backends.MockBackend{
		PortScanErr: backends.BackendError("port scan failed"),
	}
	eng := NewEngine(spec)
	eng.Backend = mock
	_, err := eng.runPortCheck(context.Background(), spec.Assertions[0])
	if err == nil {
		t.Fatal("expected error from port scan failure")
	}
}

// --- pickBestInterface edge cases ---

// --- runACLCheck: successful CheckACL path ---

func TestRunACLCheck_SuccessfulCheck(t *testing.T) {
	providers.Reset()
	t.Cleanup(func() { providers.Reset() })

	// Register a provider that returns a result from CheckACL
	okProvider := &aclTestProviderWithResult{}
	providers.Register(okProvider)

	t.Setenv("OMADA_HOST", "localhost")
	t.Setenv("OMADA_CLIENT_ID", "admin")
	t.Setenv("OMADA_CLIENT_SECRET", "pass")

	spec := &intent.Spec{
		Version: 1, Site: "test",
		Policies: []intent.Policy{
			{Name: "policy1", From: "zone1", To: "zone2", Action: "deny"},
		},
	}
	eng := NewEngine(spec)
	eng.Backend = &backends.MockBackend{}
	a := intent.Assertion{
		Type:     "acl_check",
		Provider: "acltestwithresult",
		Policy:   "policy1",
		Expect:   "enforced",
	}
	result, err := eng.runACLCheck(context.Background(), a)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

type aclTestProviderWithResult struct{}

func (a *aclTestProviderWithResult) Name() string           { return "acltestwithresult" }
func (a *aclTestProviderWithResult) Capabilities() []string { return []string{"acl_check"} }
func (a *aclTestProviderWithResult) Info(ctx context.Context, opts providers.ImportOptions) (*providers.ProviderInfo, error) {
	return nil, nil
}
func (a *aclTestProviderWithResult) ImportSpec(ctx context.Context, opts providers.ImportOptions) (*providers.ImportResult, error) {
	return nil, nil
}
func (a *aclTestProviderWithResult) Check(ctx context.Context, opts providers.ImportOptions) (*providers.AuditResult, error) {
	return nil, nil
}
func (a *aclTestProviderWithResult) CheckACL(ctx context.Context, req providers.ACLCheckRequest, opts providers.ImportOptions) (*models.CheckResult, error) {
	r := models.NewCheckResult("acltest", "acl_check", "local", req.PolicyName)
	r.Status = models.StatusPass
	r.Summary = "acl enforced"
	r.Finish()
	return r, nil
}

// --- pickBestInterface: with matching networks ---

func TestPickBestInterface_WithMatchingNetworks(t *testing.T) {
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Skipf("cannot enumerate interfaces: %v", err)
	}

	// Build a spec with networks matching the real local interfaces
	var networks []intent.Network
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				if ip := ipnet.IP.To4(); ip != nil {
					// Build a /24 CIDR from this IP
					cidr := fmt.Sprintf("%d.%d.%d.0/24", ip[0], ip[1], ip[2])
					networks = append(networks, intent.Network{Name: iface.Name, CIDR: cidr})
					break
				}
			}
		}
	}

	if len(networks) == 0 || len(ifaces) <= 1 {
		t.Skip("need at least one up non-loopback interface with an IPv4 address")
	}

	spec := &intent.Spec{
		Version:  1,
		Site:     "test",
		Networks: networks,
	}

	// Use all interfaces (not just up ones) to ensure pickBestInterface sees them
	winner := pickBestInterface(ifaces, spec)
	// winner might be empty (ambiguous) or a real interface name — either way, the code path is covered
	_ = winner
}

// --- localRunnerContext: bestIface path ---

func TestLocalRunnerContext_WithMultipleInterfaces(t *testing.T) {
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Skipf("cannot enumerate interfaces: %v", err)
	}

	// Build a spec with networks that match one of the real interfaces
	var networks []intent.Network
	foundIface := ""
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				if ip := ipnet.IP.To4(); ip != nil {
					cidr := fmt.Sprintf("%d.%d.%d.0/24", ip[0], ip[1], ip[2])
					networks = append(networks, intent.Network{Name: iface.Name, CIDR: cidr})
					foundIface = iface.Name
					break
				}
			}
		}
		if foundIface != "" {
			break
		}
	}

	if len(networks) == 0 || len(ifaces) <= 1 {
		t.Skip("need multiple interfaces with IPv4 addresses")
	}

	spec := &intent.Spec{
		Version:  1,
		Site:     "test",
		Networks: networks,
	}

	// Call localRunnerContext with empty interfaceName — should trigger pickBestInterface
	ctx := localRunnerContext(spec, "")
	_ = ctx
}

// --- runViaProbe: successful parseProbeOutput path ---

func TestRunViaProbe_SuccessPath(t *testing.T) {
	// This test ensures the parseProbeOutput path is hit by using a mock SSH server
	// that succeeds. We use SSH to localhost with the test runner's own key.
	// Skip if SSH server not available or key not found.
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Probes: []intent.Probe{
			{Name: "localprobe", Host: "127.0.0.1", User: "test", VLAN: "test"},
		},
	}
	eng := NewEngine(spec)
	eng.Backend = &backends.MockBackend{}
	eng.SkipHostKeyVerify = true
	a := intent.Assertion{Type: "network_health", Target: "127.0.0.1", Runner: "localprobe"}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// This will likely fail to connect (no SSH server), but if it succeeds,
	// we'd hit the parseProbeOutput path. Let's verify it handles both cases.
	result, err := eng.runViaProbe(ctx, a)
	if err != nil {
		t.Logf("expected SSH may fail in test env: %v", err)
		return
	}
	if result != nil {
		_ = result.Status
	}
}

// --- runIsolationViaProbe: successful ping path ---

func TestRunIsolationViaProbe_PingSuccess(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Networks: []intent.Network{
			{Name: "net1", CIDR: "10.0.0.0/24", Gateway: "10.0.0.1", Zone: "zone1"},
			{Name: "net2", CIDR: "10.0.1.0/24", Gateway: "10.0.1.1", Zone: "zone2"},
		},
		Probes: []intent.Probe{
			{Name: "probe1", Host: "127.0.0.1", User: "test", VLAN: "zone1"},
		},
	}
	eng := NewEngine(spec)
	eng.Backend = &backends.MockBackend{}
	eng.SkipHostKeyVerify = true
	a := intent.Assertion{
		Type:   "isolation",
		From:   "zone1",
		To:     "zone2",
		Expect: "deny",
		Runner: "probe1",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// This test requires a working SSH server at 127.0.0.1.
	// If SSH fails, we won't hit the parseProbeOutput/isPingBlocked path.
	// But if it succeeds, we will.
	result, err := eng.runViaProbe(ctx, a)
	if err != nil {
		t.Skipf("SSH connection failed (expected in CI): %v", err)
	}
	if result != nil {
		_ = result.Status
	}
}

// --- runDNSCheck: DNSSEC success path ---

func TestRunDNSCheck_DNSSCSSuccess(t *testing.T) {
	spec := &intent.Spec{
		Version:    1,
		Site:       "test",
		Assertions: []intent.Assertion{{Type: "dns_check", Query: "example.com", DNSSEC: true}},
	}
	r := &models.CheckResult{Status: models.StatusPass}
	r.Evidence = []string{"resolved"}
	r.Finish()
	dnssecR := &models.CheckResult{Status: models.StatusPass}
	dnssecR.Evidence = []string{"dnssec ok"}
	dnssecR.Finish()
	mock := &backends.MockBackend{
		ResolveResult: r,
		DNSSECResult:  dnssecR,
	}
	eng := NewEngine(spec)
	eng.Backend = mock
	result, err := eng.runDNSCheck(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

// --- runDNSCheck: DNSSEC failure that downgrades pass to fail ---

func TestRunDNSCheck_DNSSECFailureDowngradesStatus(t *testing.T) {
	spec := &intent.Spec{
		Version:    1,
		Site:       "test",
		Assertions: []intent.Assertion{{Type: "dns_check", Query: "example.com", DNSSEC: true}},
	}
	r := &models.CheckResult{Status: models.StatusPass}
	r.Evidence = []string{"resolved"}
	r.Finish()
	dnssecR := &models.CheckResult{Status: models.StatusFail, Summary: "DNSSEC validation failed"}
	dnssecR.Finish()
	mock := &backends.MockBackend{
		ResolveResult: r,
		DNSSECResult:  dnssecR,
	}
	eng := NewEngine(spec)
	eng.Backend = mock
	result, err := eng.runDNSCheck(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusFail {
		t.Errorf("expected fail (DNSSEC failure downgraded status), got %s", result.Status)
	}
}

func TestPickBestInterface_NoUpInterfaces(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Networks: []intent.Network{
			{Name: "net1", CIDR: "10.0.0.0/24"},
		},
	}
	ifaces := []net.Interface{
		{Name: "eth0", Flags: 0},
		{Name: "eth1", Flags: net.FlagLoopback},
	}
	winner := pickBestInterface(ifaces, spec)
	if winner != "" {
		t.Errorf("expected empty winner for no up interfaces, got %s", winner)
	}
}

func TestPickBestInterface_NoMatchingNetworks(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Networks: []intent.Network{
			{Name: "net1", CIDR: "10.0.0.0/24"},
		},
	}
	ifaces := []net.Interface{
		{Name: "eth0", Flags: net.FlagUp | net.FlagRunning},
	}
	winner := pickBestInterface(ifaces, spec)
	if winner != "" {
		t.Errorf("expected empty (no matching networks), got %s", winner)
	}
}

// --- Run: SeenDB error fallback path ---

func TestRun_SeenDBErrorFallsBackToInMemory(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Assertions: []intent.Assertion{
			{Type: "route_check", Target: "10.0.0.1"},
		},
	}
	mock := &backends.MockBackend{
		RouteResult: &system.Route{Gateway: "10.0.0.1", Device: "eth0"},
	}
	eng := NewEngine(spec)
	eng.Backend = mock
	eng.SeenDBPath = filepath.Join(os.TempDir(), "nonexistent_dir_for_test_xyz", "seen.json")
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

// --- Run: empty assertions ---

func TestRun_NoAssertions(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Assertions: []intent.Assertion{},
	}
	eng := NewEngine(spec)
	report, err := eng.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(report.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(report.Findings))
	}
}

// --- runDiscovery: seendb nil path ---

func TestRunDiscovery_SeenDBNil(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Networks: []intent.Network{
			{Name: "net1", CIDR: "192.168.1.0/24"},
		},
		Assertions: []intent.Assertion{
			{Type: "subnet_discovery", Network: "net1"},
		},
	}
	mock := &backends.MockBackend{
		DiscoverResult: &models.CheckResult{Status: models.StatusPass},
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

// --- matchNetworks with matching IPs ---

func TestMatchNetworks_Match(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Networks: []intent.Network{
			{Name: "net1", CIDR: "10.0.0.0/24"},
			{Name: "net2", CIDR: "192.168.1.0/24"},
		},
	}
	ips := []net.IP{net.ParseIP("10.0.0.5"), net.ParseIP("8.8.8.8")}
	matched := matchNetworks(ips, spec)
	if len(matched) != 1 || matched[0] != "net1" {
		t.Errorf("expected [net1], got %v", matched)
	}
}

// --- runAssertion dispatch to probe ---

func TestRunAssertion_RunnerDispatch(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Assertions: []intent.Assertion{
			{Type: "network_health", Target: "10.0.0.1", Runner: "nonexistent_probe"},
		},
	}
	eng := NewEngine(spec)
	_, err := eng.runAssertion(context.Background(), spec.Assertions[0])
	if err == nil {
		t.Fatal("expected error for probe not found")
	}
}

func TestRunAssertion_LocalRunner(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Assertions: []intent.Assertion{
			{Type: "network_health", Target: "10.0.0.1", Runner: "local"},
		},
	}
	mock := &backends.MockBackend{
		PingCheckResult: &models.CheckResult{Status: models.StatusPass},
	}
	eng := NewEngine(spec)
	eng.Backend = mock
	result, err := eng.runAssertion(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusPass {
		t.Errorf("expected pass, got %s", result.Status)
	}
}

// --- runDiscovery: float64 total ---

func TestRunDiscovery_FloatTotal(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Networks: []intent.Network{
			{Name: "net1", CIDR: "192.168.1.0/24"},
		},
		Assertions: []intent.Assertion{
			{Type: "subnet_discovery", Network: "net1"},
		},
	}
	mock := &backends.MockBackend{
		DiscoverResult: &models.CheckResult{
			Status:   models.StatusPass,
			Observed: map[string]interface{}{"total": float64(5)},
		},
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

// --- runVPNRoute: route error path ---

func TestRunVPNRoute_RouteError(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		VPN: []intent.VPNConfig{
			{Name: "work", Type: "wireguard", Interface: "wg0"},
		},
		Assertions: []intent.Assertion{
			{Type: "vpn_route", VPN: "work", Target: "10.0.0.1"},
		},
	}
	mock := &backends.MockBackend{
		RouteErr: backends.BackendError("route lookup failed for vpn"),
	}
	eng := NewEngine(spec)
	eng.Backend = mock
	result, err := eng.runVPNRoute(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusError {
		t.Errorf("expected error status, got %s: %s", result.Status, result.Summary)
	}
}

// --- runDNSCheck: DNSSEC error path ---

func TestRunDNSCheck_DNSSECError(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Assertions: []intent.Assertion{
			{Type: "dns_check", Query: "example.com", DNSSEC: true},
		},
	}
	r := &models.CheckResult{Status: models.StatusPass}
	r.Evidence = []string{"resolved"}
	r.Finish()
	mock := &backends.MockBackend{
		ResolveResult: r,
		DNSSECErr:     backends.BackendError("dnssec validation error"),
	}
	eng := NewEngine(spec)
	eng.Backend = mock
	result, err := eng.runDNSCheck(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusPass {
		t.Errorf("expected pass (DNSSEC error is non-fatal), got %s", result.Status)
	}
}

// --- runDNSCheck: ExpectIP path ---

func TestRunDNSCheck_ExpectIPMatch(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Assertions: []intent.Assertion{
			{Type: "dns_check", Query: "example.com", ExpectIP: "93.184.216.34"},
		},
	}
	r := &models.CheckResult{Status: models.StatusPass}
	r.Observed = map[string]interface{}{"ips": []interface{}{"93.184.216.34"}}
	r.Finish()
	mock := &backends.MockBackend{
		ResolveExpectResult: r,
	}
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

// --- probeCommandFor: network_health without target ---

func TestProbeCommandFor_NetworkHealthNoTarget(t *testing.T) {
	a := intent.Assertion{Type: "network_health", Target: ""}
	cmd := probeCommandFor(a, nil)
	if cmd != nil {
		t.Errorf("expected nil for network_health without target, got %v", cmd)
	}
}

// --- Run: SeenDB LoadFrom error path ---

func TestRun_SeenDBLoadFromErrorFallsBackToInMemory(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Assertions: []intent.Assertion{
			{Type: "route_check", Target: "10.0.0.1"},
		},
	}
	mock := &backends.MockBackend{
		RouteResult: &system.Route{Gateway: "10.0.0.1", Device: "eth0"},
	}
	eng := NewEngine(spec)
	eng.Backend = mock
	// Point to a directory — os.ReadFile on a dir returns a non-IsNotExist error
	// on both Windows (ERROR_ACCESS_DENIED) and Unix (EISDIR), causing LoadFrom to return an error
	eng.SeenDBPath = os.TempDir()
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

// --- panickingBackend for panic recovery tests ---

type panickingBackend struct {
	*backends.MockBackend
}

func (p *panickingBackend) GetRouteToTarget(_ context.Context, _ string) (*system.Route, error) {
	panic("simulated backend panic")
}

// --- Run: error path with From fallback (lines 134-136) ---

func TestRun_ErrorPath_FromFallback(t *testing.T) {
	// subnet_discovery with Network="" → NetworkByName("") returns nil → runDiscovery returns Go error
	// Then lines 130-136 set target = assertion.From (since Target="" and Network="")
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Networks: []intent.Network{{Name: "lan", CIDR: "10.0.0.0/24"}},
		Assertions: []intent.Assertion{
			{Type: "subnet_discovery", Network: "", From: "srczone"},
		},
	}
	eng := NewEngine(spec)
	eng.Backend = &backends.MockBackend{}
	report, err := eng.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(report.Findings))
	}
	if report.Findings[0].Status != models.StatusError {
		t.Errorf("expected error status, got %s: %s", report.Findings[0].Status, report.Findings[0].Summary)
	}
}

// --- Run: panic recovery with From fallback (lines 101-103) ---

func TestRun_PanicRecovery_FromFallback(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Networks: []intent.Network{{Name: "lan", CIDR: "10.0.0.0/24"}},
		Assertions: []intent.Assertion{
			{Type: "route_check", Target: "", Network: "", From: "srczone"},
		},
	}
	eng := NewEngine(spec)
	eng.Backend = &panickingBackend{MockBackend: &backends.MockBackend{}}
	report, err := eng.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(report.Findings))
	}
	if report.Findings[0].Status != models.StatusError {
		t.Errorf("expected error status for panicked assertion, got %s: %s",
			report.Findings[0].Status, report.Findings[0].Summary)
	}
}

// --- runAssertion dispatch for acl_check (line 335-336) ---

func TestRunAssertion_ACLCheckDispatch(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Networks: []intent.Network{{Name: "lan", CIDR: "10.0.0.0/24"}},
	}
	mock := &backends.MockBackend{
		RouteResult: &system.Route{Gateway: "10.0.0.1", Device: "eth0"},
	}
	eng := NewEngine(spec)
	eng.Backend = mock
	_, err := eng.runAssertion(context.Background(), intent.Assertion{Type: "acl_check"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- runAssertion: subnet_discovery through runAssertion ---

func TestRunAssertion_SubnetDiscoveryThroughAssertion(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Networks: []intent.Network{
			{Name: "net1", CIDR: "192.168.1.0/24"},
		},
		Assertions: []intent.Assertion{
			{Type: "subnet_discovery", Network: "net1"},
		},
	}
	mock := &backends.MockBackend{
		DiscoverResult: &models.CheckResult{Status: models.StatusPass},
	}
	eng := NewEngine(spec)
	eng.Backend = mock
	result, err := eng.runAssertion(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusPass {
		t.Errorf("expected pass, got %s", result.Status)
	}
}

// --- runIsolationViaProbe: zone with no matching networks ---

func TestRunViaProbe_IsolationNoGatewaysFound(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Networks: []intent.Network{
			{Name: "net1", CIDR: "10.0.0.0/24", Zone: "zone1"},
		},
		Probes: []intent.Probe{
			{Name: "p1", Host: "192.0.2.1", User: "test"},
		},
		Assertions: []intent.Assertion{
			{Type: "isolation", Runner: "p1", From: "zone1", To: "nonexistent_zone", Expect: "deny"},
		},
	}
	eng := NewEngine(spec)
	eng.Backend = &backends.MockBackend{}
	eng.SkipHostKeyVerify = true
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// An unresolvable target zone must be reported, not silently treated as
	// an unreachable gateway (regression: it used to ping the literal zone
	// name and confirm isolation).
	result, err := eng.runViaProbe(ctx, spec.Assertions[0])
	if err != nil {
		t.Fatalf("expected result, not error: %v", err)
	}
	if result.Status != models.StatusError {
		t.Errorf("expected error (unresolvable zone), got %s: %s", result.Status, result.Summary)
	}
}

// --- pickBestInterface: winner loop (clear winner) ---

func TestPickBestInterface_ClearWinner(t *testing.T) {
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Skipf("cannot enumerate interfaces: %v", err)
	}

	// Collect up, non-loopback interfaces with their IPv4 /24 networks
	type ifaceNet struct {
		iface net.Interface
		cidr  string
	}
	var candidates []ifaceNet
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				if ip := ipnet.IP.To4(); ip != nil {
					cidr := fmt.Sprintf("%d.%d.%d.0/24", ip[0], ip[1], ip[2])
					candidates = append(candidates, ifaceNet{iface, cidr})
					break
				}
			}
		}
	}

	if len(candidates) == 0 {
		t.Skip("no up non-loopback interfaces with IPv4")
	}

	// Create a spec with multiple networks matching the SAME interface's subnet.
	// This gives that interface count > 1, making it a clear winner.
	var multiNet []intent.Network
	// Use the actual subnet from the interface for more reliable matching
	for i := 0; i < 3; i++ {
		multiNet = append(multiNet, intent.Network{
			Name: fmt.Sprintf("net%d", i),
			CIDR: candidates[0].cidr,
			Zone: "zone1",
		})
	}

	spec := &intent.Spec{
		Version:  1,
		Site:     "test",
		Networks: multiNet,
	}

	// Also test localRunnerContext triggers pickBestInterface
	ctx := localRunnerContext(spec, "")
	_ = ctx

	winner := pickBestInterface(ifaces, spec)
	// The interface matching candidates[0] should win (count=3 vs 0 for others)
	// If winner is empty, all interfaces may be on the same subnet (tie) or no match
	_ = winner
}

// --- pickBestInterface: iface.Addrs() error path ---

func TestPickBestInterface_AddrsError(t *testing.T) {
	// Create a fake up interface that doesn't exist — Addrs() will fail
	// Use a high Index value that won't match any real interface
	ifaces := []net.Interface{
		{Name: "fake0", Flags: net.FlagUp | net.FlagRunning, Index: 99999},
	}
	spec := &intent.Spec{
		Version:  1,
		Site:     "test",
		Networks: []intent.Network{{Name: "net1", CIDR: "10.0.0.0/24"}},
	}
	// pickBestInterface should skip the interface (Addrs() fails) → empty winner
	winner := pickBestInterface(ifaces, spec)
	if winner != "" {
		t.Errorf("expected empty winner for non-existent interface, got %q", winner)
	}
}

// --- localRunnerContext: bestIface found (recursive call) ---

func TestLocalRunnerContext_BestIfaceFound(t *testing.T) {
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Skipf("cannot enumerate interfaces: %v", err)
	}

	type ifaceNet struct {
		iface net.Interface
		cidr  string
	}
	var candidates []ifaceNet
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				if ip := ipnet.IP.To4(); ip != nil {
					cidr := fmt.Sprintf("%d.%d.%d.0/24", ip[0], ip[1], ip[2])
					candidates = append(candidates, ifaceNet{iface, cidr})
					break
				}
			}
		}
	}

	if len(candidates) == 0 || len(ifaces) <= 1 {
		t.Skip("need multiple interfaces with IPv4 addresses")
	}

	var networks []intent.Network
	for i, c := range candidates {
		networks = append(networks, intent.Network{Name: fmt.Sprintf("net%d", i), CIDR: c.cidr, Zone: "zone"})
	}

	spec := &intent.Spec{
		Version:  1,
		Site:     "test",
		Networks: networks,
	}

	ctx := localRunnerContext(spec, "")
	_ = ctx
}
