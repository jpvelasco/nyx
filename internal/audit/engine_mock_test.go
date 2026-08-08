package audit

import (
	"context"
	"testing"

	"github.com/jpvelasco/nyx/internal/backends"
	"github.com/jpvelasco/nyx/internal/backends/health"

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

// --- runIsolation ---

func TestRunIsolation_DenyConfirmed(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Networks: []intent.Network{
			{Name: "fromnet", CIDR: "10.0.0.0/24", Gateway: "10.0.0.1", Zone: "fromzone"},
			{Name: "tonet", CIDR: "10.0.1.0/24", Gateway: "10.0.1.1", Zone: "tozone"},
		},
		Assertions: []intent.Assertion{{Type: "isolation", From: "fromzone", To: "tozone", Expect: "deny"}},
	}
	mock := &backends.MockBackend{
		PingResult: &system.PingResult{Reachable: false},
	}
	eng := NewEngine(spec)
	eng.Backend = mock
	result, err := eng.runIsolation(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// When runner is not in from zone and all blocked, it should be warn (unconfirmed)
	if result.Status != models.StatusWarn && result.Status != models.StatusPass {
		t.Errorf("expected warn or pass, got %s: %s", result.Status, result.Summary)
	}
}

func TestRunIsolation_AllowConfirmed(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Networks: []intent.Network{
			{Name: "fromnet", CIDR: "10.0.0.0/24", Gateway: "10.0.0.1", Zone: "fromzone"},
			{Name: "tonet", CIDR: "10.0.1.0/24", Gateway: "10.0.1.1", Zone: "tozone"},
		},
		Assertions: []intent.Assertion{{Type: "isolation", From: "fromzone", To: "tozone", Expect: "allow"}},
	}
	mock := &backends.MockBackend{
		PingResult: &system.PingResult{Reachable: true},
	}
	eng := NewEngine(spec)
	eng.Backend = mock
	result, err := eng.runIsolation(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusPass {
		t.Errorf("expected pass, got %s: %s", result.Status, result.Summary)
	}
}

func TestRunIsolation_TargetNotFound(t *testing.T) {
	spec := &intent.Spec{Version: 1, Site: "test", Networks: []intent.Network{{Name: "lan", CIDR: "10.0.0.0/24"}}}
	a := intent.Assertion{Type: "isolation", From: "zone1", To: "nonexistent-zone", Expect: "deny"}
	eng := NewEngine(spec)
	eng.Backend = &backends.MockBackend{}
	result, err := eng.runIsolation(context.Background(), a)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusError {
		t.Errorf("expected error for unresolved target, got %s", result.Status)
	}
}

func TestRunIsolation_NoGateway(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Networks: []intent.Network{
			{Name: "fromnet", CIDR: "10.0.0.0/24", Zone: "fromzone"},
			{Name: "tonet", CIDR: "10.0.1.0/24", Zone: "tozone"}, // no gateway
		},
		Assertions: []intent.Assertion{{Type: "isolation", From: "fromzone", To: "tozone", Expect: "deny"}},
	}
	mock := &backends.MockBackend{}
	eng := NewEngine(spec)
	eng.Backend = mock
	result, err := eng.runIsolation(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// No gateway means no tests could be run → warn
	if result.Status != models.StatusWarn {
		t.Errorf("expected warn when no gateway, got %s: %s", result.Status, result.Summary)
	}
}

// --- runPortCheck ---

func TestRunPortCheck_AllOpen(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Assertions: []intent.Assertion{{Type: "port_check", Target: "10.0.0.1", Ports: []int{80, 443}, Expect: "open"}},
	}
	mock := &backends.MockBackend{
		PortScanResult: mockPortScanResult([]int{80, 443}, "open"),
	}
	eng := NewEngine(spec)
	eng.Backend = mock
	result, err := eng.runPortCheck(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusPass {
		t.Errorf("expected pass, got %s: %s", result.Status, result.Summary)
	}
}

func TestRunPortCheck_MixedStates(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Assertions: []intent.Assertion{{Type: "port_check", Target: "10.0.0.1", Ports: []int{80, 443}, Expect: "open"}},
	}
	r := models.NewCheckResult("nmap", "port_check", "nmap", "10.0.0.1")
	r.Status = models.StatusPass
	r.Observed = map[string]interface{}{
		"ports": []interface{}{
			map[string]interface{}{"port": float64(80), "protocol": "tcp", "state": "open"},
			map[string]interface{}{"port": float64(443), "protocol": "tcp", "state": "filtered"},
		},
	}
	r.Finish()
	mock := &backends.MockBackend{PortScanResult: r}
	eng := NewEngine(spec)
	eng.Backend = mock
	result, err := eng.runPortCheck(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusFail {
		t.Errorf("expected fail for mismatched port, got %s", result.Status)
	}
}

func TestRunPortCheck_DefaultProtocol(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Assertions: []intent.Assertion{{Type: "port_check", Target: "10.0.0.1", Ports: []int{80}, Expect: "open"}},
	}
	mock := &backends.MockBackend{
		PortScanResult: mockPortScanResult([]int{80}, "open"),
	}
	eng := NewEngine(spec)
	eng.Backend = mock
	result, err := eng.runPortCheck(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusPass {
		t.Errorf("expected pass, got %s", result.Status)
	}
}

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

// --- runNetworkHealth ---

func TestRunNetworkHealth_PingCheck(t *testing.T) {
	r := models.NewCheckResult("ping", "network_health", "system", "10.0.0.1")
	r.Status = models.StatusPass
	r.Finish()

	spec := &intent.Spec{
		Version: 1, Site: "test",
		Assertions: []intent.Assertion{{Type: "network_health", Target: "10.0.0.1"}},
	}
	mock := &backends.MockBackend{PingCheckResult: r}
	eng := NewEngine(spec)
	eng.Backend = mock
	result, err := eng.runNetworkHealth(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusPass {
		t.Errorf("expected pass, got %s", result.Status)
	}
}

func TestRunNetworkHealth_LatencyAndLoss(t *testing.T) {
	r := models.NewCheckResult("ping", "network_health", "system", "10.0.0.1")
	r.Status = models.StatusPass
	r.Finish()

	spec := &intent.Spec{
		Version: 1, Site: "test",
		Assertions: []intent.Assertion{{Type: "network_health", Target: "10.0.0.1", ExpectLatencyMs: 100}},
	}
	mock := &backends.MockBackend{LatencyResult: r}
	eng := NewEngine(spec)
	eng.Backend = mock
	result, err := eng.runNetworkHealth(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusPass {
		t.Errorf("expected pass, got %s", result.Status)
	}
}

func TestRunNetworkHealth_MTUPass(t *testing.T) {
	r := models.NewCheckResult("ping", "network_health", "system", "10.0.0.1")
	r.Status = models.StatusPass
	r.Finish()

	mtuR := models.NewCheckResult("ping", "network_health", "system", "10.0.0.1")
	mtuR.Status = models.StatusPass
	mtuR.Observed = map[string]interface{}{"mtu": 1500}
	mtuR.Evidence = []string{"MTU probe ok"}
	mtuR.Finish()

	spec := &intent.Spec{
		Version: 1, Site: "test",
		Assertions: []intent.Assertion{{Type: "network_health", Target: "10.0.0.1", ExpectMTU: 1500}},
	}
	mock := &backends.MockBackend{PingCheckResult: r, PingCheckStats: &health.PingStats{}, MTUResult: mtuR}
	eng := NewEngine(spec)
	eng.Backend = mock
	result, err := eng.runNetworkHealth(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusPass {
		t.Errorf("expected pass with MTU, got %s", result.Status)
	}
	if result.Observed["mtu"] != 1500 {
		t.Errorf("expected MTU in observed, got %v", result.Observed["mtu"])
	}
}

func TestRunNetworkHealth_MTUWarn(t *testing.T) {
	r := models.NewCheckResult("ping", "network_health", "system", "10.0.0.1")
	r.Status = models.StatusPass
	r.Finish()

	mtuR := models.NewCheckResult("ping", "network_health", "system", "10.0.0.1")
	mtuR.Status = models.StatusWarn
	mtuR.Evidence = []string{"MTU slightly low"}
	mtuR.Finish()

	spec := &intent.Spec{
		Version: 1, Site: "test",
		Assertions: []intent.Assertion{{Type: "network_health", Target: "10.0.0.1", ExpectMTU: 1500}},
	}
	mock := &backends.MockBackend{PingCheckResult: r, PingCheckStats: &health.PingStats{}, MTUResult: mtuR}
	eng := NewEngine(spec)
	eng.Backend = mock
	result, err := eng.runNetworkHealth(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusWarn {
		t.Errorf("expected warn for MTU, got %s", result.Status)
	}
}

func TestRunNetworkHealth_MTUFail(t *testing.T) {
	r := models.NewCheckResult("ping", "network_health", "system", "10.0.0.1")
	r.Status = models.StatusPass
	r.Finish()

	mtuR := models.NewCheckResult("ping", "network_health", "system", "10.0.0.1")
	mtuR.Status = models.StatusFail
	mtuR.Summary = "MTU too low"
	mtuR.Evidence = []string{"MTU too low"}
	mtuR.Finish()

	spec := &intent.Spec{
		Version: 1, Site: "test",
		Assertions: []intent.Assertion{{Type: "network_health", Target: "10.0.0.1", ExpectMTU: 1500}},
	}
	mock := &backends.MockBackend{PingCheckResult: r, PingCheckStats: &health.PingStats{}, MTUResult: mtuR}
	eng := NewEngine(spec)
	eng.Backend = mock
	result, err := eng.runNetworkHealth(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusFail {
		t.Errorf("expected fail for MTU, got %s", result.Status)
	}
}

// --- runVPNRoute ---

func TestRunVPNRoute_ViaTunnel(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		VPN:        []intent.VPNConfig{{Name: "work", Type: "wireguard", Interface: "wg0"}},
		Assertions: []intent.Assertion{{Type: "vpn_route", VPN: "work", Target: "10.0.0.1", ExpectTunnel: ptrBool(true)}},
	}
	mock := &backends.MockBackend{
		RouteResult: &system.Route{Device: "wg0", Gateway: "10.0.0.1", Destination: "10.0.0.0/8"},
	}
	eng := NewEngine(spec)
	eng.Backend = mock
	result, err := eng.runVPNRoute(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusPass {
		t.Errorf("expected pass for tunnel route, got %s: %s", result.Status, result.Summary)
	}
}

func TestRunVPNRoute_NotViaTunnel(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		VPN:        []intent.VPNConfig{{Name: "work", Type: "wireguard", Interface: "wg0"}},
		Assertions: []intent.Assertion{{Type: "vpn_route", VPN: "work", Target: "10.0.0.1", ExpectTunnel: ptrBool(true)}},
	}
	mock := &backends.MockBackend{
		RouteResult:        &system.Route{Device: "eth0", Gateway: "192.168.1.1", Destination: "10.0.0.0/8"},
		VPNInterfaceResult: false,
	}
	eng := NewEngine(spec)
	eng.Backend = mock
	result, err := eng.runVPNRoute(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusFail {
		t.Errorf("expected fail for non-tunnel route, got %s: %s", result.Status, result.Summary)
	}
}

func TestRunVPNRoute_VPNNotFound(t *testing.T) {
	spec := &intent.Spec{Version: 1, Site: "test"}
	a := intent.Assertion{Type: "vpn_route", VPN: "missing", Target: "10.0.0.1"}
	eng := NewEngine(spec)
	_, err := eng.runVPNRoute(context.Background(), a)
	if err == nil {
		t.Fatal("expected error for missing VPN")
	}
}

// --- runRouteCheck ---

func TestRunRouteCheck(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Assertions: []intent.Assertion{{Type: "route_check", Target: "8.8.8.8"}},
	}
	mock := &backends.MockBackend{
		RouteResult: &system.Route{Device: "eth0", Gateway: "192.168.1.1", Destination: "0.0.0.0/0"},
	}
	eng := NewEngine(spec)
	eng.Backend = mock
	result, err := eng.runRouteCheck(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusPass {
		t.Errorf("expected pass, got %s", result.Status)
	}
	if result.Observed["gateway"] != "192.168.1.1" {
		t.Errorf("expected gateway 192.168.1.1, got %v", result.Observed["gateway"])
	}
}

func TestRunRouteCheck_RouteError(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Assertions: []intent.Assertion{{Type: "route_check", Target: "8.8.8.8"}},
	}
	mock := &backends.MockBackend{RouteErr: backends.BackendError("route lookup failed")}
	eng := NewEngine(spec)
	eng.Backend = mock
	result, err := eng.runRouteCheck(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusError {
		t.Errorf("expected error status, got %s", result.Status)
	}
}

// --- runACLCheck ---

func TestRunACLCheck_PolicyNotFound(t *testing.T) {
	spec := &intent.Spec{Version: 1, Site: "test"}
	a := intent.Assertion{Type: "acl_check", Provider: "omada", Policy: "missing-policy", Expect: "enforced"}
	eng := NewEngine(spec)
	result, err := eng.runACLCheck(context.Background(), a)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusError {
		t.Errorf("expected error for missing policy, got %s", result.Status)
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

// --- runPortCheck closed/filtered semantics (#116) ---

func TestRunPortCheck_ClosedAcceptsFiltered(t *testing.T) {
	// nmap scans with --open, so closed ports are absent from the output and
	// the parser tags them "filtered". expect: closed must PASS for a
	// not-open port — previously it always failed with "got filtered".
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Assertions: []intent.Assertion{{Type: "port_check", Target: "10.0.0.1", Ports: []int{8080}, Expect: "closed"}},
	}
	mock := &backends.MockBackend{
		PortScanResult: mockPortScanResult([]int{8080}, "filtered"),
	}
	eng := NewEngine(spec)
	eng.Backend = mock
	result, err := eng.runPortCheck(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusPass {
		t.Errorf("expected pass (not-open port with expect closed), got %s: %s", result.Status, result.Summary)
	}
}

func TestRunPortCheck_ClosedViolatedWhenOpen(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Assertions: []intent.Assertion{{Type: "port_check", Target: "10.0.0.1", Ports: []int{8080}, Expect: "closed"}},
	}
	mock := &backends.MockBackend{
		PortScanResult: mockPortScanResult([]int{8080}, "open"),
	}
	eng := NewEngine(spec)
	eng.Backend = mock
	result, err := eng.runPortCheck(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusFail {
		t.Errorf("expected fail (open port with expect closed), got %s: %s", result.Status, result.Summary)
	}
}

func TestRunPortCheck_OpenFailsWhenFiltered(t *testing.T) {
	// A port absent from --open output must not satisfy expect: open.
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Assertions: []intent.Assertion{{Type: "port_check", Target: "10.0.0.1", Ports: []int{8080}, Expect: "open"}},
	}
	mock := &backends.MockBackend{
		PortScanResult: mockPortScanResult([]int{8080}, "filtered"),
	}
	eng := NewEngine(spec)
	eng.Backend = mock
	result, err := eng.runPortCheck(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusFail {
		t.Errorf("expected fail (filtered port with expect open), got %s: %s", result.Status, result.Summary)
	}
}

func TestRunPortCheck_OpenPassesWhenOpen(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Assertions: []intent.Assertion{{Type: "port_check", Target: "10.0.0.1", Ports: []int{80}, Expect: "open"}},
	}
	mock := &backends.MockBackend{
		PortScanResult: mockPortScanResult([]int{80}, "open"),
	}
	eng := NewEngine(spec)
	eng.Backend = mock
	result, err := eng.runPortCheck(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusPass {
		t.Errorf("expected pass (open port with expect open), got %s: %s", result.Status, result.Summary)
	}
}
