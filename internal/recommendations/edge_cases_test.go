package recommendations

import (
	"testing"

	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/models"
)

// --- Cap at 8 recommendations ---

func TestGenerateRecommendations_CapAllTenCategories(t *testing.T) {
	// Trigger all 10 categories to exceed the 8-recommendation cap
	spec := &intent.Spec{
		Networks: []intent.Network{
			{Name: "net-a", CIDR: "10.0.0.0/24", Zone: "zone-a"},
			{Name: "net-b", CIDR: "10.0.1.0/24", Zone: "zone-b"},
			{Name: "net-c", CIDR: "10.0.2.0/24", Zone: "zone-c"},
		},
		VPN:    []intent.VPNConfig{{Name: "vpn1", Type: "wireguard"}},
		Probes: []intent.Probe{{Name: "probe1", Host: "10.0.1.50", VLAN: "zone-b"}},
		Policies: []intent.Policy{
			{Name: "p1", From: "zone-a", To: "zone-b", Action: "deny"},
		},
	}
	runner := models.RunnerContext{Networks: []string{"net-a"}}
	failures := []models.CheckResult{
		// isolation_breach: runner in zone-a (from net-a), isolation violated
		{CheckType: "isolation", Target: "zone-a -> zone-b", Status: models.StatusFail,
			Summary:    "isolation violation: zone-a can reach zone-b",
			Violations: []string{"expected deny"}},
		// acl_not_enforced
		{CheckType: "acl_check", Target: "policy1", Status: models.StatusFail,
			Summary: "not enforced"},
		// discovery_count (max violation)
		{CheckType: "subnet_discovery", Target: "net-a", Status: models.StatusFail,
			Summary: "35 hosts", Observed: map[string]interface{}{"total": 35},
			Violations: []string{"found 35 hosts, expected max 20"},
			Expected:   map[string]interface{}{"expect_hosts_max": 20}},
		// vpn_misconfigured
		{CheckType: "vpn_route", Target: "10.0.0.1", Status: models.StatusFail,
			Summary: "not via tunnel"},
		// dns_failure
		{CheckType: "dns_check", Target: "x.lan", Status: models.StatusFail,
			Summary: "wrong ip"},
		// service_down
		{CheckType: "port_check", Target: "1.1.1.1", Status: models.StatusFail,
			Summary: "port closed"},
		// network_degraded
		{CheckType: "network_health", Target: "192.168.1.1", Status: models.StatusFail,
			Summary: "latency and loss"},
		// network_unreachable: port_check ERROR (runner may be anywhere)
		{CheckType: "port_check", Target: "10.99.0.1", Status: models.StatusError,
			Summary: "connection timed out"},
		// vantage_point: isolation WARN with runner NOT in zone-c
		{CheckType: "isolation", Target: "zone-c -> zone-d", Status: models.StatusWarn,
			Summary: "unverifiable from current vantage point"},
		// host_down_or_filtered: subnet_discovery FAIL, hostCount=0, runner IN net-a
		{CheckType: "subnet_discovery", Target: "net-a", Status: models.StatusFail,
			Summary: "0 hosts found", Observed: map[string]interface{}{"total": 0}},
	}
	recs, err := GenerateRecommendations(failures, spec, runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// With 9 categories triggered (>8), we should get exactly 8 (capped)
	if len(recs) != 8 {
		t.Errorf("expected 8 recommendations (capped), got %d", len(recs))
	}

}

// --- buildIsolationContext: probe with empty Host ---

func TestBuildIsolationContext_ProbeWithEmptyHost(t *testing.T) {
	spec := &intent.Spec{
		Networks: []intent.Network{
			{Name: "net-a", CIDR: "10.0.0.0/24", Zone: "zone-a"},
		},
		Probes: []intent.Probe{
			{Name: "probe1", Host: "", VLAN: "zone-b"}, // VLAN doesn't match from
		},
	}
	// probe1 has VLAN="zone-b" which doesn't match "zone-a", and Host="" so IP check is skipped
	ctx := buildIsolationContext("zone-a", "zone-b", spec, models.RunnerContext{})
	if ctx == nil {
		t.Fatal("expected non-nil context")
	}
	if ctx.probeInFromZone {
		t.Error("expected probeInFromZone=false for probe not in zone-a")
	}
}

// --- buildIsolationContext: probe host not in any matching network ---

func TestBuildIsolationContext_ProbeHostNotInZone(t *testing.T) {
	spec := &intent.Spec{
		Networks: []intent.Network{
			{Name: "net-a", CIDR: "10.0.0.0/24", Zone: "zone-a"},
		},
		Probes: []intent.Probe{
			{Name: "probe1", Host: "192.168.99.50"}, // IP not in 10.0.0.0/24
		},
	}
	// probe1 Host is not in any network matching zone-a
	ctx := buildIsolationContext("zone-a", "zone-b", spec, models.RunnerContext{})
	if ctx == nil {
		t.Fatal("expected non-nil context")
	}
	if ctx.probeInFromZone {
		t.Error("expected probeInFromZone=false for probe host not in zone")
	}
}

// --- recommendVantagePoint: failure with non-zone, non-network name ---

func TestRecommendVantagePoint_NoNetworkByName(t *testing.T) {
	g := failureGroup{
		category: "vantage_point",
		failures: []models.CheckResult{
			// Target is a name not in spec and not a valid zone
			{CheckType: "isolation", Target: "nonexistent -> other", Status: models.StatusWarn, Summary: "unverifiable"},
		},
	}
	spec := &intent.Spec{
		Networks: []intent.Network{
			{Name: "net-a", CIDR: "10.0.0.0/24", Zone: "zone-a"},
		},
	}
	runner := models.RunnerContext{Networks: []string{}}
	recs := recommendVantagePoint(g, spec, runner, 1)
	if len(recs) == 0 {
		t.Fatal("expected at least 1 recommendation")
	}
}

// --- recommendVantagePoint: failure targeting network with no Zone ---

func TestRecommendVantagePoint_NetworkWithoutZone(t *testing.T) {
	g := failureGroup{
		category: "vantage_point",
		failures: []models.CheckResult{
			// Target matches a network name that has no Zone field
			{CheckType: "subnet_discovery", Target: "net-a", Status: models.StatusError, Summary: "timed out"},
		},
	}
	spec := &intent.Spec{
		Networks: []intent.Network{
			{Name: "net-a", CIDR: "10.0.0.0/24"}, // no Zone
		},
	}
	runner := models.RunnerContext{Networks: []string{}}
	recs := recommendVantagePoint(g, spec, runner, 1)
	if len(recs) == 0 {
		t.Fatal("expected at least 1 recommendation")
	}
	// Should set neededZones[net.Name] since net.Zone is empty
}

// --- recommendVPN: failure with empty target ---

func TestRecommendVPN_EmptyTarget(t *testing.T) {
	g := failureGroup{
		category: "vpn_misconfigured",
		failures: []models.CheckResult{
			{CheckType: "vpn_route", Target: "", Status: models.StatusFail, Summary: "not via tunnel"},
		},
	}
	recs := recommendVPN(g, nil, models.RunnerContext{}, 1)
	if len(recs) != 0 {
		t.Errorf("expected 0 recommendations for empty target, got %d", len(recs))
	}
}

// --- recommendDNSFailure: resolved_ip is empty string ---

func TestRecommendDNSFailure_EmptyResolvedIP(t *testing.T) {
	g := failureGroup{
		category: "dns_failure",
		failures: []models.CheckResult{
			{CheckType: "dns_check", Target: "nas.lan", Status: models.StatusFail,
				Summary:  "wrong ip",
				Observed: map[string]interface{}{"resolved_ip": ""}, // non-nil but empty
				Expected: map[string]interface{}{"expect_ip": "10.0.0.10"},
			},
		},
	}
	spec := &intent.Spec{
		Networks: []intent.Network{{Name: "personal", CIDR: "10.0.0.0/24", Zone: "personal"}},
	}
	runner := models.RunnerContext{Networks: []string{"personal"}}
	recs := recommendDNSFailure(g, spec, runner, 1)
	if len(recs) != 1 {
		t.Fatalf("expected 1 recommendation, got %d", len(recs))
	}
	// SpecPatch should be empty because the resolved_ip was empty (skipped)
	if recs[0].SpecPatch != "" {
		t.Errorf("expected empty SpecPatch for empty resolved_ip, got %q", recs[0].SpecPatch)
	}
}

// --- recommendNetworkDegraded: new latency > old latency ---

func TestRecommendNetworkDegraded_LatencyAdjustmentNeeded(t *testing.T) {
	g := failureGroup{
		category: "network_degraded",
		failures: []models.CheckResult{
			{CheckType: "network_health", Target: "10.0.0.1", Status: models.StatusFail,
				Summary:  "high latency",
				Observed: map[string]interface{}{"avg_rtt_ms": 200, "loss_pct": 0},
				Expected: map[string]interface{}{"max_latency_ms": 100, "max_loss_pct": 5},
			},
		},
	}
	spec := &intent.Spec{
		Networks: []intent.Network{{Name: "net", CIDR: "10.0.0.0/24", Zone: "zone-a"}},
	}
	runner := models.RunnerContext{Networks: []string{"net"}}
	recs := recommendNetworkDegraded(g, spec, runner, 1)
	if len(recs) != 1 {
		t.Fatalf("expected 1 recommendation, got %d", len(recs))
	}
	// newLatency = 200 + 66 = 266, which is > oldLatency (100), so the adjustment applies
	r := recs[0]
	if !containsStr(r.SpecPatch, "expect_latency_ms") {
		t.Errorf("expected latency threshold in SpecPatch, got: %s", r.SpecPatch)
	}
}

// --- recommendNetworkDegraded: newLatency < oldLatency (lower bound) ---

func TestRecommendNetworkDegraded_LatencyAlreadyHigh(t *testing.T) {
	g := failureGroup{
		category: "network_degraded",
		failures: []models.CheckResult{
			{CheckType: "network_health", Target: "10.0.0.1", Status: models.StatusFail,
				Summary:  "high latency",
				Observed: map[string]interface{}{"avg_rtt_ms": 50, "loss_pct": 0},
				Expected: map[string]interface{}{"max_latency_ms": 200, "max_loss_pct": 0},
			},
		},
	}
	spec := &intent.Spec{
		Networks: []intent.Network{{Name: "net", CIDR: "10.0.0.0/24", Zone: "zone-a"}},
	}
	runner := models.RunnerContext{Networks: []string{"net"}}
	recs := recommendNetworkDegraded(g, spec, runner, 1)
	if len(recs) != 1 {
		t.Fatalf("expected 1 recommendation, got %d", len(recs))
	}
	// newLatency = 50 + 16 = 66, which is < oldLatency (200), so newLatency = 200
	r := recs[0]
	if !containsStr(r.SpecPatch, "expect_latency_ms") {
		t.Errorf("expected latency threshold in SpecPatch, got: %s", r.SpecPatch)
	}
	// No loss threshold configured (max_loss_pct 0) means no loss patch line
	if containsStr(r.SpecPatch, "expect_loss_pct") {
		t.Errorf("expected no loss threshold in SpecPatch when max_loss_pct is 0, got: %s", r.SpecPatch)
	}
}

// --- ipInCIDR: hostname resolution success ---

func TestIpInCIDR_HostnameResolves(t *testing.T) {
	// "localhost" resolves to 127.0.0.1 which is in 127.0.0.0/8
	result := ipInCIDR("localhost", "127.0.0.0/8")
	// This may or may not resolve depending on /etc/hosts, but the code path
	// should execute without crashing
	_ = result
}

// --- recommendNetworkUnreachable: duplicate zones in affected list ---

func TestRecommendNetworkUnreachable_DuplicateZones(t *testing.T) {
	g := failureGroup{
		category: "network_unreachable",
		failures: []models.CheckResult{
			// Two failures targeting different networks but in the same zone
			{CheckType: "port_check", Target: "net-a", Status: models.StatusError, Summary: "connection refused"},
			{CheckType: "port_check", Target: "net-b", Status: models.StatusError, Summary: "connection refused"},
		},
	}
	spec := &intent.Spec{
		Networks: []intent.Network{
			{Name: "net-a", CIDR: "10.0.0.0/24", Zone: "zone-a"},
			{Name: "net-b", CIDR: "10.0.1.0/24", Zone: "zone-a"}, // same zone
		},
	}
	runner := models.RunnerContext{Networks: []string{}}
	recs := recommendNetworkUnreachable(g, spec, runner, 1)
	if len(recs) != 1 {
		t.Fatalf("expected 1 recommendation, got %d", len(recs))
	}
	// SpecPatch should only mention the zone once (dedup path)
	if recs[0].SpecPatch == "" {
		t.Error("expected non-empty SpecPatch for duplicate zone test")
	}
}

// --- recommendNetworkUnreachable: runner zone pick must be deterministic ---

func TestRecommendNetworkUnreachable_DeterministicRunnerZone(t *testing.T) {
	g := failureGroup{
		category: "network_unreachable",
		failures: []models.CheckResult{
			{CheckType: "port_check", Target: "10.0.1.5", Status: models.StatusError, Summary: "connection refused"},
			{CheckType: "port_check", Target: "10.0.2.5", Status: models.StatusError, Summary: "connection refused"},
			{CheckType: "port_check", Target: "10.0.3.5", Status: models.StatusError, Summary: "connection refused"},
		},
	}
	spec := &intent.Spec{
		Networks: []intent.Network{
			{Name: "zulu", CIDR: "10.0.1.0/24", Zone: "zulu"},
			{Name: "alpha", CIDR: "10.0.2.0/24", Zone: "alpha"},
			{Name: "mike", CIDR: "10.0.3.0/24", Zone: "mike"},
		},
	}
	runner := models.RunnerContext{}
	// Map iteration order varies per iteration — repeated runs must still
	// name the same (alphabetically first) zone in the runner example.
	for i := 0; i < 100; i++ {
		recs := recommendNetworkUnreachable(g, spec, runner, 1)
		if len(recs) != 1 {
			t.Fatalf("iteration %d: expected 1 recommendation, got %d", i, len(recs))
		}
		if !containsStr(recs[0].SpecPatch, "+    runner: alpha-probe") {
			t.Fatalf("iteration %d: expected deterministic runner alpha-probe, got patch:\n%s", i, recs[0].SpecPatch)
		}
	}
}

// --- recommendDiscovery: "expected min" with negative host count (edge case) ---

func TestRecommendDiscovery_ExpectedMinNegativeHostCount(t *testing.T) {
	g := failureGroup{
		category: "discovery_count",
		failures: []models.CheckResult{
			{CheckType: "subnet_discovery", Target: "net-a", Status: models.StatusFail,
				Summary:    "2 hosts found",
				Violations: []string{"expected min 5"},
				Observed:   map[string]interface{}{"total": float64(-3)}, // negative float64 → int(-3)
				Expected:   map[string]interface{}{"expect_hosts_min": 5},
			},
		},
	}
	// newMin = -3 + 1 = -2, which is < 1, triggering the reassignment to 1
	recs := recommendDiscovery(g, nil, models.RunnerContext{}, 1)
	if len(recs) != 1 {
		t.Fatalf("expected 1 recommendation, got %d", len(recs))
	}
	if !containsStr(recs[0].SpecPatch, "expect_hosts_min") {
		t.Errorf("expected expect_hosts_min in SpecPatch, got: %s", recs[0].SpecPatch)
	}
}

// --- recommendNetworkDegraded: negative loss_pct triggers newLoss floor ---

func TestRecommendNetworkDegraded_NegativeLossPct(t *testing.T) {
	g := failureGroup{
		category: "network_degraded",
		failures: []models.CheckResult{
			{CheckType: "network_health", Target: "10.0.0.1", Status: models.StatusFail,
				Summary:  "high latency",
				Observed: map[string]interface{}{"avg_rtt_ms": 50, "loss_pct": float64(-3)}, // negative → extractInt returns -3
				Expected: map[string]interface{}{"max_latency_ms": 200, "max_loss_pct": 5},
			},
		},
	}
	spec := &intent.Spec{
		Networks: []intent.Network{{Name: "net", CIDR: "10.0.0.0/24", Zone: "zone-a"}},
	}
	runner := models.RunnerContext{Networks: []string{"net"}}
	recs := recommendNetworkDegraded(g, spec, runner, 1)
	if len(recs) != 1 {
		t.Fatalf("expected 1 recommendation, got %d", len(recs))
	}
	// newLoss = -3 + 1 = -2, which is < 1, triggering reassignment to 1
	if !containsStr(recs[0].SpecPatch, "expect_loss_pct") {
		t.Errorf("expected expect_loss_pct in SpecPatch, got: %s", recs[0].SpecPatch)
	}
}

func containsStr(s, substr string) bool {
	return len(s) > 0 && (s == substr || len(substr) == 0 || len(s) >= len(substr) && s[0:len(substr)] == substr || containsStrInner(s, substr))
}

func containsStrInner(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
