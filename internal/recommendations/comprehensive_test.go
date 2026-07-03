package recommendations

import (
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/models"
)

// TestClassifyIsolation_VantagePointRunnerNotInZone tests vantage point
// when runner is NOT in the source zone.
func TestClassifyIsolation_VantagePointRunnerNotInZone(t *testing.T) {
	failures := []models.CheckResult{
		{
			CheckType:  "isolation",
			Target:     "personal -> gaming",
			Status:     models.StatusFail,
			Summary:    "isolation violation: personal can reach gaming",
			Violations: []string{"expected deny but traffic is reachable"},
		},
	}
	spec := &intent.Spec{
		Networks: []intent.Network{
			{Name: "personal", CIDR: "10.0.20.0/24", Zone: "personal"},
			{Name: "gaming", CIDR: "10.0.30.0/24", Zone: "gaming"},
		},
	}
	runner := models.RunnerContext{Networks: []string{"gaming"}}
	recs, err := GenerateRecommendations(failures, spec, runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, r := range recs {
		if r.Category == "vantage_point" {
			found = true
			if !strings.Contains(r.Description, "personal") {
				t.Errorf("expected description to mention personal zone, got: %s", r.Description)
			}
		}
	}
	if !found {
		t.Error("expected vantage_point when runner not in source zone")
	}
}

// TestClassifyIsolation_WarnStatusIsVantagePoint tests WARN isolation goes to vantage_point.
func TestClassifyIsolation_WarnStatusIsVantagePoint(t *testing.T) {
	failures := []models.CheckResult{
		{CheckType: "isolation", Target: "personal -> gaming", Status: models.StatusWarn, Summary: "unverifiable"},
	}
	spec := &intent.Spec{
		Networks: []intent.Network{
			{Name: "personal", CIDR: "10.0.20.0/24", Zone: "personal"},
			{Name: "gaming", CIDR: "10.0.30.0/24", Zone: "gaming"},
		},
	}
	runner := models.RunnerContext{Networks: []string{"personal"}}
	recs, err := GenerateRecommendations(failures, spec, runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, r := range recs {
		if r.Category == "vantage_point" {
			found = true
		}
	}
	if !found {
		t.Error("expected vantage_point for WARN isolation")
	}
}

// TestClassifyIsolation_ConnectivityFailureIsNetworkUnreachable tests connectivity-failure path.
func TestClassifyIsolation_ConnectivityFailureIsNetworkUnreachable(t *testing.T) {
	failures := []models.CheckResult{
		{CheckType: "isolation", Target: "personal -> gaming", Status: models.StatusFail, Summary: "connectivity failure: cannot reach 10.0.30.0/24"},
	}
	spec := &intent.Spec{
		Networks: []intent.Network{
			{Name: "personal", CIDR: "10.0.20.0/24", Zone: "personal"},
			{Name: "gaming", CIDR: "10.0.30.0/24", Zone: "gaming"},
		},
	}
	runner := models.RunnerContext{Networks: []string{"personal"}}
	recs, err := GenerateRecommendations(failures, spec, runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, r := range recs {
		if r.Category == "network_unreachable" {
			found = true
		}
	}
	if !found {
		t.Error("expected network_unreachable for connectivity failure")
	}
}

// TestClassifyIsolation_NoParseableTarget tests fallback to isolation_breach when target cannot be parsed.
func TestClassifyIsolation_NoParseableTarget(t *testing.T) {
	failures := []models.CheckResult{
		{CheckType: "isolation", Target: "random", Status: models.StatusFail, Summary: "some error", Violations: []string{"expected deny"}},
	}
	spec := &intent.Spec{
		Networks: []intent.Network{{Name: "personal", CIDR: "10.0.20.0/24", Zone: "personal"}},
	}
	runner := models.RunnerContext{Networks: []string{"personal"}}
	recs, err := GenerateRecommendations(failures, spec, runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, r := range recs {
		if r.Category == "isolation_breach" {
			found = true
		}
	}
	if !found {
		t.Error("expected isolation_breach when target cannot be parsed")
	}
}

// TestClassifyIsolation_FromSummaryParsing tests from/to extracted from summary text.
func TestClassifyIsolation_FromSummaryParsing(t *testing.T) {
	failures := []models.CheckResult{
		{CheckType: "isolation", Target: "just-an-ip", Status: models.StatusFail, Summary: "isolation violation: personal can reach gaming", Violations: []string{"expected deny"}},
	}
	spec := &intent.Spec{
		Networks: []intent.Network{
			{Name: "personal", CIDR: "10.0.20.0/24", Zone: "personal"},
			{Name: "gaming", CIDR: "10.0.30.0/24", Zone: "gaming"},
		},
	}
	runner := models.RunnerContext{Networks: []string{"personal"}}
	recs, err := GenerateRecommendations(failures, spec, runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, r := range recs {
		if r.Category == "isolation_breach" {
			found = true
		}
	}
	if !found {
		t.Error("expected isolation_breach when from/to parsed from summary")
	}
}

// TestBuildIsolationContext_NilSpec tests nil spec returns nil context.
func TestBuildIsolationContext_NilSpec(t *testing.T) {
	ctx := buildIsolationContext("personal", "gaming", nil, models.RunnerContext{})
	if ctx != nil {
		t.Error("expected nil context for nil spec")
	}
}

// TestBuildIsolationContext_ProbeInZoneViaCIDR tests probe detection via IP in CIDR.
func TestBuildIsolationContext_ProbeInZoneViaCIDR(t *testing.T) {
	spec := &intent.Spec{
		Networks: []intent.Network{
			{Name: "personal", CIDR: "10.0.20.0/24", Zone: "personal"},
		},
		Probes: []intent.Probe{
			{Name: "my-probe", Host: "10.0.20.50", VLAN: "personal"},
		},
	}
	ctx := buildIsolationContext("personal", "gaming", spec, models.RunnerContext{})
	if ctx == nil {
		t.Fatal("expected non-nil context")
	}
	if !ctx.probeInFromZone {
		t.Error("expected probeInFromZone to be true")
	}
	if ctx.probeName != "my-probe" {
		t.Errorf("expected probeName my-probe, got %s", ctx.probeName)
	}
}

// TestBuildIsolationContext_ProbeInZoneViaVLAN tests probe detection via VLAN field.
func TestBuildIsolationContext_ProbeInZoneViaVLAN(t *testing.T) {
	spec := &intent.Spec{
		Networks: []intent.Network{
			{Name: "personal", CIDR: "10.0.20.0/24", Zone: "personal"},
		},
		Probes: []intent.Probe{
			{Name: "vlan-probe", VLAN: "personal"},
		},
	}
	ctx := buildIsolationContext("personal", "gaming", spec, models.RunnerContext{})
	if ctx == nil {
		t.Fatal("expected non-nil context")
	}
	if !ctx.probeInFromZone {
		t.Error("expected probeInFromZone to be true via VLAN")
	}
	if ctx.probeName != "vlan-probe" {
		t.Errorf("expected probeName vlan-probe, got %s", ctx.probeName)
	}
}

// TestBuildIsolationContext_PolicyMatch tests policy name lookup.
func TestBuildIsolationContext_PolicyMatch(t *testing.T) {
	spec := &intent.Spec{
		Networks: []intent.Network{
			{Name: "personal", CIDR: "10.0.20.0/24", Zone: "personal"},
			{Name: "gaming", CIDR: "10.0.30.0/24", Zone: "gaming"},
		},
		Policies: []intent.Policy{
			{Name: "deny-personal-gaming", From: "personal", To: "gaming", Action: "deny"},
		},
	}
	ctx := buildIsolationContext("personal", "gaming", spec, models.RunnerContext{})
	if ctx == nil {
		t.Fatal("expected non-nil context")
	}
	if ctx.policyName != "deny-personal-gaming" {
		t.Errorf("expected policyName deny-personal-gaming, got %s", ctx.policyName)
	}
}

// TestBuildIsolationContext_RunnerInFromZone tests runner network detection.
func TestBuildIsolationContext_RunnerInFromZone(t *testing.T) {
	spec := &intent.Spec{
		Networks: []intent.Network{
			{Name: "personal", CIDR: "10.0.20.0/24", Zone: "personal"},
		},
	}
	runner := models.RunnerContext{Networks: []string{"personal"}}
	ctx := buildIsolationContext("personal", "gaming", spec, runner)
	if ctx == nil {
		t.Fatal("expected non-nil context")
	}
	if !ctx.runnerInFrom {
		t.Error("expected runnerInFrom to be true")
	}
}

// TestBuildIsolationContext_RunnerNotInFromZone tests runner not in source zone.
func TestBuildIsolationContext_RunnerNotInFromZone(t *testing.T) {
	spec := &intent.Spec{
		Networks: []intent.Network{
			{Name: "personal", CIDR: "10.0.20.0/24", Zone: "personal"},
			{Name: "gaming", CIDR: "10.0.30.0/24", Zone: "gaming"},
		},
	}
	runner := models.RunnerContext{Networks: []string{"gaming"}}
	ctx := buildIsolationContext("personal", "gaming", spec, runner)
	if ctx == nil {
		t.Fatal("expected non-nil context")
	}
	if ctx.runnerInFrom {
		t.Error("expected runnerInFrom to be false")
	}
}

// =============================================================================
// classifyDiscovery — host_down_or_filtered, network_unreachable, zero hosts
// =============================================================================

func TestClassifyDiscovery_ZeroHostsRunnerInNetwork(t *testing.T) {
	failures := []models.CheckResult{
		{
			CheckType: "subnet_discovery",
			Target:    "personal",
			Status:    models.StatusWarn,
			Summary:   "0 hosts discovered in 10.0.20.0/24",
			Observed:  map[string]interface{}{"total": 0},
		},
	}
	spec := &intent.Spec{
		Networks: []intent.Network{
			{Name: "personal", CIDR: "10.0.20.0/24", Zone: "personal"},
		},
	}
	runner := models.RunnerContext{Networks: []string{"personal"}}
	recs, err := GenerateRecommendations(failures, spec, runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, r := range recs {
		if r.Category == "host_down_or_filtered" {
			found = true
		}
	}
	if !found {
		t.Error("expected host_down_or_filtered when runner is in network with 0 hosts")
	}
}

func TestClassifyDiscovery_ZeroHostsRunnerNotInNetwork(t *testing.T) {
	failures := []models.CheckResult{
		{
			CheckType: "subnet_discovery",
			Target:    "personal",
			Status:    models.StatusWarn,
			Summary:   "0 hosts discovered in 10.0.20.0/24",
			Observed:  map[string]interface{}{"total": 0},
		},
	}
	spec := &intent.Spec{
		Networks: []intent.Network{
			{Name: "personal", CIDR: "10.0.20.0/24", Zone: "personal"},
			{Name: "gaming", CIDR: "10.0.30.0/24", Zone: "gaming"},
		},
	}
	runner := models.RunnerContext{Networks: []string{"gaming"}}
	recs, err := GenerateRecommendations(failures, spec, runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, r := range recs {
		if r.Category == "network_unreachable" {
			found = true
		}
	}
	// Runner is not in the target network and 0 hosts → network_unreachable
	if !found {
		t.Error("expected network_unreachable when runner not in network with 0 hosts")
	}
}

func TestClassifyDiscovery_TimeoutRunnerNotInNetwork(t *testing.T) {
	failures := []models.CheckResult{
		{
			CheckType: "subnet_discovery",
			Target:    "media",
			Status:    models.StatusError,
			Summary:   "subnet_discovery timed out",
		},
	}
	spec := &intent.Spec{
		Networks: []intent.Network{
			{Name: "media", CIDR: "10.0.40.0/24", Zone: "media"},
			{Name: "personal", CIDR: "10.0.20.0/24", Zone: "personal"},
		},
	}
	runner := models.RunnerContext{Networks: []string{"personal"}}
	recs, err := GenerateRecommendations(failures, spec, runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, r := range recs {
		if r.Category == "vantage_point" {
			found = true
		}
	}
	if !found {
		t.Error("expected vantage_point for timeout when runner not in target network")
	}
}

func TestClassifyDiscovery_TimeoutRunnerInNetwork(t *testing.T) {
	failures := []models.CheckResult{
		{
			CheckType: "subnet_discovery",
			Target:    "personal",
			Status:    models.StatusError,
			Summary:   "subnet_discovery timed out",
		},
	}
	spec := &intent.Spec{
		Networks: []intent.Network{
			{Name: "personal", CIDR: "10.0.20.0/24", Zone: "personal"},
		},
	}
	runner := models.RunnerContext{Networks: []string{"personal"}}
	recs, err := GenerateRecommendations(failures, spec, runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, r := range recs {
		if r.Category == "network_unreachable" {
			found = true
		}
	}
	// Runner IS in the network and timeout → network_unreachable
	if !found {
		t.Error("expected network_unreachable when runner in network with timeout")
	}
}

func TestClassifyDiscovery_ExpectedMinViolation(t *testing.T) {
	failures := []models.CheckResult{
		{
			CheckType:  "subnet_discovery",
			Target:     "personal",
			Status:     models.StatusFail,
			Summary:    "3 hosts discovered in 10.0.20.0/24",
			Observed:   map[string]interface{}{"total": 3},
			Expected:   map[string]interface{}{"expect_hosts_min": 10},
			Violations: []string{"found 3 hosts, expected min 10"},
		},
	}
	recs, err := GenerateRecommendations(failures, nil, models.RunnerContext{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, r := range recs {
		if r.Category == "discovery_count" {
			found = true
			if !strings.Contains(r.Title, "Fewer hosts") {
				t.Errorf("expected title to mention fewer hosts, got: %s", r.Title)
			}
			if r.SpecPatch == "" {
				t.Error("expected SpecPatch with updated min")
			}
		}
	}
	if !found {
		t.Error("expected discovery_count for expected min violation")
	}
}

// =============================================================================
// runnerInNetwork tests
// =============================================================================

func TestRunnerInNetwork(t *testing.T) {
	spec := &intent.Spec{
		Networks: []intent.Network{
			{Name: "personal", CIDR: "10.0.20.0/24", Zone: "personal"},
			{Name: "gaming", CIDR: "10.0.30.0/24", Zone: "gaming"},
		},
	}

	runner := models.RunnerContext{Networks: []string{"personal"}}

	if !runnerInNetwork(runner, "personal", spec) {
		t.Error("expected runner to be in personal network")
	}
	if runnerInNetwork(runner, "gaming", spec) {
		t.Error("expected runner to NOT be in gaming network")
	}
	if runnerInNetwork(runner, "unknown", spec) {
		t.Error("expected runner to NOT be in unknown network")
	}
}

func TestRunnerInNetwork_NilSpec(t *testing.T) {
	runner := models.RunnerContext{Networks: []string{"personal"}}
	if runnerInNetwork(runner, "personal", nil) {
		t.Error("expected false for nil spec")
	}
}

func TestRunnerInNetwork_NetworkNotFound(t *testing.T) {
	spec := &intent.Spec{
		Networks: []intent.Network{
			{Name: "personal", CIDR: "10.0.20.0/24", Zone: "personal"},
		},
	}
	runner := models.RunnerContext{Networks: []string{"personal"}}
	if runnerInNetwork(runner, "nonexistent", spec) {
		t.Error("expected false for nonexistent network")
	}
}

// =============================================================================
// recommendVantagePoint tests
// =============================================================================

func TestRecommendVantagePoint_WithSpecAndProbe(t *testing.T) {
	spec := &intent.Spec{
		Networks: []intent.Network{
			{Name: "personal", CIDR: "10.0.20.0/24", Zone: "personal", Gateway: "10.0.20.1"},
			{Name: "gaming", CIDR: "10.0.30.0/24", Zone: "gaming"},
		},
		Probes: []intent.Probe{
			{Name: "personal-probe", Host: "10.0.20.50", User: "admin", VLAN: "personal"},
		},
		Policies: []intent.Policy{
			{Name: "deny-pg", From: "personal", To: "gaming", Action: "deny"},
		},
	}
	runner := models.RunnerContext{Networks: []string{"gaming"}}
	g := failureGroup{
		category: "vantage_point",
		failures: []models.CheckResult{
			{CheckType: "isolation", Target: "personal -> gaming", Status: models.StatusFail, Summary: "isolation violation: personal can reach gaming"},
		},
		isolationCtx: &isolationContext{
			fromZone:        "personal",
			toZone:          "gaming",
			runnerInFrom:    false,
			probeInFromZone: true,
			probeName:       "personal-probe",
			policyName:      "deny-pg",
		},
	}
	recs := recommendVantagePoint(g, spec, runner, 1)
	if len(recs) != 1 {
		t.Fatalf("expected 1 recommendation, got %d", len(recs))
	}
	r := recs[0]
	if r.Category != "vantage_point" {
		t.Errorf("expected category vantage_point, got %s", r.Category)
	}
	if !strings.Contains(r.Remediation, "personal-probe") {
		t.Errorf("expected remediation to mention probe name, got: %s", r.Remediation)
	}
	if r.SpecPatch == "" {
		t.Error("expected non-empty SpecPatch")
	}
}

func TestRecommendVantagePoint_NoIsolationCtx(t *testing.T) {
	g := failureGroup{
		category: "vantage_point",
		failures: []models.CheckResult{
			{CheckType: "subnet_discovery", Target: "media", Status: models.StatusError, Summary: "timed out"},
		},
	}
	spec := &intent.Spec{
		Networks: []intent.Network{
			{Name: "media", CIDR: "10.0.40.0/24", Zone: "media"},
		},
	}
	runner := models.RunnerContext{Networks: []string{"personal"}}
	recs := recommendVantagePoint(g, spec, runner, 1)
	if len(recs) != 1 {
		t.Fatalf("expected 1 recommendation, got %d", len(recs))
	}
	r := recs[0]
	// Generic remediation mentions adding a probe (not an existing probe hint)
	if !strings.Contains(r.Remediation, "Add a probe") {
		t.Errorf("expected generic remediation mentioning 'Add a probe', got: %s", r.Remediation)
	}
}

func TestRecommendVantagePoint_NoNeededZones(t *testing.T) {
	g := failureGroup{
		category: "vantage_point",
		failures: []models.CheckResult{
			{CheckType: "isolation", Target: "", Status: models.StatusFail, Summary: "unparseable"},
		},
	}
	recs := recommendVantagePoint(g, nil, models.RunnerContext{}, 1)
	if len(recs) != 0 {
		t.Errorf("expected 0 recommendations when no needed zones, got %d", len(recs))
	}
}

func TestRecommendVantagePoint_NoSpec(t *testing.T) {
	g := failureGroup{
		category: "vantage_point",
		failures: []models.CheckResult{
			{CheckType: "isolation", Target: "personal -> gaming", Status: models.StatusFail, Summary: "isolation violation"},
		},
	}
	runner := models.RunnerContext{Networks: []string{"gaming"}}
	recs := recommendVantagePoint(g, nil, runner, 1)
	if len(recs) != 1 {
		t.Fatalf("expected 1 recommendation, got %d", len(recs))
	}
	r := recs[0]
	// Without spec, no SpecPatch
	if r.SpecPatch != "" {
		t.Error("expected empty SpecPatch when spec is nil")
	}
}

func TestRecommendVantagePoint_MultipleZones(t *testing.T) {
	g := failureGroup{
		category: "vantage_point",
		failures: []models.CheckResult{
			{CheckType: "isolation", Target: "personal -> gaming", Status: models.StatusFail, Summary: "isolation violation: personal can reach gaming"},
			{CheckType: "isolation", Target: "iot -> personal", Status: models.StatusFail, Summary: "isolation violation: iot can reach personal"},
		},
	}
	spec := &intent.Spec{
		Networks: []intent.Network{
			{Name: "personal", CIDR: "10.0.20.0/24", Zone: "personal", Gateway: "10.0.20.1"},
			{Name: "gaming", CIDR: "10.0.30.0/24", Zone: "gaming"},
			{Name: "iot", CIDR: "10.0.50.0/24", Zone: "iot"},
		},
	}
	// Runner is in neither personal nor iot
	runner := models.RunnerContext{Networks: []string{"dmz"}}
	recs := recommendVantagePoint(g, spec, runner, 1)
	if len(recs) != 1 {
		t.Fatalf("expected 1 recommendation, got %d", len(recs))
	}
	r := recs[0]
	// Should mention both needed zones (personal, iot)
	if !strings.Contains(r.Description, "personal") || !strings.Contains(r.Description, "iot") {
		t.Errorf("expected description to mention both zones, got: %s", r.Description)
	}
}

// =============================================================================
// recommendIsolationBreach — no isolationCtx, no policy
// =============================================================================

func TestRecommendIsolationBreach_NoIsolationCtx(t *testing.T) {
	g := failureGroup{
		category: "isolation_breach",
		failures: []models.CheckResult{
			{CheckType: "isolation", Target: "a -> b", Status: models.StatusFail, Summary: "breach detected"},
		},
	}
	recs := recommendIsolationBreach(g, nil, models.RunnerContext{}, 1)
	if len(recs) != 1 {
		t.Fatalf("expected 1 recommendation, got %d", len(recs))
	}
	r := recs[0]
	if !strings.Contains(r.Remediation, "firewall should be blocking") {
		t.Errorf("expected generic remediation, got: %s", r.Remediation)
	}
	if r.SpecPatch != "" {
		t.Error("expected empty SpecPatch when no isolationCtx")
	}
}

func TestRecommendIsolationBreach_NoPolicyName(t *testing.T) {
	g := failureGroup{
		category: "isolation_breach",
		failures: []models.CheckResult{
			{CheckType: "isolation", Target: "a -> b", Status: models.StatusFail, Summary: "breach detected"},
		},
		isolationCtx: &isolationContext{
			fromZone:   "personal",
			toZone:     "gaming",
			policyName: "",
		},
	}
	spec := &intent.Spec{
		Networks: []intent.Network{
			{Name: "personal", CIDR: "10.0.20.0/24", Zone: "personal"},
		},
	}
	recs := recommendIsolationBreach(g, spec, models.RunnerContext{}, 1)
	if len(recs) != 1 {
		t.Fatalf("expected 1 recommendation, got %d", len(recs))
	}
	r := recs[0]
	// Default policy name should be used
	if !strings.Contains(r.SpecPatch, "personal-to-gaming-deny") {
		t.Errorf("expected default policy name in SpecPatch, got: %s", r.SpecPatch)
	}
}

func TestRecommendIsolationBreach_WithProbeName(t *testing.T) {
	g := failureGroup{
		category: "isolation_breach",
		failures: []models.CheckResult{
			{CheckType: "isolation", Target: "a -> b", Status: models.StatusFail, Summary: "breach detected"},
		},
		isolationCtx: &isolationContext{
			fromZone:   "personal",
			toZone:     "gaming",
			policyName: "my-policy",
			probeName:  "my-probe",
		},
	}
	spec := &intent.Spec{
		Networks: []intent.Network{
			{Name: "personal", CIDR: "10.0.20.0/24", Zone: "personal"},
		},
	}
	recs := recommendIsolationBreach(g, spec, models.RunnerContext{}, 1)
	if len(recs) != 1 {
		t.Fatalf("expected 1 recommendation, got %d", len(recs))
	}
	r := recs[0]
	if !strings.Contains(r.SpecPatch, "my-probe") {
		t.Errorf("expected probe name in SpecPatch, got: %s", r.SpecPatch)
	}
}

// =============================================================================
// recommendACLEnforcement — with spec, SpecPatch
// =============================================================================

func TestRecommendACLEnforcement_WithSpec(t *testing.T) {
	g := failureGroup{
		category: "acl_not_enforced",
		failures: []models.CheckResult{
			{CheckType: "acl_check", Target: "policy-a", Status: models.StatusFail, Summary: "not enforced"},
			{CheckType: "acl_check", Target: "policy-b", Status: models.StatusFail, Summary: "not enforced"},
		},
	}
	spec := &intent.Spec{
		Networks: []intent.Network{{Name: "personal", CIDR: "10.0.20.0/24", Zone: "personal"}},
	}
	recs := recommendACLEnforcement(g, spec, models.RunnerContext{}, 1)
	if len(recs) != 1 {
		t.Fatalf("expected 1 recommendation, got %d", len(recs))
	}
	r := recs[0]
	if !strings.Contains(r.SpecPatch, "policy-a") || !strings.Contains(r.SpecPatch, "policy-b") {
		t.Errorf("expected SpecPatch to mention both policies, got: %s", r.SpecPatch)
	}
}

func TestRecommendACLEnforcement_WithProbe(t *testing.T) {
	g := failureGroup{
		category: "acl_not_enforced",
		failures: []models.CheckResult{
			{CheckType: "acl_check", Target: "policy-a", Status: models.StatusFail, Summary: "not enforced"},
		},
		isolationCtx: &isolationContext{probeName: "my-probe"},
	}
	spec := &intent.Spec{
		Networks: []intent.Network{{Name: "personal", CIDR: "10.0.20.0/24", Zone: "personal"}},
	}
	recs := recommendACLEnforcement(g, spec, models.RunnerContext{}, 1)
	if len(recs) != 1 {
		t.Fatalf("expected 1 recommendation, got %d", len(recs))
	}
	r := recs[0]
	if !strings.Contains(r.SpecPatch, "my-probe") {
		t.Errorf("expected probe in SpecPatch, got: %s", r.SpecPatch)
	}
}

func TestRecommendACLEnforcement_NoSpec(t *testing.T) {
	g := failureGroup{
		category: "acl_not_enforced",
		failures: []models.CheckResult{
			{CheckType: "acl_check", Target: "policy-a", Status: models.StatusFail, Summary: "not enforced"},
		},
	}
	recs := recommendACLEnforcement(g, nil, models.RunnerContext{}, 1)
	if len(recs) != 1 {
		t.Fatalf("expected 1 recommendation, got %d", len(recs))
	}
	r := recs[0]
	if r.SpecPatch != "" {
		t.Error("expected empty SpecPatch when spec is nil")
	}
}

// =============================================================================
// recommendNetworkUnreachable — with spec, SpecPatch
// =============================================================================

func TestRecommendNetworkUnreachable_WithSpec(t *testing.T) {
	g := failureGroup{
		category: "network_unreachable",
		failures: []models.CheckResult{
			{CheckType: "subnet_discovery", Target: "media", Status: models.StatusError, Summary: "timed out"},
		},
	}
	spec := &intent.Spec{
		Networks: []intent.Network{
			{Name: "media", CIDR: "10.0.40.0/24", Zone: "media", Gateway: "192.168.40.1"},
		},
		Probes: []intent.Probe{{Name: "p", User: "admin"}},
	}
	runner := models.RunnerContext{Networks: []string{"personal"}}
	recs := recommendNetworkUnreachable(g, spec, runner, 1)
	if len(recs) != 1 {
		t.Fatalf("expected 1 recommendation, got %d", len(recs))
	}
	r := recs[0]
	if !strings.Contains(r.SpecPatch, "media-probe") {
		t.Errorf("expected probe suggestion in SpecPatch, got: %s", r.SpecPatch)
	}
	if !strings.Contains(r.SpecPatch, "192.168.40.1") {
		t.Errorf("expected gateway in SpecPatch, got: %s", r.SpecPatch)
	}
}

func TestRecommendNetworkUnreachable_NoNetworkInSpec(t *testing.T) {
	g := failureGroup{
		category: "network_unreachable",
		failures: []models.CheckResult{
			{CheckType: "subnet_discovery", Target: "unknown", Status: models.StatusError, Summary: "timed out"},
		},
	}
	spec := &intent.Spec{
		Networks: []intent.Network{
			{Name: "personal", CIDR: "10.0.20.0/24", Zone: "personal"},
		},
	}
	runner := models.RunnerContext{Networks: []string{"personal"}}
	recs := recommendNetworkUnreachable(g, spec, runner, 1)
	if len(recs) != 1 {
		t.Fatalf("expected 1 recommendation, got %d", len(recs))
	}
	r := recs[0]
	// No SpecPatch because network not found in spec
	if r.SpecPatch != "" {
		t.Error("expected empty SpecPatch when target network not in spec")
	}
}

func TestRecommendNetworkUnreachable_NoZoneOnNetwork(t *testing.T) {
	g := failureGroup{
		category: "network_unreachable",
		failures: []models.CheckResult{
			{CheckType: "subnet_discovery", Target: "flatnet", Status: models.StatusError, Summary: "timed out"},
		},
	}
	spec := &intent.Spec{
		Networks: []intent.Network{
			{Name: "flatnet", CIDR: "10.0.10.0/24"},
		},
		Probes: []intent.Probe{{Name: "p", User: "admin"}},
	}
	runner := models.RunnerContext{Networks: []string{"personal"}}
	recs := recommendNetworkUnreachable(g, spec, runner, 1)
	if len(recs) != 1 {
		t.Fatalf("expected 1 recommendation, got %d", len(recs))
	}
	r := recs[0]
	// Zone falls back to network name
	if !strings.Contains(r.SpecPatch, "flatnet") {
		t.Errorf("expected network name as zone fallback, got: %s", r.SpecPatch)
	}
}

// =============================================================================
// recommendVPN — no spec, no vpn name
// =============================================================================

func TestRecommendVPN_NoVPNName(t *testing.T) {
	g := failureGroup{
		category: "vpn_misconfigured",
		failures: []models.CheckResult{
			{CheckType: "vpn_route", Target: "10.0.0.1", Status: models.StatusFail, Summary: "not via tunnel"},
		},
	}
	recs := recommendVPN(g, nil, models.RunnerContext{}, 1)
	if len(recs) != 1 {
		t.Fatalf("expected 1 recommendation, got %d", len(recs))
	}
	r := recs[0]
	if !strings.Contains(r.Remediation, "VPN is active") {
		t.Errorf("expected generic remediation, got: %s", r.Remediation)
	}
}

func TestRecommendVPN_VPNNameButNotFoundInSpec(t *testing.T) {
	g := failureGroup{
		category: "vpn_misconfigured",
		failures: []models.CheckResult{
			{CheckType: "vpn_route", Target: "10.0.0.1", Status: models.StatusFail, Summary: "not via tunnel", Expected: map[string]interface{}{"vpn": "unknown-vpn"}},
		},
	}
	spec := &intent.Spec{
		VPN: []intent.VPNConfig{{Name: "other-vpn", Type: "wireguard"}},
	}
	recs := recommendVPN(g, spec, models.RunnerContext{}, 1)
	if len(recs) != 1 {
		t.Fatalf("expected 1 recommendation, got %d", len(recs))
	}
	r := recs[0]
	if !strings.Contains(r.Remediation, "unknown-vpn") {
		t.Errorf("expected vpn name in remediation, got: %s", r.Remediation)
	}
	// No SpecPatch because VPN not found in spec
	if r.SpecPatch != "" {
		t.Error("expected empty SpecPatch when VPN not in spec")
	}
}

func TestRecommendVPN_WithFullVPNConfig(t *testing.T) {
	g := failureGroup{
		category: "vpn_misconfigured",
		failures: []models.CheckResult{
			{CheckType: "vpn_route", Target: "10.0.0.1", Status: models.StatusFail, Summary: "not via tunnel", Expected: map[string]interface{}{"vpn": "my-vpn"}},
		},
	}
	spec := &intent.Spec{
		VPN: []intent.VPNConfig{
			{Name: "my-vpn", Type: "wireguard", Interface: "wg0", ExpectedRoutes: []string{"10.0.0.0/8"}, Mode: "split-tunnel"},
		},
	}
	recs := recommendVPN(g, spec, models.RunnerContext{}, 1)
	if len(recs) != 1 {
		t.Fatalf("expected 1 recommendation, got %d", len(recs))
	}
	r := recs[0]
	if !strings.Contains(r.Remediation, "wg0") {
		t.Errorf("expected interface in remediation, got: %s", r.Remediation)
	}
	if !strings.Contains(r.SpecPatch, "wg0") {
		t.Errorf("expected interface in SpecPatch, got: %s", r.SpecPatch)
	}
}

// =============================================================================
// recommendDiscovery — min violation
// =============================================================================

func TestRecommendDiscovery_MinViolation(t *testing.T) {
	g := failureGroup{
		category: "discovery_count",
		failures: []models.CheckResult{
			{
				CheckType:  "subnet_discovery",
				Target:     "personal",
				Status:     models.StatusFail,
				Summary:    "3 hosts discovered",
				Observed:   map[string]interface{}{"total": 3},
				Expected:   map[string]interface{}{"expect_hosts_min": 10},
				Violations: []string{"found 3 hosts, expected min 10"},
			},
		},
	}
	recs := recommendDiscovery(g, nil, models.RunnerContext{}, 1)
	if len(recs) != 1 {
		t.Fatalf("expected 1 recommendation, got %d", len(recs))
	}
	r := recs[0]
	if !strings.Contains(r.Title, "Fewer hosts") {
		t.Errorf("expected title about fewer hosts, got: %s", r.Title)
	}
	if !strings.Contains(r.SpecPatch, "expect_hosts_min") {
		t.Errorf("expected expect_hosts_min in SpecPatch, got: %s", r.SpecPatch)
	}
}

func TestRecommendDiscovery_BothMaxAndMin(t *testing.T) {
	g := failureGroup{
		category: "discovery_count",
		failures: []models.CheckResult{
			{
				CheckType:  "subnet_discovery",
				Target:     "personal",
				Status:     models.StatusFail,
				Summary:    "25 hosts discovered",
				Observed:   map[string]interface{}{"total": 25},
				Expected:   map[string]interface{}{"expect_hosts_max": 20, "expect_hosts_min": 5},
				Violations: []string{"found 25 hosts, expected max 20", "found 25 hosts, expected min 5"},
			},
		},
	}
	recs := recommendDiscovery(g, nil, models.RunnerContext{}, 1)
	// Should generate separate recs for max and min violations
	if len(recs) != 2 {
		t.Fatalf("expected 2 recommendations (max + min), got %d", len(recs))
	}
}

func TestRecommendDiscovery_MinViolationZeroHosts(t *testing.T) {
	g := failureGroup{
		category: "discovery_count",
		failures: []models.CheckResult{
			{
				CheckType:  "subnet_discovery",
				Target:     "personal",
				Status:     models.StatusFail,
				Summary:    "0 hosts discovered",
				Observed:   map[string]interface{}{"total": 0},
				Expected:   map[string]interface{}{"expect_hosts_min": 5},
				Violations: []string{"found 0 hosts, expected min 5"},
			},
		},
	}
	recs := recommendDiscovery(g, nil, models.RunnerContext{}, 1)
	if len(recs) != 1 {
		t.Fatalf("expected 1 recommendation, got %d", len(recs))
	}
	r := recs[0]
	// newMin should be max(1, 0+1) = 1
	if !strings.Contains(r.SpecPatch, "expect_hosts_min: 1") {
		t.Errorf("expected lowered min to 1, got: %s", r.SpecPatch)
	}
}

// =============================================================================
// recommendHostDown
// =============================================================================

func TestRecommendHostDown_WithSpec(t *testing.T) {
	minVal := 5
	g := failureGroup{
		category: "host_down_or_filtered",
		failures: []models.CheckResult{
			{CheckType: "subnet_discovery", Target: "personal", Status: models.StatusWarn, Summary: "0 hosts", Observed: map[string]interface{}{"total": 0}},
		},
	}
	spec := &intent.Spec{
		Networks: []intent.Network{{Name: "personal", CIDR: "10.0.20.0/24", Zone: "personal"}},
		Assertions: []intent.Assertion{
			{Type: "subnet_discovery", Network: "personal", ExpectHostsMin: &minVal},
		},
	}
	runner := models.RunnerContext{Networks: []string{"personal"}}
	recs := recommendHostDown(g, spec, runner, 1)
	if len(recs) != 1 {
		t.Fatalf("expected 1 recommendation, got %d", len(recs))
	}
	r := recs[0]
	if r.SpecPatch == "" {
		t.Error("expected non-empty SpecPatch when assertion found")
	}
}

func TestRecommendHostDown_NoMatchingAssertion(t *testing.T) {
	g := failureGroup{
		category: "host_down_or_filtered",
		failures: []models.CheckResult{
			{CheckType: "subnet_discovery", Target: "unknown", Status: models.StatusWarn, Summary: "0 hosts"},
		},
	}
	spec := &intent.Spec{
		Networks: []intent.Network{{Name: "personal", CIDR: "10.0.20.0/24", Zone: "personal"}},
	}
	runner := models.RunnerContext{Networks: []string{"personal"}}
	recs := recommendHostDown(g, spec, runner, 1)
	if len(recs) != 1 {
		t.Fatalf("expected 1 recommendation, got %d", len(recs))
	}
	r := recs[0]
	// No assertion found, so no SpecPatch
	if r.SpecPatch != "" {
		t.Error("expected empty SpecPatch when no matching assertion")
	}
}

// =============================================================================
// recommendDNSFailure — with observed resolved_ip
// =============================================================================

func TestRecommendDNSFailure_WithObservedIP(t *testing.T) {
	g := failureGroup{
		category: "dns_failure",
		failures: []models.CheckResult{
			{
				CheckType: "dns_check", Target: "nas.home.lan", Status: models.StatusFail,
				Summary: "resolved to wrong IP",
				Observed: map[string]interface{}{"resolved_ip": "10.0.0.5"},
				Expected: map[string]interface{}{"expect_ip": "10.0.0.10"},
			},
		},
	}
	spec := &intent.Spec{
		Networks: []intent.Network{{Name: "personal", CIDR: "10.0.20.0/24", Zone: "personal"}},
	}
	runner := models.RunnerContext{Networks: []string{"personal"}}
	recs := recommendDNSFailure(g, spec, runner, 1)
	if len(recs) != 1 {
		t.Fatalf("expected 1 recommendation, got %d", len(recs))
	}
	r := recs[0]
	if !strings.Contains(r.SpecPatch, "10.0.0.5") {
		t.Errorf("expected observed IP in SpecPatch, got: %s", r.SpecPatch)
	}
}

func TestRecommendDNSFailure_NoObservedIP(t *testing.T) {
	g := failureGroup{
		category: "dns_failure",
		failures: []models.CheckResult{
			{CheckType: "dns_check", Target: "nas.home.lan", Status: models.StatusFail, Summary: "no resolution"},
		},
	}
	spec := &intent.Spec{
		Networks: []intent.Network{{Name: "personal", CIDR: "10.0.20.0/24", Zone: "personal"}},
	}
	runner := models.RunnerContext{Networks: []string{"personal"}}
	recs := recommendDNSFailure(g, spec, runner, 1)
	if len(recs) != 1 {
		t.Fatalf("expected 1 recommendation, got %d", len(recs))
	}
	r := recs[0]
	if r.SpecPatch != "" {
		t.Error("expected empty SpecPatch when no observed IP")
	}
}

// =============================================================================
// recommendServiceDown — with observed ports
// =============================================================================

func TestRecommendServiceDown_WithObservedPorts(t *testing.T) {
	g := failureGroup{
		category: "service_down",
		failures: []models.CheckResult{
			{
				CheckType: "port_check", Target: "10.0.50.55", Status: models.StatusFail,
				Summary: "port check failed",
				Observed: map[string]interface{}{"ports": "8096 closed"},
			},
		},
	}
	spec := &intent.Spec{
		Networks: []intent.Network{{Name: "personal", CIDR: "10.0.20.0/24", Zone: "personal"}},
	}
	runner := models.RunnerContext{Networks: []string{"personal"}}
	recs := recommendServiceDown(g, spec, runner, 1)
	if len(recs) != 1 {
		t.Fatalf("expected 1 recommendation, got %d", len(recs))
	}
	r := recs[0]
	if !strings.Contains(r.SpecPatch, "8096") {
		t.Errorf("expected observed ports in SpecPatch, got: %s", r.SpecPatch)
	}
}

func TestRecommendServiceDown_NoObservedPorts(t *testing.T) {
	g := failureGroup{
		category: "service_down",
		failures: []models.CheckResult{
			{CheckType: "port_check", Target: "10.0.50.55", Status: models.StatusFail, Summary: "port check failed"},
		},
	}
	spec := &intent.Spec{
		Networks: []intent.Network{{Name: "personal", CIDR: "10.0.20.0/24", Zone: "personal"}},
	}
	runner := models.RunnerContext{Networks: []string{"personal"}}
	recs := recommendServiceDown(g, spec, runner, 1)
	if len(recs) != 1 {
		t.Fatalf("expected 1 recommendation, got %d", len(recs))
	}
	r := recs[0]
	if !strings.Contains(r.SpecPatch, "service not responding") {
		t.Errorf("expected generic message in SpecPatch, got: %s", r.SpecPatch)
	}
}

// =============================================================================
// recommendNetworkDegraded — with observed values
// =============================================================================

func TestRecommendNetworkDegraded_WithObservedValues(t *testing.T) {
	g := failureGroup{
		category: "network_degraded",
		failures: []models.CheckResult{
			{
				CheckType: "network_health", Target: "10.0.20.254", Status: models.StatusFail,
				Summary: "latency and loss",
				Observed: map[string]interface{}{"latency_ms": 500, "loss_pct": 15},
				Expected: map[string]interface{}{"expect_latency_ms": 100, "expect_loss_pct": 5},
			},
		},
	}
	spec := &intent.Spec{
		Networks: []intent.Network{{Name: "personal", CIDR: "10.0.20.0/24", Zone: "personal"}},
	}
	runner := models.RunnerContext{Networks: []string{"personal"}}
	recs := recommendNetworkDegraded(g, spec, runner, 1)
	if len(recs) != 1 {
		t.Fatalf("expected 1 recommendation, got %d", len(recs))
	}
	r := recs[0]
	if !strings.Contains(r.SpecPatch, "expect_latency_ms") {
		t.Errorf("expected latency threshold in SpecPatch, got: %s", r.SpecPatch)
	}
	if !strings.Contains(r.SpecPatch, "expect_loss_pct") {
		t.Errorf("expected loss threshold in SpecPatch, got: %s", r.SpecPatch)
	}
}

func TestRecommendNetworkDegraded_NoObservedValues(t *testing.T) {
	g := failureGroup{
		category: "network_degraded",
		failures: []models.CheckResult{
			{CheckType: "network_health", Target: "10.0.20.254", Status: models.StatusFail, Summary: "degraded"},
		},
	}
	spec := &intent.Spec{
		Networks: []intent.Network{{Name: "personal", CIDR: "10.0.20.0/24", Zone: "personal"}},
	}
	runner := models.RunnerContext{Networks: []string{"personal"}}
	recs := recommendNetworkDegraded(g, spec, runner, 1)
	if len(recs) != 1 {
		t.Fatalf("expected 1 recommendation, got %d", len(recs))
	}
	r := recs[0]
	// No observed values means no patch lines (both old values are 0)
	// The recommendation should still have a non-empty description
	if r.Description == "" {
		t.Error("expected non-empty description for network_degraded recommendation")
	}
}

// =============================================================================
// 8-Recommendation Cap
// =============================================================================

func TestGenerateRecommendations_CapAtEight(t *testing.T) {
	failures := []models.CheckResult{
		{CheckType: "isolation", Target: "a -> b", Status: models.StatusFail, Summary: "isolation violation: a can reach b", Violations: []string{"expected deny"}},
		{CheckType: "acl_check", Target: "p1", Status: models.StatusFail, Summary: "not enforced"},
		{CheckType: "subnet_discovery", Target: "net1", Status: models.StatusError, Summary: "timed out"},
		{CheckType: "vpn_route", Target: "10.0.0.1", Status: models.StatusFail, Summary: "not via tunnel"},
		{CheckType: "subnet_discovery", Target: "net2", Status: models.StatusFail, Summary: "35 hosts", Observed: map[string]interface{}{"total": 35}, Violations: []string{"found 35 hosts, expected max 20"}},
		{CheckType: "dns_check", Target: "x.lan", Status: models.StatusFail, Summary: "wrong ip"},
		{CheckType: "port_check", Target: "1.1.1.1", Status: models.StatusFail, Summary: "port closed"},
		{CheckType: "network_health", Target: "2.2.2.2", Status: models.StatusFail, Summary: "slow"},
		{CheckType: "isolation", Target: "c -> d", Status: models.StatusFail, Summary: "isolation violation: c can reach d", Violations: []string{"expected deny"}},
		{CheckType: "subnet_discovery", Target: "net3", Status: models.StatusFail, Summary: "0 hosts", Observed: map[string]interface{}{"total": 0}},
	}
	spec := &intent.Spec{
		Networks: []intent.Network{
			{Name: "a", CIDR: "192.168.1.0/24", Zone: "a"},
			{Name: "b", CIDR: "192.168.2.0/24", Zone: "b"},
			{Name: "c", CIDR: "192.168.3.0/24", Zone: "c"},
			{Name: "d", CIDR: "192.168.4.0/24", Zone: "d"},
		},
	}
	runner := models.RunnerContext{Networks: []string{"a", "c"}}
	recs, err := GenerateRecommendations(failures, spec, runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(recs) > 8 {
		t.Errorf("expected at most 8 recommendations, got %d", len(recs))
	}
}

// =============================================================================
// classifyServiceCheck — ERROR path
// =============================================================================

func TestClassifyServiceCheck_ErrorStatus(t *testing.T) {
	failures := []models.CheckResult{
		{CheckType: "port_check", Target: "10.0.50.55", Status: models.StatusError, Summary: "connection refused"},
	}
	recs, err := GenerateRecommendations(failures, nil, models.RunnerContext{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, r := range recs {
		if r.Category == "network_unreachable" {
			found = true
		}
	}
	if !found {
		t.Error("expected network_unreachable for port_check ERROR status")
	}
}

// =============================================================================
// classifyHealthCheck — ERROR path
// =============================================================================

func TestClassifyHealthCheck_ErrorStatus(t *testing.T) {
	failures := []models.CheckResult{
		{CheckType: "network_health", Target: "10.0.20.254", Status: models.StatusError, Summary: "host unreachable"},
	}
	recs, err := GenerateRecommendations(failures, nil, models.RunnerContext{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, r := range recs {
		if r.Category == "network_unreachable" {
			found = true
		}
	}
	if !found {
		t.Error("expected network_unreachable for network_health ERROR status")
	}
}

// =============================================================================
// ipInCIDR edge cases
// =============================================================================

func TestIpInCidr_EmptyCIDR(t *testing.T) {
	if ipInCIDR("192.168.1.1", "") {
		t.Error("expected false for empty CIDR")
	}
}

func TestIpInCidr_InvalidIP(t *testing.T) {
	if ipInCIDR("not-an-ip", "192.168.1.0/24") {
		t.Error("expected false for invalid IP")
	}
}

func TestIpInCidr_InvalidCIDR(t *testing.T) {
	if ipInCIDR("192.168.1.1", "not-a-cidr") {
		t.Error("expected false for invalid CIDR")
	}
}

// =============================================================================
// existingProbeUser
// =============================================================================

func TestExistingProbeUser(t *testing.T) {
	// No probes
	spec := &intent.Spec{}
	user := existingProbeUser(spec)
	if user != "<user>" {
		t.Errorf("expected <user>, got %s", user)
	}

	// Nil spec
	user = existingProbeUser(nil)
	if user != "<user>" {
		t.Errorf("expected <user> for nil spec, got %s", user)
	}

	// Probe with user
	spec = &intent.Spec{
		Probes: []intent.Probe{{Name: "p", User: "admin"}},
	}
	user = existingProbeUser(spec)
	if user != "admin" {
		t.Errorf("expected admin, got %s", user)
	}

	// Probe without user
	spec = &intent.Spec{
		Probes: []intent.Probe{{Name: "p"}},
	}
	user = existingProbeUser(spec)
	if user != "<user>" {
		t.Errorf("expected <user> for empty user, got %s", user)
	}
}

// =============================================================================
// networkForZone
// =============================================================================

func TestNetworkForZone(t *testing.T) {
	spec := &intent.Spec{
		Networks: []intent.Network{
			{Name: "personal", CIDR: "10.0.20.0/24", Zone: "home"},
			{Name: "guest", CIDR: "10.0.40.0/24", Zone: "guest"},
		},
	}

	net := networkForZone(spec, "home")
	if net == nil || net.Name != "personal" {
		t.Errorf("expected personal network, got %v", net)
	}

	net = networkForZone(spec, "nonexistent")
	if net != nil {
		t.Error("expected nil for nonexistent zone")
	}

	net = networkForZone(nil, "home")
	if net != nil {
		t.Error("expected nil for nil spec")
	}
}

// =============================================================================
// deduplicateStrings edge cases
// =============================================================================

func TestDeduplicateStrings(t *testing.T) {
	// Duplicates
	result := deduplicateStrings([]string{"a", "b", "a", "c", "b"})
	expected := []string{"a", "b", "c"}
	if len(result) != len(expected) {
		t.Fatalf("expected %d, got %d", len(expected), len(result))
	}
	for i := range expected {
		if result[i] != expected[i] {
			t.Errorf("result[%d] = %q, want %q", i, result[i], expected[i])
		}
	}

	// Empty strings removed
	result = deduplicateStrings([]string{"", "a", "", "b"})
	if len(result) != 2 || result[0] != "a" || result[1] != "b" {
		t.Errorf("expected [a, b], got %v", result)
	}

	// Empty input
	result = deduplicateStrings([]string{})
	if len(result) != 0 {
		t.Errorf("expected empty, got %v", result)
	}

	// All empty
	result = deduplicateStrings([]string{"", "", ""})
	if len(result) != 0 {
		t.Errorf("expected empty, got %v", result)
	}
}

// =============================================================================
// lookupAssertion
// =============================================================================

func TestLookupAssertion(t *testing.T) {
	minVal := 5
	spec := &intent.Spec{
		Assertions: []intent.Assertion{
			{Type: "subnet_discovery", Network: "personal", ExpectHostsMin: &minVal},
			{Type: "port_check", Target: "192.168.1.1"},
		},
	}

	// Find by network
	a := lookupAssertion(spec, "personal", "", "subnet_discovery")
	if a == nil {
		t.Error("expected assertion found by network")
	}

	// Find by target
	a = lookupAssertion(spec, "", "192.168.1.1", "port_check")
	if a == nil {
		t.Error("expected assertion found by target")
	}

	// Not found
	a = lookupAssertion(spec, "unknown", "", "subnet_discovery")
	if a != nil {
		t.Error("expected nil for unknown network")
	}

	// Nil spec
	a = lookupAssertion(nil, "personal", "", "subnet_discovery")
	if a != nil {
		t.Error("expected nil for nil spec")
	}
}

// =============================================================================
// Mixed failure types in vantage_point group
// =============================================================================

func TestVantagePoint_MixedFailureTypes(t *testing.T) {
	failures := []models.CheckResult{
		{CheckType: "isolation", Target: "personal -> gaming", Status: models.StatusFail, Summary: "isolation violation: personal can reach gaming", Violations: []string{"expected deny"}},
		{CheckType: "subnet_discovery", Target: "media", Status: models.StatusError, Summary: "timed out"},
	}
	spec := &intent.Spec{
		Networks: []intent.Network{
			{Name: "personal", CIDR: "10.0.20.0/24", Zone: "personal", Gateway: "10.0.20.1"},
			{Name: "gaming", CIDR: "10.0.30.0/24", Zone: "gaming"},
			{Name: "media", CIDR: "10.0.40.0/24", Zone: "media"},
		},
	}
	runner := models.RunnerContext{Networks: []string{"gaming"}}
	recs, err := GenerateRecommendations(failures, spec, runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Both should be classified as vantage_point
	found := false
	for _, r := range recs {
		if r.Category == "vantage_point" {
			found = true
		}
	}
	if !found {
		t.Error("expected vantage_point for mixed failure types")
	}
}

// =============================================================================
// parseIsolationFromSummary — additional patterns
// =============================================================================

func TestParseIsolationFromSummary_AdditionalPatterns(t *testing.T) {
	tests := []struct {
		name string
		input string
		wantFrom string
		wantTo string
	}{
		{"isolation confirmed", "isolation confirmed: iot can reach lan", "iot", "lan"},
		{"connectivity confirmed", "connectivity confirmed: a can reach b", "a", "b"},
		{"expected deny marker", "expected deny: iot can reach lan", ": iot", "lan"},
		{"no can reach", "some random text", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			from, to := parseIsolationFromSummary(tt.input)
			if from != tt.wantFrom || to != tt.wantTo {
				t.Errorf("parseIsolationFromSummary(%q) = (%q, %q); want (%q, %q)", tt.input, from, to, tt.wantFrom, tt.wantTo)
			}
		})
	}
}

// =============================================================================
// parseIsolationTarget edge cases
// =============================================================================

func TestParseIsolationTarget_EdgeCases(t *testing.T) {
	tests := []struct {
		input string
		wantFrom string
		wantTo string
	}{
		{"personal -> gaming", "personal", "gaming"},
		{"a->b", "", ""},
		{" -> ", "", ""},
		{"personal -> gaming -> extra", "", ""},
	}
	for _, tt := range tests {
		from, to := parseIsolationTarget(tt.input)
		if from != tt.wantFrom || to != tt.wantTo {
			t.Errorf("parseIsolationTarget(%q) = (%q, %q); want (%q, %q)", tt.input, from, to, tt.wantFrom, tt.wantTo)
		}
	}
}

// =============================================================================
// recommendNetworkDegraded_NoExpectedValues
// =============================================================================

func TestRecommendNetworkDegraded_NoExpectedValues(t *testing.T) {
	g := failureGroup{
		category: "network_degraded",
		failures: []models.CheckResult{
			{CheckType: "network_health", Target: "1.2.3.4", Status: models.StatusFail, Summary: "slow"},
		},
	}
	spec := &intent.Spec{
		Networks: []intent.Network{{Name: "personal", CIDR: "10.0.20.0/24", Zone: "personal"}},
	}
	runner := models.RunnerContext{Networks: []string{"personal"}}
	recs := recommendNetworkDegraded(g, spec, runner, 1)
	if len(recs) != 1 {
		t.Fatalf("expected 1 recommendation, got %d", len(recs))
	}
}

// =============================================================================
// classifyDiscovery_UnreachableSummary
// =============================================================================

func TestClassifyDiscovery_UnreachableSummary(t *testing.T) {
	failures := []models.CheckResult{
		{CheckType: "subnet_discovery", Target: "media", Status: models.StatusError, Summary: "network unreachable for 10.0.40.0/24"},
	}
	spec := &intent.Spec{
		Networks: []intent.Network{
			{Name: "media", CIDR: "10.0.40.0/24", Zone: "media"},
			{Name: "personal", CIDR: "10.0.20.0/24", Zone: "personal"},
		},
	}
	runner := models.RunnerContext{Networks: []string{"personal"}}
	recs, err := GenerateRecommendations(failures, spec, runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, r := range recs {
		if r.Category == "vantage_point" {
			found = true
		}
	}
	if !found {
		t.Error("expected vantage_point for unreachable summary when runner not in target network")
	}
}

// =============================================================================
// classifyDiscovery_NoSpec
// =============================================================================

func TestClassifyDiscovery_NoSpec(t *testing.T) {
	failures := []models.CheckResult{
		{CheckType: "subnet_discovery", Target: "media", Status: models.StatusError, Summary: "timed out"},
	}
	recs, err := GenerateRecommendations(failures, nil, models.RunnerContext{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, r := range recs {
		if r.Category == "network_unreachable" {
			found = true
		}
	}
	if !found {
		t.Error("expected network_unreachable when spec is nil")
	}
}

// =============================================================================
// classifyDiscovery_DeadlineExceeded
// =============================================================================

func TestClassifyDiscovery_DeadlineExceeded(t *testing.T) {
	failures := []models.CheckResult{
		{CheckType: "subnet_discovery", Target: "media", Status: models.StatusError, Summary: "context deadline exceeded"},
	}
	spec := &intent.Spec{
		Networks: []intent.Network{
			{Name: "media", CIDR: "10.0.40.0/24", Zone: "media"},
			{Name: "personal", CIDR: "10.0.20.0/24", Zone: "personal"},
		},
	}
	runner := models.RunnerContext{Networks: []string{"personal"}}
	recs, err := GenerateRecommendations(failures, spec, runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, r := range recs {
		if r.Category == "vantage_point" {
			found = true
		}
	}
	if !found {
		t.Error("expected vantage_point for deadline exceeded when runner not in target network")
	}
}

// =============================================================================
// classifyDiscovery_Float64HostCount
// =============================================================================

func TestClassifyDiscovery_Float64HostCount(t *testing.T) {
	failures := []models.CheckResult{
		{
			CheckType: "subnet_discovery",
			Target:    "personal",
			Status:    models.StatusWarn,
			Summary:   "0 hosts discovered",
			Observed:  map[string]interface{}{"total": float64(0)},
		},
	}
	spec := &intent.Spec{
		Networks: []intent.Network{
			{Name: "personal", CIDR: "10.0.20.0/24", Zone: "personal"},
		},
	}
	runner := models.RunnerContext{Networks: []string{"personal"}}
	recs, err := GenerateRecommendations(failures, spec, runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, r := range recs {
		if r.Category == "host_down_or_filtered" {
			found = true
		}
	}
	if !found {
		t.Error("expected host_down_or_filtered with float64 host count")
	}
}

// =============================================================================
// recommendDiscovery_MaxViolationWithFloat64Observed
// =============================================================================

func TestRecommendDiscovery_MaxViolationFloat64(t *testing.T) {
	g := failureGroup{
		category: "discovery_count",
		failures: []models.CheckResult{
			{
				CheckType:  "subnet_discovery",
				Target:     "personal",
				Status:     models.StatusFail,
				Summary:    "30 hosts discovered",
				Observed:   map[string]interface{}{"total": float64(30)},
				Expected:   map[string]interface{}{"expect_hosts_max": int(20)},
				Violations: []string{"found 30 hosts, expected max 20"},
			},
		},
	}
	recs := recommendDiscovery(g, nil, models.RunnerContext{}, 1)
	if len(recs) != 1 {
		t.Fatalf("expected 1 recommendation, got %d", len(recs))
	}
	r := recs[0]
	if !strings.Contains(r.Title, "More hosts") {
		t.Errorf("expected title about more hosts, got: %s", r.Title)
	}
	// Should show bumped value: 30 + 5 = 35
	if !strings.Contains(r.SpecPatch, "35") {
		t.Errorf("expected bumped max 35 in SpecPatch, got: %s", r.SpecPatch)
	}
}

// =============================================================================
// recommendVantagePoint_RunnerLocation
// =============================================================================

func TestRecommendVantagePoint_RunnerLocation(t *testing.T) {
	g := failureGroup{
		category: "vantage_point",
		failures: []models.CheckResult{
			{CheckType: "isolation", Target: "personal -> gaming", Status: models.StatusFail, Summary: "isolation violation: personal can reach gaming"},
		},
	}
	spec := &intent.Spec{
		Networks: []intent.Network{
			{Name: "personal", CIDR: "10.0.20.0/24", Zone: "personal"},
			{Name: "gaming", CIDR: "10.0.30.0/24", Zone: "gaming"},
		},
	}
	// Runner with multiple networks
	runner := models.RunnerContext{Networks: []string{"lan", "dmz"}}
	recs := recommendVantagePoint(g, spec, runner, 1)
	if len(recs) != 1 {
		t.Fatalf("expected 1 recommendation, got %d", len(recs))
	}
	r := recs[0]
	if !strings.Contains(r.Description, "lan") || !strings.Contains(r.Description, "dmz") {
		t.Errorf("expected description to mention runner networks, got: %s", r.Description)
	}
}

func TestRecommendVantagePoint_EmptyRunnerNetworks(t *testing.T) {
	g := failureGroup{
		category: "vantage_point",
		failures: []models.CheckResult{
			{CheckType: "isolation", Target: "personal -> gaming", Status: models.StatusFail, Summary: "isolation violation: personal can reach gaming"},
		},
	}
	spec := &intent.Spec{
		Networks: []intent.Network{
			{Name: "personal", CIDR: "10.0.20.0/24", Zone: "personal"},
			{Name: "gaming", CIDR: "10.0.30.0/24", Zone: "gaming"},
		},
	}
	runner := models.RunnerContext{Networks: []string{}}
	recs := recommendVantagePoint(g, spec, runner, 1)
	if len(recs) != 1 {
		t.Fatalf("expected 1 recommendation, got %d", len(recs))
	}
	r := recs[0]
	if !strings.Contains(r.Description, "your current adapter") {
		t.Errorf("expected fallback to current adapter, got: %s", r.Description)
	}
}

// =============================================================================
// buildIsolationContext_FromNetworkName
// =============================================================================

func TestBuildIsolationContext_FromNetworkName(t *testing.T) {
	spec := &intent.Spec{
		Networks: []intent.Network{
			{Name: "personal", CIDR: "10.0.20.0/24", Zone: "home"},
		},
	}
	ctx := buildIsolationContext("personal", "gaming", spec, models.RunnerContext{})
	if ctx == nil {
		t.Fatal("expected non-nil context")
	}
	// fromNetworkNames should include "personal" (matched by n.Name == from)
	if len(ctx.fromNetworkNames) != 1 || ctx.fromNetworkNames[0] != "personal" {
		t.Errorf("expected fromNetworkNames [personal], got %v", ctx.fromNetworkNames)
	}
}

// =============================================================================
// buildIsolationContext_ProbeHostInCIDR
// =============================================================================

func TestBuildIsolationContext_ProbeHostInCIDR(t *testing.T) {
	spec := &intent.Spec{
		Networks: []intent.Network{
			{Name: "personal", CIDR: "10.0.20.0/24", Zone: "personal"},
		},
		Probes: []intent.Probe{
			{Name: "cidr-probe", Host: "10.0.20.100"},
		},
	}
	ctx := buildIsolationContext("personal", "gaming", spec, models.RunnerContext{})
	if ctx == nil {
		t.Fatal("expected non-nil context")
	}
	if !ctx.probeInFromZone {
		t.Error("expected probeInFromZone via CIDR match")
	}
	if ctx.probeName != "cidr-probe" {
		t.Errorf("expected probeName cidr-probe, got %s", ctx.probeName)
	}
}

// =============================================================================
// buildIsolationContext_ProbeHostNotInCIDR
// =============================================================================

func TestBuildIsolationContext_ProbeHostNotInCIDR(t *testing.T) {
	spec := &intent.Spec{
		Networks: []intent.Network{
			{Name: "personal", CIDR: "10.0.20.0/24", Zone: "personal"},
		},
		Probes: []intent.Probe{
			{Name: "other-probe", Host: "10.0.0.1"},
		},
	}
	ctx := buildIsolationContext("personal", "gaming", spec, models.RunnerContext{})
	if ctx == nil {
		t.Fatal("expected non-nil context")
	}
	if ctx.probeInFromZone {
		t.Error("expected probeInFromZone to be false when host not in CIDR")
	}
}

// =============================================================================
// buildIsolationContext_RunnerNetworkInFromZone
// =============================================================================

func TestBuildIsolationContext_RunnerNetworkInFromZone(t *testing.T) {
	spec := &intent.Spec{
		Networks: []intent.Network{
			{Name: "personal", CIDR: "10.0.20.0/24", Zone: "personal"},
			{Name: "gaming", CIDR: "10.0.30.0/24", Zone: "gaming"},
		},
	}
	runner := models.RunnerContext{Networks: []string{"personal"}}
	ctx := buildIsolationContext("personal", "gaming", spec, runner)
	if ctx == nil {
		t.Fatal("expected non-nil context")
	}
	if !ctx.runnerInFrom {
		t.Error("expected runnerInFrom to be true")
	}
}

// =============================================================================
// buildIsolationContext_MultipleNetworksInFromZone
// =============================================================================

func TestBuildIsolationContext_MultipleNetworksInFromZone(t *testing.T) {
	spec := &intent.Spec{
		Networks: []intent.Network{
			{Name: "personal", CIDR: "10.0.20.0/24", Zone: "home"},
			{Name: "work", CIDR: "10.0.30.0/24", Zone: "home"},
			{Name: "guest", CIDR: "10.0.40.0/24", Zone: "guest"},
		},
	}
	ctx := buildIsolationContext("home", "guest", spec, models.RunnerContext{})
	if ctx == nil {
		t.Fatal("expected non-nil context")
	}
	if len(ctx.fromNetworkNames) != 2 {
		t.Errorf("expected 2 networks in from zone, got %d", len(ctx.fromNetworkNames))
	}
}