package recommendations

import (
	"strings"
	"testing"

	"github.com/velasco-jp/nyx/internal/intent"
	"github.com/velasco-jp/nyx/internal/models"
)

func TestGenerateRecommendations_NoFailures(t *testing.T) {
	recs, err := GenerateRecommendations(nil, nil, models.RunnerContext{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(recs) != 0 {
		t.Errorf("expected 0 recommendations, got %d", len(recs))
	}
}

func TestGenerateRecommendations_VantagePointAggregation(t *testing.T) {
	// Simulate the real audit: 4 isolation failures from trusted, runner in trusted.
	// All should be aggregated into ONE vantage_point recommendation.
	failures := []models.CheckResult{
		{
			CheckType: "isolation",
			Target:    "personal -> gaming",
			Status:    models.StatusFail,
			Summary:   "isolation violation: personal can reach gaming",
			Violations: []string{"expected deny but traffic is reachable"},
		},
		{
			CheckType: "isolation",
			Target:    "personal -> iot",
			Status:    models.StatusFail,
			Summary:   "isolation violation: personal can reach iot",
			Violations: []string{"expected deny but traffic is reachable"},
		},
		{
			CheckType: "isolation",
			Target:    "gaming -> personal",
			Status:    models.StatusFail,
			Summary:   "isolation violation: gaming can reach personal",
			Violations: []string{"expected deny but traffic is reachable"},
		},
		{
			CheckType: "isolation",
			Target:    "personal -> trusted",
			Status:    models.StatusFail,
			Summary:   "isolation violation: personal can reach trusted",
			Violations: []string{"expected deny but traffic is reachable"},
		},
	}

	spec := &intent.Spec{
		Networks: []intent.Network{
			{Name: "trusted", CIDR: "192.168.0.0/24", Zone: "trusted"},
			{Name: "personal", CIDR: "192.168.20.0/24", Zone: "personal"},
			{Name: "gaming", CIDR: "192.168.30.0/24", Zone: "gaming"},
			{Name: "iot", CIDR: "192.168.60.0/24", Zone: "iot"},
		},
		Policies: []intent.Policy{
			{Name: "personal-isolation", From: "personal", To: "gaming", Action: "deny"},
			{Name: "game-isolation", From: "gaming", To: "personal", Action: "deny"},
			{Name: "trusted-protection", From: "personal", To: "trusted", Action: "deny"},
		},
	}

	runner := models.RunnerContext{
		Networks: []string{"trusted"}, // runner is in trusted
	}

	recs, err := GenerateRecommendations(failures, spec, runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should produce exactly 1 vantage_point recommendation (aggregated)
	if len(recs) == 0 {
		t.Fatal("expected at least one recommendation")
	}

	foundVantagePoint := false
	for _, r := range recs {
		if r.Category == "vantage_point" {
			foundVantagePoint = true

			// Should mention the runner is in trusted
			if !strings.Contains(r.Description, "trusted") {
				t.Errorf("expected description to mention runner is in trusted, got: %s", r.Description)
			}

			// Should mention the needed zones
			if !strings.Contains(r.Description, "gaming") && !strings.Contains(r.Description, "personal") {
				t.Errorf("expected description to mention needed zones, got: %s", r.Description)
			}

			// Should suggest adding a probe
			if !strings.Contains(r.Remediation, "probe") && !strings.Contains(r.Remediation, "runner:") {
				t.Errorf("expected remediation to suggest probe or runner, got: %s", r.Remediation)
			}

			// Should have a SpecPatch with probe YAML
			if r.SpecPatch == "" {
				t.Error("expected SpecPatch for probe suggestion when no probe is declared")
			}
		}
	}

	if !foundVantagePoint {
		t.Error("did not find vantage_point recommendation — this is the most critical category")
	}
}

func TestGenerateRecommendations_IsolationBreach(t *testing.T) {
	// When the runner IS in the source zone and the check fails, it's a real breach.
	failures := []models.CheckResult{
		{
			CheckType: "isolation",
			Target:    "gaming -> personal",
			Status:    models.StatusFail,
			Summary:   "isolation violation: gaming can reach personal",
			Violations: []string{"expected deny but traffic is reachable"},
		},
	}

	spec := &intent.Spec{
		Networks: []intent.Network{
			{Name: "gaming", CIDR: "192.168.30.0/24", Zone: "gaming"},
			{Name: "personal", CIDR: "192.168.20.0/24", Zone: "personal"},
		},
		Policies: []intent.Policy{
			{Name: "game-isolation", From: "gaming", To: "personal", Action: "deny"},
		},
	}

	runner := models.RunnerContext{
		Networks: []string{"gaming"}, // runner IS in gaming
	}

	recs, err := GenerateRecommendations(failures, spec, runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, r := range recs {
		if r.Category == "isolation_breach" {
			found = true
			if !strings.Contains(r.Remediation, "game-isolation") {
				t.Errorf("expected remediation to mention the policy, got: %s", r.Remediation)
			}
		}
	}

	if !found {
		t.Error("expected isolation_breach recommendation when runner is in source zone")
	}
}

func TestGenerateRecommendations_ProbeAlreadyDeclared(t *testing.T) {
	// When a probe exists in the needed zone, the recommendation should tell the user to use it.
	failures := []models.CheckResult{
		{
			CheckType: "isolation",
			Target:    "personal -> gaming",
			Status:    models.StatusFail,
			Summary:   "isolation violation: personal can reach gaming",
			Violations: []string{"expected deny but traffic is reachable"},
		},
	}

	spec := &intent.Spec{
		Networks: []intent.Network{
			{Name: "personal", CIDR: "192.168.20.0/24", Zone: "personal"},
			{Name: "gaming", CIDR: "192.168.30.0/24", Zone: "gaming"},
		},
		Probes: []intent.Probe{
			{Name: "personal-jump", Host: "192.168.20.50", User: "admin", VLAN: "personal"},
		},
	}

	runner := models.RunnerContext{
		Networks: []string{"nightfall"},
	}

	recs, err := GenerateRecommendations(failures, spec, runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, r := range recs {
		if r.Category == "vantage_point" && strings.Contains(r.Remediation, "personal-jump") {
			found = true
		}
	}

	if !found {
		t.Error("expected recommendation to mention existing probe personal-jump")
	}
}

func TestGenerateRecommendations_VPNFailure(t *testing.T) {
	failures := []models.CheckResult{
		{
			CheckType: "vpn_route",
			Target:    "192.168.20.77",
			Status:    models.StatusFail,
			Summary:   "192.168.20.77 routed via 192.168.10.112 (not tunnel)",
			Expected:  map[string]interface{}{"vpn": "primary-vpn"},
		},
	}

	spec := &intent.Spec{
		VPN: []intent.VPNConfig{
			{Name: "primary-vpn", Type: "wireguard", Interface: "wg0"},
		},
	}

	recs, err := GenerateRecommendations(failures, spec, models.RunnerContext{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, r := range recs {
		if r.Category == "vpn_misconfigured" {
			found = true
			if !strings.Contains(r.Remediation, "wg0") {
				t.Errorf("expected remediation to mention VPN interface, got: %s", r.Remediation)
			}
		}
	}

	if !found {
		t.Error("expected vpn_misconfigured recommendation")
	}
}

func TestGenerateRecommendations_NetworkUnreachable(t *testing.T) {
	failures := []models.CheckResult{
		{
			CheckType: "subnet_discovery",
			Target:    "media",
			Status:    models.StatusError,
			Summary:   "subnet_discovery timed out",
		},
		{
			CheckType: "dns_check",
			Target:    "nas.home.example",
			Status:    models.StatusError,
			Summary:   "failed to resolve nas.home.example",
		},
	}

	recs, err := GenerateRecommendations(failures, nil, models.RunnerContext{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, r := range recs {
		if r.Category == "network_unreachable" {
			found = true
			if len(r.Affected) < 2 {
				t.Errorf("expected both failures to be aggregated, got %d affected", len(r.Affected))
			}
		}
	}

	if !found {
		t.Error("expected network_unreachable recommendation")
	}
}

func TestGenerateRecommendations_ACLNotEnforced(t *testing.T) {
	failures := []models.CheckResult{
		{
			CheckType:  "acl_check",
			Target:     "personal-isolation",
			Status:     models.StatusFail,
			Summary:    `ACL policy "personal-isolation" is NOT enforced in Omada`,
			Violations: []string{"no matching ACL rule found for policy \"personal-isolation\" (personal -> gaming deny)"},
		},
	}

	recs, err := GenerateRecommendations(failures, nil, models.RunnerContext{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, r := range recs {
		if r.Category == "acl_not_enforced" {
			found = true
			if !strings.Contains(r.Remediation, "Omada") {
				t.Errorf("expected remediation to mention Omada, got: %s", r.Remediation)
			}
		}
	}

	if !found {
		t.Error("expected acl_not_enforced recommendation")
	}
}

func TestGenerateRecommendations_HostDown(t *testing.T) {
	failures := []models.CheckResult{
		{
			CheckType: "port_check",
			Target:    "192.168.50.55",
			Status:    models.StatusFail,
			Summary:   "port check failed on 192.168.50.55",
			Violations: []string{"port 8096: expected open, got filtered"},
		},
	}

	recs, err := GenerateRecommendations(failures, nil, models.RunnerContext{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, r := range recs {
		if r.Category == "service_down" {
			found = true
		}
	}

	if !found {
		t.Error("expected service_down recommendation")
	}
}

func TestGenerateRecommendations_DNSFailure(t *testing.T) {
	failures := []models.CheckResult{
		{
			CheckType: "dns_check",
			Target:    "nas.home.example",
			Status:    models.StatusFail,
			Summary:   "dns_check failed: nas.home.lan resolved to 10.0.0.5 (expected 10.0.0.10)",
			Violations: []string{"expected IP 10.0.0.10, got 10.0.0.5"},
		},
	}

	recs, err := GenerateRecommendations(failures, nil, models.RunnerContext{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, r := range recs {
		if r.Category == "dns_failure" {
			found = true
			if !strings.Contains(r.Remediation, "DNS") {
				t.Errorf("expected remediation to mention DNS, got: %s", r.Remediation)
			}
		}
	}

	if !found {
		t.Error("expected dns_failure recommendation")
	}
}

func TestGenerateRecommendations_NetworkDegraded(t *testing.T) {
	failures := []models.CheckResult{
		{
			CheckType: "network_health",
			Target:    "192.168.20.254",
			Status:    models.StatusFail,
			Summary:   "network_health failed: 192.168.20.254 latency 500ms (expected <100ms)",
			Violations: []string{"latency 500ms exceeds threshold 100ms"},
		},
	}

	recs, err := GenerateRecommendations(failures, nil, models.RunnerContext{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, r := range recs {
		if r.Category == "network_degraded" {
			found = true
		}
	}

	if !found {
		t.Error("expected network_degraded recommendation")
	}
}

func TestGenerateRecommendations_DiscoveryCountViolation(t *testing.T) {
	failures := []models.CheckResult{
		{
			CheckType: "subnet_discovery",
			Target:    "personal",
			Status:    models.StatusFail,
			Summary:   "25 hosts discovered in 192.168.20.0/24",
			Observed:  map[string]interface{}{"total": float64(25)},
			Expected:  map[string]interface{}{"expect_hosts_max": float64(20)},
			Violations: []string{"found 25 hosts, expected max 20"},
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
			if !strings.Contains(r.Title, "More hosts") {
				t.Errorf("expected title to mention more hosts, got: %s", r.Title)
			}
			if r.SpecPatch == "" {
				t.Error("expected SpecPatch with updated max")
			}
		}
	}

	if !found {
		t.Error("expected discovery_count recommendation")
	}
}

func TestGenerateRecommendations_IsolationWarnVantagePoint(t *testing.T) {
	// WARN from unconfirmed isolation check — should be vantage_point
	failures := []models.CheckResult{
		{
			CheckType: "isolation",
			Target:    "iot -> clients",
			Status:    models.StatusWarn,
			Summary:   "isolation unconfirmed: iot → clients gateways unreachable, but nyx is not running from inside the iot zone",
		},
	}

	spec := &intent.Spec{
		Networks: []intent.Network{
			{Name: "iot", CIDR: "10.0.30.0/24", Zone: "iot"},
			{Name: "clients", CIDR: "10.0.20.0/24", Zone: "clients"},
		},
	}

	runner := models.RunnerContext{
		Networks: []string{"clients"},
	}

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
		t.Error("expected vantage_point recommendation for WARN isolation check")
	}
}

// TestRealAuditScenario simulates the actual failures from the real homelab audit run.
func TestRealAuditScenario(t *testing.T) {
	failures := []models.CheckResult{
		{
			CheckType:  "isolation",
			Target:     "personal -> gaming",
			Status:     models.StatusFail,
			Summary:    "isolation violation: personal can reach gaming",
			Violations: []string{"expected deny but traffic is reachable"},
		},
		{
			CheckType:  "isolation",
			Target:     "personal -> iot",
			Status:     models.StatusFail,
			Summary:    "isolation violation: personal can reach iot",
			Violations: []string{"expected deny but traffic is reachable"},
		},
		{
			CheckType:  "isolation",
			Target:     "gaming -> personal",
			Status:     models.StatusFail,
			Summary:    "isolation violation: gaming can reach personal",
			Violations: []string{"expected deny but traffic is reachable"},
		},
		{
			CheckType:  "isolation",
			Target:     "personal -> trusted",
			Status:     models.StatusFail,
			Summary:    "isolation violation: personal can reach trusted",
			Violations: []string{"expected deny but traffic is reachable"},
		},
		{
			CheckType: "vpn_route",
			Target:    "192.168.20.77",
			Status:    models.StatusFail,
			Summary:   "192.168.20.77 routed via 192.168.10.112 (not tunnel)",
			Expected:  map[string]interface{}{"vpn": "primary-vpn"},
		},
		{
			CheckType: "port_check",
			Target:    "192.168.50.55",
			Status:    models.StatusFail,
			Summary:   "port check failed on 192.168.50.55",
			Violations: []string{"port 8096: expected open, got filtered"},
		},
		{
			CheckType: "dns_check",
			Target:    "nas.home.example",
			Status:    models.StatusError,
			Summary:   "failed to resolve nas.home.example",
		},
	}

	spec := &intent.Spec{
		Networks: []intent.Network{
			{Name: "trusted", CIDR: "192.168.10.0/24", Zone: "trusted", Gateway: "192.168.10.1"},
			{Name: "personal", CIDR: "192.168.20.0/24", Zone: "personal", Gateway: "192.168.20.1"},
			{Name: "gaming", CIDR: "192.168.30.0/24", Zone: "gaming", Gateway: "192.168.30.1"},
			{Name: "iot", CIDR: "192.168.40.0/24", Zone: "iot", Gateway: "192.168.40.1"},
			{Name: "media", CIDR: "192.168.50.0/24", Zone: "media", Gateway: "192.168.50.1"},
		},
		VPN: []intent.VPNConfig{
			{Name: "primary-vpn", Type: "wireguard", Interface: "wg0"},
		},
		Policies: []intent.Policy{
			{Name: "personal-isolation", From: "personal", To: "gaming", Action: "deny"},
			{Name: "game-isolation", From: "gaming", To: "personal", Action: "deny"},
			{Name: "trusted-protection", From: "personal", To: "trusted", Action: "deny"},
		},
	}

	runner := models.RunnerContext{
		Networks: []string{"trusted"},
	}

	recs, err := GenerateRecommendations(failures, spec, runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(recs) == 0 {
		t.Fatal("expected recommendations for real audit scenario")
	}

	// Verify the most critical rec is vantage_point and it's P1
	if recs[0].Category != "vantage_point" {
		t.Errorf("expected first recommendation to be vantage_point, got: %s", recs[0].Category)
	}
	if recs[0].Priority != 1 {
		t.Errorf("expected first recommendation to be priority 1, got: %d", recs[0].Priority)
	}

	// Verify the vantage_point rec aggregates multiple affected checks
	if len(recs[0].Affected) < 4 {
		t.Errorf("expected vantage_point rec to aggregate at least 4 affected checks, got %d", len(recs[0].Affected))
	}

	// Verify we have a SpecPatch for probes
	if recs[0].SpecPatch == "" {
		t.Error("expected SpecPatch with probe suggestions in vantage_point recommendation")
	}

	// Verify categories are present (vantage_point, vpn, host_down)
	categories := map[string]bool{}
	for _, r := range recs {
		categories[r.Category] = true
	}
	if !categories["vantage_point"] {
		t.Error("missing vantage_point category")
	}
	if !categories["vpn_misconfigured"] {
		t.Error("missing vpn_misconfigured category")
	}
	if !categories["service_down"] {
		t.Error("missing service_down category")
	}
}
