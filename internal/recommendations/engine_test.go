package recommendations

import (
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/models"
)

// TestGenerateRecommendations_IsolationBreach tests isolation breach detection
func TestGenerateRecommendations_IsolationBreach(t *testing.T) {
	failures := []models.CheckResult{
		{
			CheckType:  "isolation",
			Target:     "gaming -> personal",
			Status:     models.StatusFail,
			Summary:    "isolation violation: gaming can reach personal",
			Violations: []string{"expected deny but traffic is reachable"},
		},
	}

	spec := &intent.Spec{
		Networks: []intent.Network{
			{Name: "gaming", CIDR: "10.0.30.0/24", Zone: "gaming"},
			{Name: "personal", CIDR: "10.0.20.0/24", Zone: "personal"},
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

// TestGenerateRecommendations_ACLNotEnforced tests ACL enforcement detection
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

// TestGenerateRecommendations_NetworkUnreachable tests network unreachable detection
func TestGenerateRecommendations_NetworkUnreachable(t *testing.T) {
	failures := []models.CheckResult{
		{
			CheckType:  "subnet_discovery",
			Target:     "media",
			Status:     models.StatusError,
			Summary:    "subnet_discovery timed out",
		},
		{
			CheckType:  "dns_check",
			Target:     "nas.home.example",
			Status:     models.StatusError,
			Summary:    "failed to resolve nas.home.example",
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

// TestGenerateRecommendations_VPNFailure tests VPN misconfiguration detection
func TestGenerateRecommendations_VPNFailure(t *testing.T) {
	failures := []models.CheckResult{
		{
			CheckType: "vpn_route",
			Target:    "10.0.20.77",
			Status:    models.StatusFail,
			Summary:   "10.0.20.77 routed via 10.0.10.112 (not tunnel)",
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

// TestGenerateRecommendations_DiscoveryCountViolation tests discovery count violations
func TestGenerateRecommendations_DiscoveryCountViolation(t *testing.T) {
	failures := []models.CheckResult{
		{
			CheckType:  "subnet_discovery",
			Target:     "personal",
			Status:     models.StatusFail,
			Summary:    "25 hosts discovered in 10.0.20.0/24",
			Observed:   map[string]interface{}{"total": float64(25)},
			Expected:   map[string]interface{}{"expect_hosts_max": float64(20)},
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

// TestGenerateRecommendations_HostDown tests host down detection
func TestGenerateRecommendations_HostDown(t *testing.T) {
	failures := []models.CheckResult{
		{
			CheckType:  "port_check",
			Target:     "10.0.50.55",
			Status:     models.StatusFail,
			Summary:    "port check failed on 10.0.50.55",
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

// TestGenerateRecommendations_DNSFailure tests DNS failure detection
func TestGenerateRecommendations_DNSFailure(t *testing.T) {
	failures := []models.CheckResult{
		{
			CheckType:  "dns_check",
			Target:     "nas.home.example",
			Status:     models.StatusFail,
			Summary:    "dns_check failed: nas.home.lan resolved to 10.0.0.5 (expected 10.0.0.10)",
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

// TestGenerateRecommendations_ServiceDown tests service down detection
func TestGenerateRecommendations_ServiceDown(t *testing.T) {
	failures := []models.CheckResult{
		{
			CheckType:  "port_check",
			Target:     "10.0.50.55",
			Status:     models.StatusFail,
			Summary:    "port check failed on 10.0.50.55",
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

// TestGenerateRecommendations_NetworkDegraded tests network degradation detection
func TestGenerateRecommendations_NetworkDegraded(t *testing.T) {
	failures := []models.CheckResult{
		{
			CheckType:  "network_health",
			Target:     "10.0.20.254",
			Status:     models.StatusFail,
			Summary:    "network_health failed: 10.0.20.254 latency 500ms (expected <100ms)",
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

// TestGenerateRecommendations_EmptyOrAllPass tests that no recommendations are generated for passing checks
func TestGenerateRecommendations_EmptyOrAllPass(t *testing.T) {
	recs, err := GenerateRecommendations(nil, nil, models.RunnerContext{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(recs) != 0 {
		t.Errorf("expected 0 recs for nil/empty failures, got %d", len(recs))
	}

	passOnly := []models.CheckResult{
		{CheckType: "dummy", Status: models.StatusPass, Summary: "fine"},
	}
	recs, err = GenerateRecommendations(passOnly, nil, models.RunnerContext{})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 0 {
		t.Errorf("expected 0 recs for passing only, got %d", len(recs))
	}
}

// TestGenerateRecommendations_NetworkUnreachable_SingleNetwork tests single network unreachable
func TestGenerateRecommendations_NetworkUnreachable_SingleNetwork(t *testing.T) {
	failures := []models.CheckResult{
		{
			CheckType:  "subnet_discovery",
			Target:     "personal",
			Status:     models.StatusError,
			Summary:    "subnet_discovery timed out",
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
			if len(r.Affected) < 1 {
				t.Errorf("expected at least 1 affected, got %d", len(r.Affected))
			}
		}
	}

	if !found {
		t.Error("expected network_unreachable recommendation for single network")
	}
}

// TestGenerateRecommendations_NetworkUnreachable_MultipleNetworks tests aggregation of multiple unreachable networks
func TestGenerateRecommendations_NetworkUnreachable_MultipleNetworks(t *testing.T) {
	failures := []models.CheckResult{
		{
			CheckType:  "subnet_discovery",
			Target:     "personal",
			Status:     models.StatusError,
			Summary:    "subnet_discovery timed out",
		},
		{
			CheckType:  "subnet_discovery",
			Target:     "gaming",
			Status:     models.StatusError,
			Summary:    "subnet_discovery timed out",
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
		t.Error("expected network_unreachable recommendation for multiple networks")
	}
}

// TestGenerateRecommendations_DNSFailure_NoIP tests DNS failure when no IP is returned
func TestGenerateRecommendations_DNSFailure_NoIP(t *testing.T) {
	failures := []models.CheckResult{
		{
			CheckType:  "dns_check",
			Target:     "nas.home.example",
			Status:     models.StatusFail,
			Summary:    "failed to resolve nas.home.example",
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
		}
	}

	if !found {
		t.Error("expected dns_failure recommendation when no IP returned")
	}
}

// TestGenerateRecommendations_ServiceDown_MultiplePorts tests service down with multiple failed ports
func TestGenerateRecommendations_ServiceDown_MultiplePorts(t *testing.T) {
	failures := []models.CheckResult{
		{
			CheckType:  "port_check",
			Target:     "10.0.50.55",
			Status:     models.StatusFail,
			Summary:    "port check failed on 10.0.50.55",
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
		t.Error("expected service_down recommendation for multiple failed ports")
	}
}

// TestGenerateRecommendations_NetworkDegraded_LatencyOnly tests network degradation with only latency issue
func TestGenerateRecommendations_NetworkDegraded_LatencyOnly(t *testing.T) {
	failures := []models.CheckResult{
		{
			CheckType:  "network_health",
			Target:     "10.0.20.254",
			Status:     models.StatusFail,
			Summary:    "network_health failed: 10.0.20.254 latency 500ms (expected <100ms)",
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
		t.Error("expected network_degraded recommendation for latency issue")
	}
}

// TestGenerateRecommendations_NetworkDegraded_LossOnly tests network degradation with only packet loss
func TestGenerateRecommendations_NetworkDegraded_LossOnly(t *testing.T) {
	failures := []models.CheckResult{
		{
			CheckType:  "network_health",
			Target:     "10.0.20.254",
			Status:     models.StatusFail,
			Summary:    "network_health failed: 10.0.20.254 packet loss 15% (expected <5%)",
			Violations: []string{"packet loss 15% exceeds threshold 5%"},
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
		t.Error("expected network_degraded recommendation for packet loss issue")
	}
}

// TestGenerateRecommendations_NetworkDegraded_Both tests network degradation with both latency and loss
func TestGenerateRecommendations_NetworkDegraded_Both(t *testing.T) {
	failures := []models.CheckResult{
		{
			CheckType:  "network_health",
			Target:     "10.0.20.254",
			Status:     models.StatusFail,
			Summary:    "network_health failed: 10.0.20.254 latency 500ms (expected <100ms), packet loss 15% (expected <5%)",
			Violations: []string{"latency 500ms exceeds threshold 100ms", "packet loss 15% exceeds threshold 5%"},
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
		t.Error("expected network_degraded recommendation for combined issues")
	}
}
