package topology

import (
	"strings"
	"testing"
)

// TestClassify is the table test for per-device NAT role classification.
func TestClassify(t *testing.T) {
	cases := []struct {
		name     string
		facts    DeviceFacts
		wantRole NatRole
	}{
		{"opnsense automatic mode", DeviceFacts{Provider: ProviderOpnsense, OutboundNatMode: "automatic"}, RoleNatRouter},
		{"opnsense hybrid mode", DeviceFacts{Provider: ProviderOpnsense, OutboundNatMode: "hybrid"}, RoleNatRouter},
		{"opnsense advanced mode", DeviceFacts{Provider: ProviderOpnsense, OutboundNatMode: "advanced"}, RoleNatRouter},
		{"opnsense disabled mode", DeviceFacts{Provider: ProviderOpnsense, OutboundNatMode: "disabled"}, RoleBridge},
		{"opnsense disabled mode with port forwards", DeviceFacts{Provider: ProviderOpnsense, OutboundNatMode: "disabled", PortForwardRules: 3}, RoleBridge},
		{"opnsense disabled mode with source nat rules", DeviceFacts{Provider: ProviderOpnsense, OutboundNatMode: "disabled", SourceNatRules: 2}, RoleIndeterminate},
		{"opnsense mode unreadable with source nat rules", DeviceFacts{Provider: ProviderOpnsense, SourceNatRules: 1}, RoleNatRouter},
		{"opnsense mode unreadable with no rules", DeviceFacts{Provider: ProviderOpnsense}, RoleUnknown},
		{"opnsense mode unreadable with port forwards only", DeviceFacts{Provider: ProviderOpnsense, PortForwardRules: 4}, RoleNatRouter},
		{"omada managed gateway", DeviceFacts{Provider: ProviderOmada, HasManagedGateway: true}, RoleNatRouter},
		{"omada managed gateway with port forwards", DeviceFacts{Provider: ProviderOmada, HasManagedGateway: true, PortForwardRules: 2, OneToOneRules: 1}, RoleNatRouter},
		{"omada no managed gateway no rules", DeviceFacts{Provider: ProviderOmada}, RoleUnknown},
		{"omada no managed gateway but rules present", DeviceFacts{Provider: ProviderOmada, PortForwardRules: 1}, RoleIndeterminate},
		{"unknown provider", DeviceFacts{Provider: "fortigate"}, RoleUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			role, evidence := Classify(tc.facts)
			if role != tc.wantRole {
				t.Fatalf("role = %q, want %q (evidence: %v)", role, tc.wantRole, evidence)
			}
			if len(evidence) == 0 {
				t.Errorf("evidence empty for %q — every verdict must carry printable evidence", tc.name)
			}
		})
	}
}

// TestIsRole is the gate for role-based expected values: only the
// classifiable roles qualify — an unknown mode is key drift, not a role.
func TestIsRole(t *testing.T) {
	cases := []struct {
		value string
		want  bool
	}{
		{"nat_router", true},
		{"bridge", true},
		{"indeterminate", true},
		{"unknown", false},
		{"", false},
		{"automatic", false},
		{"fortigate", false},
	}
	for _, tc := range cases {
		t.Run(tc.value, func(t *testing.T) {
			if got := IsRole(tc.value); got != tc.want {
				t.Errorf("IsRole(%q) = %v, want %v", tc.value, got, tc.want)
			}
		})
	}
}

// TestBuildReportRisk is the table test for the site-level double-NAT verdict.
func TestBuildReportRisk(t *testing.T) {
	cases := []struct {
		name     string
		facts    []DeviceFacts
		wantRisk DoubleNatRisk
	}{
		{"two routers", []DeviceFacts{
			{Provider: ProviderOmada, HasManagedGateway: true},
			{Provider: ProviderOpnsense, OutboundNatMode: "automatic"},
		}, RiskDouble},
		{"two routers but one is a LAN client", []DeviceFacts{
			{Provider: ProviderOmada, HasManagedGateway: true},
			{Provider: ProviderOpnsense, OutboundNatMode: "automatic", DownstreamOfManagedGateway: true},
		}, RiskMultipleConfigured},
		{"omada router plus transparent opnsense", []DeviceFacts{
			{Provider: ProviderOmada, HasManagedGateway: true},
			{Provider: ProviderOpnsense, OutboundNatMode: "disabled"},
		}, RiskNone},
		{"single omada router", []DeviceFacts{
			{Provider: ProviderOmada, HasManagedGateway: true},
		}, RiskNone},
		{"router plus indeterminate", []DeviceFacts{
			{Provider: ProviderOmada, HasManagedGateway: true},
			{Provider: ProviderOpnsense, OutboundNatMode: "disabled", SourceNatRules: 1},
		}, RiskDouble},
		{"router plus downstream indeterminate", []DeviceFacts{
			{Provider: ProviderOmada, HasManagedGateway: true},
			{Provider: ProviderOpnsense, OutboundNatMode: "disabled", SourceNatRules: 1, DownstreamOfManagedGateway: true},
		}, RiskMultipleConfigured},
		{"indeterminate only", []DeviceFacts{
			{Provider: ProviderOpnsense, OutboundNatMode: "disabled", SourceNatRules: 1},
		}, RiskIndeterminate},
		{"two indeterminates", []DeviceFacts{
			{Provider: ProviderOmada, PortForwardRules: 1},
			{Provider: ProviderOpnsense, OutboundNatMode: "disabled", SourceNatRules: 1},
		}, RiskIndeterminate},
		{"all unknown", []DeviceFacts{
			{Provider: ProviderOpnsense},
			{Provider: ProviderOmada},
		}, RiskNone},
		{"empty", []DeviceFacts{}, RiskNone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := BuildReport(tc.facts)
			if rep.Risk != tc.wantRisk {
				t.Fatalf("risk = %q (reason %q), want %q", rep.Risk, rep.Reason, tc.wantRisk)
			}
			if rep.Reason == "" {
				t.Errorf("reason empty for risk %q", rep.Risk)
			}
			if len(rep.Devices) != len(tc.facts) {
				t.Errorf("devices = %d, want %d", len(rep.Devices), len(tc.facts))
			}
		})
	}
}

// TestBuildReportRisk_DownstreamReason states that extra NAT-configured
// devices off the egress path produce multiple_nat_configured, not a
// path-claiming double_nat message.
func TestBuildReportRisk_DownstreamReason(t *testing.T) {
	rep := BuildReport([]DeviceFacts{
		{Provider: ProviderOmada, HasManagedGateway: true},
		{Provider: ProviderOpnsense, OutboundNatMode: "automatic", DownstreamOfManagedGateway: true},
	})
	if rep.Risk != RiskMultipleConfigured {
		t.Fatalf("risk = %q, want %q", rep.Risk, RiskMultipleConfigured)
	}
	if !strings.Contains(rep.Reason, "egress path") {
		t.Errorf("reason %q should explain the devices are not on the same egress path", rep.Reason)
	}
	if strings.Contains(rep.Reason, "will be rewritten more than once") {
		t.Errorf("reason %q still claims a path rewrite", rep.Reason)
	}
}

// TestClassify_DownstreamEvidence tags a LAN-side device so the operator
// can see why it was excluded from the egress verdict.
func TestClassify_DownstreamEvidence(t *testing.T) {
	_, evidence := Classify(DeviceFacts{
		Provider:                   ProviderOpnsense,
		OutboundNatMode:            "automatic",
		DownstreamOfManagedGateway: true,
	})
	joined := strings.Join(evidence, " ")
	if !strings.Contains(joined, "LAN client") {
		t.Errorf("evidence %v should note the device is a LAN client, not an egress hop", evidence)
	}
}

// TestClassify_ConfigOnlyEvidence distinguishes factory-default outbound
// NAT from observed NAT rules so a config-only nat_router is not read as
// a hot-path rewrite.
func TestClassify_ConfigOnlyEvidence(t *testing.T) {
	_, evidence := Classify(DeviceFacts{
		Provider:        ProviderOpnsense,
		OutboundNatMode: "automatic",
	})
	joined := strings.Join(evidence, " ")
	if !strings.Contains(joined, "config-only") {
		t.Errorf("evidence %v should tag a default outbound-NAT mode with no rules as config-only", evidence)
	}
}

// TestReportEvidenceNeverLeaksPII guards the PII boundary: classification
// evidence must be generic — the facts carry no hostnames or IPs, and the
// evidence text must not invent any.
func TestReportEvidenceNeverLeaksPII(t *testing.T) {
	rep := BuildReport([]DeviceFacts{
		{Provider: ProviderOmada, HasManagedGateway: true, PortForwardRules: 3, OneToOneRules: 1},
		{Provider: ProviderOpnsense, OutboundNatMode: "automatic", SourceNatRules: 2},
	})
	joined := ""
	for _, d := range rep.Devices {
		joined += strings.Join(d.Evidence, " ") + " "
	}
	joined += rep.Reason
	for _, leak := range []string{"10.", "192.168.", "172.16.", "wan1", "myhost"} {
		if strings.Contains(joined, leak) {
			t.Errorf("report text contains %q: %q", leak, joined)
		}
	}
}
