package audit

import (
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/models"
	"github.com/jpvelasco/nyx/internal/probe/fake"
)

func TestServicePolicyFromProbeFixtures(t *testing.T) {
	for _, tc := range []struct {
		name, kind, action, host, prefix string
		source, control                  uint32
		want                             models.Status
		family                           string
	}{
		{"denied management", "tcp", "deny", "10.0.11.1", "10.0.11.0/24", 1, 0, models.StatusPass, "ipv4"},
		{"permitted management", "tcp", "allow", "2001:db8:11::1", "2001:db8:11::/64", 0, 0, models.StatusPass, "ipv6"},
		{"unexpectedly permitted", "tcp", "deny", "10.0.11.1", "10.0.11.0/24", 0, 0, models.StatusFail, "ipv4"},
		{"positive control unavailable", "tcp", "deny", "10.0.11.1", "10.0.11.0/24", 1, 1, models.StatusWarn, "ipv4"},
		{"source command error", "tcp", "deny", "10.0.11.1", "10.0.11.0/24", 2, 0, models.StatusWarn, "ipv4"},
		{"source tooling unavailable", "tcp", "deny", "10.0.11.1", "10.0.11.0/24", 127, 0, models.StatusWarn, "ipv4"},
		{"permitted DNS", "dns", "allow", "10.0.11.1", "10.0.11.0/24", 0, 0, models.StatusPass, "ipv4"},
	} {
		t.Run(tc.name, func(t *testing.T) {

			build := func(role string, code uint32) intent.Probe {
				p := startFakeProbe(t, fake.Options{ExecReply: true, OnExec: func(cmd string) (string, uint32) {
					if tc.kind == "dns" {
						if !strings.Contains(cmd, "nslookup") || !strings.Contains(cmd, tc.host) {
							t.Error("unexpected DNS command")
						}
						return "Name: service.example\nAddress: 192.0.2.8\n", code
					}
					if !strings.Contains(cmd, "nc") || !strings.Contains(cmd, tc.host) {
						t.Error("unexpected port command")
					}
					return "", code
				}})
				p.Name = role
				p.VLAN = role
				return p
			}
			src, control := build("iot", tc.source), build("management", tc.control)
			a := intent.Assertion{Name: "source-check", Type: "port_check", Runner: src.Name, Target: tc.host, Ports: []int{443}, Expect: "open"}
			if tc.kind == "dns" {
				a = intent.Assertion{Name: "source-check", Type: "dns_check", Runner: src.Name, Server: tc.host, Query: "service.example", ExpectIP: "192.0.2.8"}
			}
			pos := a
			pos.Name = "control-check"
			pos.Runner = control.Name
			if tc.action == "deny" {
				a.Expect = "closed"
			}
			spec := &intent.Spec{
				Version: 1, Site: "trusted", Probes: []intent.Probe{src, control},
				Networks:        []intent.Network{{Name: "iot", CIDR: "10.0.60.0/24"}, {Name: "management", CIDR: tc.prefix}},
				Policies:        []intent.Policy{{Name: "management-access", From: "iot", To: "management", Action: tc.action}},
				Assertions:      []intent.Assertion{a, pos},
				ServicePolicies: []intent.ServicePolicy{{Policy: "management-access", Measurement: a.Name, PositiveControl: pos.Name}},
			}
			if err := intent.ValidateSpec(spec); err != nil {
				t.Fatal(err)
			}
			engine := NewEngine(spec)
			engine.SkipHostKeyVerify = true
			report, err := engine.Run(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			var got *models.CheckResult
			for i := range report.Findings {
				if report.Findings[i].CheckType == "service_policy" {
					got = &report.Findings[i]
				}
			}
			if got == nil || got.Status != tc.want || got.Observed["ip_family"] != tc.family || got.Observed["established_reply"] != "unmeasured" {
				t.Fatalf("unexpected policy finding: %+v", got)
			}
		})
	}
}

func TestServiceFirewallChecksOnlyMatchingPolicy(t *testing.T) {
	spec := &intent.Spec{Assertions: []intent.Assertion{{Type: "acl_check", Policy: "management-access", Expect: "enforced"}, {Type: "acl_check", Policy: "other"}, {Type: "port_check"}}}
	findings := []models.CheckResult{{Tool: "opnsense", Status: models.StatusPass}, {Tool: "omada", Status: models.StatusFail}, {Status: models.StatusPass}}
	checks := serviceFirewallChecks(spec, "management-access", findings)
	if len(checks) != 1 || checks[0].Provider != "opnsense" || checks[0].Status != models.StatusPass || checks[0].Expect != "enforced" {
		t.Fatal("status came from an unrelated policy or assertion")
	}
}

func TestServiceObservationUnmeasured(t *testing.T) {
	for _, tc := range []struct {
		kind, runner string
		data         map[string]any
	}{{"dns_check", "source", nil}, {"port_check", "mismatch", nil}, {"port_check", "source", nil}, {"port_check", "source", map[string]any{"ports": []interface{}{map[string]any{"state": "filtered"}}}}} {
		a := intent.Assertion{Type: tc.kind, Runner: "source"}
		r := models.CheckResult{CheckType: tc.kind, Runner: tc.runner, Status: models.StatusFail, Observed: tc.data}
		if got := serviceObservation(a, r); got != "unknown" {
			t.Fatalf("ambiguous evidence promoted to %s", got)
		}
	}
	if _, err := NewEngine(&intent.Spec{ServicePolicies: []intent.ServicePolicy{{Policy: "missing"}}}).Run(t.Context()); err == nil {
		t.Fatal("engine accepted an undeclared policy")
	}
}
