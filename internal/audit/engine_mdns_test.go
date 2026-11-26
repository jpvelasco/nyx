package audit

import (
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/models"
	"github.com/jpvelasco/nyx/internal/probe/fake"
)

func TestSegmentedMediaAndManagementFixtures(t *testing.T) {
	for _, tc := range []struct {
		name, addr, media, admin, management, answer string
		code                                         uint32
		app, discover                                models.Status
	}{
		{"v4", "10.0.50.1", "10.0.50.0/24", "10.0.11.1", "10.0.11.0/24", "10.0.50.1", 0, models.StatusPass, models.StatusPass},
		{"v6", "2001:db8:50::1", "2001:db8:50::/64", "2001:db8:11::1", "2001:db8:11::/64", "2001:db8:50::1", 0, models.StatusPass, models.StatusPass},
		{"missing resolver", "10.0.50.1", "10.0.50.0/24", "10.0.11.1", "10.0.11.0/24", "", 0, models.StatusPass, models.StatusWarn},
		{"incorrect answer and blocked service", "10.0.50.1", "10.0.50.0/24", "10.0.11.1", "10.0.11.0/24", "192.0.2.9", 1, models.StatusFail, models.StatusFail},
	} {
		t.Run(tc.name, func(t *testing.T) {
			declare := func(role string) intent.Probe {
				p := startFakeProbe(t, fake.Options{ExecReply: true, OnExec: func(cmd string) (string, uint32) {
					switch {
					case strings.Contains(cmd, "avahi-resolve-host-name"):
						family := "-4"
						if strings.Contains(tc.addr, ":") {
							family = "-6"
						}
						if role != "trusted" || !strings.Contains(cmd, family) || !strings.Contains(cmd, "media-device.local") {
							t.Error("unexpected mDNS command")
						}
						if tc.answer == "" {
							return "", 127
						}
						return "media-device.local\t" + tc.answer + "\n", 0
					case strings.Contains(cmd, "nc") && strings.Contains(cmd, tc.admin):
						if role == "trusted" {
							return "", 1
						}
						return "", 0
					case strings.Contains(cmd, "nc") && strings.Contains(cmd, tc.addr):
						if role == "trusted" {
							return "", tc.code
						}
						return "", 0
					default:
						t.Error("unexpected probe request")
						return "", 2
					}
				}})
				p.Name, p.VLAN = role, role
				return p
			}
			discovery := intent.Assertion{Name: "find-media", Type: "mdns_lookup", Runner: "trusted", From: "trusted", To: "media", Query: "media-device.local", ExpectIP: tc.addr}
			src := intent.Assertion{Name: "use-media", Type: "port_check", Runner: "trusted", Target: tc.addr, Ports: []int{443}, Expect: "open"}
			ctrl := src
			ctrl.Name, ctrl.Runner = "media-control", "media"
			adm := src
			adm.Name, adm.Expect, adm.Target = "admin-deny", "closed", tc.admin
			ac := adm
			ac.Name, ac.Expect, ac.Runner = "admin-control", "open", "management"
			spec := &intent.Spec{
				Version: 1, Site: "trusted",
				Networks: []intent.Network{
					{Name: "trusted", VLAN: 10, CIDR: "10.0.10.0/24"},
					{Name: "media", VLAN: 50, CIDR: tc.media},
					{Name: "management", VLAN: 11, CIDR: tc.management},
				},
				Probes: []intent.Probe{declare("trusted"), declare("media"), declare("management")},
				Policies: []intent.Policy{
					{Name: "media-access", From: "trusted", To: "media", Action: "deny", Except: []intent.PolicyException{{Protocol: "tcp", Port: 443, Target: tc.addr}}},
					{Name: "admin-isolation", From: "trusted", To: "management", Action: "deny"},
				},
				Assertions: []intent.Assertion{discovery, src, ctrl, adm, ac},
				ServicePolicies: []intent.ServicePolicy{
					{Policy: "media-access", Measurement: src.Name, PositiveControl: ctrl.Name, Discovery: discovery.Name},
					{Policy: "admin-isolation", Measurement: adm.Name, PositiveControl: ac.Name},
				},
			}
			if err := intent.ValidateSpec(spec); err != nil {
				t.Fatal(err)
			}
			e := NewEngine(spec)
			e.SkipHostKeyVerify = true
			r, err := e.Run(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			discovered, media, admin := false, false, false
			for _, f := range r.Findings {
				switch {
				case f.CheckType == "mdns_lookup":
					discovered = f.Status == tc.discover && f.Observed["application_connectivity"] == "unmeasured"
				case f.Expected["policy"] == "media-access":
					media = f.Status == tc.app && f.Observed["mdns_discovery"] != nil && f.Observed["service_change_impact"] != nil
				case f.Expected["policy"] == "admin-isolation":
					admin = f.Status == models.StatusPass
				}
			}
			if !discovered || !media || !admin {
				t.Fatalf("incorrect discovery=%t, media=%t, admin=%t", discovered, media, admin)
			}
		})
	}
}

func TestImportedReflectionNetworkScope(t *testing.T) {
	s := &intent.Spec{Networks: []intent.Network{{Name: "trusted", VLAN: 10}, {Name: "media", VLAN: 50}}}
	a := intent.Assertion{From: "trusted", To: "media"}
	if reflectionState(s, a) != "unknown" {
		t.Fatal("missing inventory")
	}
	inv := &intent.MDNSInventory{Status: "available"}
	s.Inventory = &intent.Inventory{MDNS: inv}
	rule := intent.MDNSRule{AP: &intent.MDNSVLAN{Service: "50", Client: "8-11,20"}}
	inv.Rules = []intent.MDNSRule{rule}
	if reflectionState(s, a) != "disabled" {
		t.Fatal("range match")
	}
	inv.Rules[0].Enabled = true
	if reflectionState(s, a) != "enabled" {
		t.Fatal("matching enabled rule")
	}
	rule.AP.Client = "12-15"
	if reflectionState(s, a) != "no_matching_rule" {
		t.Fatal("nonmatching range")
	}
	rule.AP.Client = "unsupported"
	if reflectionState(s, a) != "unknown" {
		t.Fatal("unknown VLAN notation")
	}
	inv.Rules = []intent.MDNSRule{{Type: 1}}
	if reflectionState(s, a) != "unknown" {
		t.Fatal("opaque gateway network")
	}
}
