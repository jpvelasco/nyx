package topology

import (
	"strings"
	"testing"
)

func TestSwitchRolePlanning(t *testing.T) {
	gaming := MapResource{ID: "gaming", Kind: "segment", Name: "gaming", VLAN: 30}
	management := MapResource{ID: "management", Kind: "segment", Name: "management", VLAN: 11}
	port := MapResource{ID: "p", Kind: "port", Port: 8}
	ap := MapResource{ID: "a", Kind: "ap"}
	for _, tc := range []struct {
		name     string
		intent   PortIntent
		native   string
		peer     bool
		client   bool
		role     string
		eligible bool
	}{
		{"gaming client", PortIntent{Port: 8, Role: "access", Native: "gaming"}, "gaming", false, true, "access", true},
		{"unknown access client", PortIntent{Port: 8, Role: "access", Native: "gaming"}, "gaming", false, false, "access", false},
		{"AP uplink", PortIntent{Port: 8, Role: "ap-uplink", Native: "management", Tagged: []string{"gaming"}}, "management", true, false, "ap-uplink", true},
		{"AP loses management", PortIntent{Port: 8, Role: "ap-uplink", Native: "gaming"}, "management", true, false, "ap-uplink", false},
		{"management access", PortIntent{Port: 8, Role: "access", Native: "gaming"}, "management", false, true, "management", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NetworkMap{Resources: []MapResource{port, ap, gaming, management}, Links: []MapLink{{From: "p", Targets: []string{tc.native}, State: "observed", Relation: "native"}}}
			if tc.peer {
				m.Links = append(m.Links, MapLink{From: "a", Targets: []string{"p"}, State: "observed", Relation: "uplink"})
			}
			r := EvaluateSwitchPort(m, "p", tc.intent, 11, tc.client)
			if r.Eligible != tc.eligible || r.Role != tc.role {
				t.Fatalf("%+v", r)
			}
		})
	}
}

func TestGuardInfrastructureAndUnresolvedTags(t *testing.T) {
	const port = "port"
	native := MapResource{ID: "native", Kind: "segment", Name: "gaming", VLAN: 30}
	edge := func(relation, state, target string) MapLink {
		return MapLink{From: port, Relation: relation, State: state, Targets: []string{target}}
	}
	for _, tc := range []struct {
		name, neighbor, intended, observed, reason string
		tags                                       []MapLink
		blocked                                    bool
	}{
		{"switch", "switch", "access", "trunk", "infrastructure", nil, false},
		{"firewall", "gateway", "access", "management", "infrastructure", nil, false},
		{"unknown peer", "client", "access", "ambiguous", "infrastructure", nil, false},
		{"unresolved neighbor", "", "access", "ambiguous", "neighbor", []MapLink{edge("neighbor", "ambiguous", "peer")}, false},
		{"unresolved tags", "", "access", "ambiguous", "tagged", []MapLink{edge("tagged", "missing", "unknown")}, false},
		{"client trunk", "", "access", "ambiguous", "tagged", []MapLink{edge("tagged", "observed", "tag")}, false},
		{"ap loses tag", "ap", "ap-uplink", "ap-uplink", "removing", []MapLink{edge("tagged", "observed", "tag")}, false},
		{"wrong intent", "ap", "access", "ap-uplink", "intent", nil, false},
		{"discarding", "", "access", "ambiguous", "spanning tree", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NetworkMap{Resources: []MapResource{{ID: port, Kind: "port", STPDiscarding: &tc.blocked}, native, {ID: "tag", Kind: "segment", Name: "media", VLAN: 50}}, Links: []MapLink{edge("native", "observed", "native")}}
			if tc.neighbor != "" {
				m.Resources = append(m.Resources, MapResource{ID: "peer", Kind: tc.neighbor})
				m.Links = append(m.Links, edge("neighbor", "observed", "peer"))
			}
			m.Links = append(m.Links, tc.tags...)
			got := EvaluateSwitchPort(m, port, PortIntent{Port: 8, Role: tc.intended, Native: "gaming"}, 11, true)
			if got.Eligible || got.Role != tc.observed || !strings.Contains(got.Reason, tc.reason) {
				t.Fatalf("unsafe assessment: %+v", got)
			}
		})
	}
	for _, list := range [][]PortIntent{{{Port: 0, Role: "access", Native: "gaming"}}, {{Port: 1, Role: "access", Native: "gaming"}, {Port: 1, Role: "access", Native: "media"}}, {{Port: 1, Role: "unsupported", Native: "gaming"}}} {
		if (SwitchPortPolicy{ManagementVLAN: 11, Ports: list}).Validate() == nil {
			t.Fatal("unsafe or ambiguous policy accepted")
		}
	}
}
