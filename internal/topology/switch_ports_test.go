package topology

import "testing"

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
