package intent

import "testing"

func TestKnownDiscoveryBinding(t *testing.T) {
	s := &Spec{Version: 1, Site: "trusted", Networks: []Network{{Name: "trusted", CIDR: "10.0.10.0/24"}, {Name: "media", CIDR: "10.0.50.0/24"}}, Probes: []Probe{{Name: "client", Host: "client.example", VLAN: "trusted"}, {Name: "server", Host: "server.example", VLAN: "media"}}, Policies: []Policy{{Name: "watch", Action: "allow", From: "trusted", To: "media"}}, Assertions: []Assertion{{Name: "resolve", Type: "mdns_lookup", Runner: "client", From: "trusted", To: "media", Query: "media-device.local.", ExpectIP: "10.0.50.1"}, {Name: "connect", Type: "port_check", Runner: "client", Target: "10.0.50.1", Ports: []int{443}, Expect: "open"}, {Name: "control", Type: "port_check", Runner: "server", Target: "10.0.50.1", Ports: []int{443}, Expect: "open"}}, ServicePolicies: []ServicePolicy{{Policy: "watch", Discovery: "resolve", Measurement: "connect", PositiveControl: "control"}}}
	if _, err := s.BindServicePolicies(); err != nil {
		t.Fatal(err)
	}
	for _, edit := range []func(*Spec){func(s *Spec) { s.Assertions[0].To = "trusted" }, func(s *Spec) { s.Assertions[0].Runner = "server" }, func(s *Spec) { s.Assertions[0].ExpectIP = "10.0.11.1" }, func(s *Spec) { s.Assertions[0].ExpectIP = "10.0.50.5" }, func(s *Spec) { s.Assertions[0].ExpectIP = "invalid" }, func(s *Spec) { s.Assertions[0].Query = "*.local" }, func(s *Spec) { s.Assertions[0].Query = "media.example" }, func(s *Spec) { s.ServicePolicies[0].Discovery = "missing" }} {
		copy := *s
		copy.Assertions = append([]Assertion(nil), s.Assertions...)
		copy.ServicePolicies = append([]ServicePolicy(nil), s.ServicePolicies...)
		edit(&copy)
		if _, err := copy.BindServicePolicies(); err == nil {
			t.Fatal("invalid discovery reference accepted")
		}
	}
}
