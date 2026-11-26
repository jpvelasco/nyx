package intent

import "testing"

func policyFixture() *Spec {
	return &Spec{
		Version: 1, Site: "trusted",
		Networks: []Network{{Name: "iot", CIDR: "10.0.60.0/24"}, {Name: "management", CIDR: "10.0.11.0/24"}},
		Probes:   []Probe{{Name: "source", Host: "source.example", User: "fixture", VLAN: "iot"}, {Name: "control", Host: "control.example", User: "fixture", VLAN: "management"}},
		Policies: []Policy{{Name: "protect-management", From: "iot", To: "management", Action: "deny"}},
		Assertions: []Assertion{
			{Name: "from-iot", Type: "port_check", Runner: "source", Target: "10.0.11.1", Ports: []int{443}, Expect: "closed"},
			{Name: "known-good", Type: "port_check", Runner: "control", Target: "10.0.11.1", Ports: []int{443}, Expect: "open"},
		},
		ServicePolicies: []ServicePolicy{{Policy: "protect-management", Measurement: "from-iot", PositiveControl: "known-good"}},
	}
}

func TestServicePolicyBindings(t *testing.T) {
	spec := policyFixture()
	if err := ValidateSpec(spec); err != nil {
		t.Fatal(err)
	}
	// An explicit service exception takes precedence over its broader deny policy.
	spec.Policies[0].Except = []PolicyException{{Protocol: "TCP", Port: 443, Target: "10.0.11.1"}}
	spec.Assertions[0].Expect = "open"
	bindings, err := spec.BindServicePolicies()
	if err != nil || len(bindings) != 1 || bindings[0].Expected != "allow" {
		t.Fatal("explicit TCP service exception was missed")
	}
	spec.Policies[0].Except = nil
	spec.Assertions[0].Expect = "closed"

	for _, change := range []func(*Spec){
		func(s *Spec) { s.Policies = append(s.Policies, s.Policies[0]) },
		func(s *Spec) { s.Policies[0].Name = "other" },
		func(s *Spec) {
			s.ServicePolicies = []ServicePolicy{{Policy: s.Policies[0].Name, Measurement: "missing", PositiveControl: "known-good"}}
		},
		func(s *Spec) { s.Probes[0].VLAN = "" },
		func(s *Spec) { s.Assertions[0].Target = "10.0.40.1"; s.Assertions[1].Target = "10.0.40.1" },
		func(s *Spec) { s.Assertions[1].Type = "network_health" },
		func(s *Spec) { s.Assertions[1].Protocol = "udp" },
		func(s *Spec) {
			s.Policies[0].Except = []PolicyException{{Port: 443, Protocol: "tcp", Target: "service.example"}}
		},
		func(s *Spec) { s.Assertions[1].Target = "10.0.40.1" },
		func(s *Spec) { s.Assertions[1].Ports = []int{22} },
		func(s *Spec) { s.Probes[0].VLAN = "management" },
		func(s *Spec) { s.Assertions[1].Runner = "source" },
		func(s *Spec) { s.Assertions[0].Target = "controller.example" },
		func(s *Spec) { s.Assertions[0].Expect = "open" },
		func(s *Spec) { s.Assertions[1].Name = "from-iot" },
		func(s *Spec) { s.Policies[0].To = "iot" },
	} {
		copy := *spec
		copy.Assertions = append([]Assertion(nil), spec.Assertions...)
		copy.Probes = append([]Probe(nil), spec.Probes...)
		copy.Policies = append([]Policy(nil), spec.Policies...)
		change(&copy)
		if _, err := copy.BindServicePolicies(); err == nil {
			t.Fatal("accepted ambiguous policy or unmatched positive control")
		}
	}
}

func TestDNSServicePolicyBinding(t *testing.T) {
	for _, tc := range []struct {
		name   string
		except []PolicyException
		action string
		valid  bool
	}{{"permitted", nil, "allow", true}, {"permitted exception", []PolicyException{{Port: 53, Protocol: "any"}}, "deny", true}, {"wrong address", []PolicyException{{Port: 53, Protocol: "any", Target: "10.0.40.1"}}, "deny", false}, {"wrong port", []PolicyException{{Port: 443, Protocol: "any"}}, "deny", false}, {"ambiguous transport", []PolicyException{{Port: 53, Protocol: "tcp"}}, "deny", false}, {"denied DNS", nil, "deny", false}} {
		t.Run(tc.name, func(t *testing.T) {
			s := policyFixture()
			s.Policies[0].Action = tc.action
			s.Policies[0].Except = tc.except
			for i := range s.Assertions {
				a := &s.Assertions[i]
				a.Type = "dns_check"
				a.Server = "10.0.11.1"
				a.Query = "service.example"
				a.ExpectIP = "192.0.2.9"
			}
			_, err := s.BindServicePolicies()
			if (err == nil) != tc.valid {
				t.Fatalf("unexpected policy result %v", err)
			}
			s.Assertions[0].Query = ""
			if _, err := s.BindServicePolicies(); err == nil {
				t.Fatal("missing DNS query accepted")
			}
		})
	}
}

func TestPolicyNetworkAndProbeIdentity(t *testing.T) {
	s := policyFixture()
	s.Networks[0].Zone = "source-zone"
	if s.EndpointCovers("any", "") || s.EndpointCovers(",", "iot") || !s.EndpointCovers("zone:source-zone", "iot") || s.probeInDirection("", "any") {
		t.Fatal("invalid zone membership")
	}
	s.Probes[1].Host = s.Probes[0].Host
	s.Probes[0].Port = 2222
	s.Probes[1].Port = 22
	if _, err := s.BindServicePolicies(); err != nil {
		t.Fatal(err)
	}
}
