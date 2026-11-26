package intent

import "testing"

func TestServicePolicyBindings(t *testing.T) {
	spec := &Spec{
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
		if ValidateSpec(&copy) == nil {
			t.Fatal("accepted ambiguous policy or unmatched positive control")
		}
	}
}
