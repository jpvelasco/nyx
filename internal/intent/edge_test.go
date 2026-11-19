package intent

import "testing"

func TestSegmentEdge(t *testing.T) {
	spec := &Spec{Version: 1, Site: "example", Networks: []Network{{Name: "trusted", CIDR: "10.0.10.0/24", Edge: "opnsense", Observer: "omada"}}}
	for _, a := range []Assertion{
		{Type: "acl_check", Network: "trusted", Policy: "deny-egress", Expect: "enforced"},
		{Type: "nat_check", Network: "trusted", NatMode: "automatic"},
	} {
		spec.Assertions = []Assertion{a}
		if err := ValidateSpec(spec); err != nil {
			t.Fatal(err)
		}
		if p, err := spec.AssertionProvider(a); p != "opnsense" || err != nil {
			t.Fatalf("provider=%q error=%v", p, err)
		}
		a.Provider = "omada"
		spec.Assertions[0] = a
		if err := ValidateSpec(spec); err == nil {
			t.Fatal("expected conflict with segment edge")
		}
	}
	if edges := spec.SegmentEdges(); len(edges) != 1 || edges[0].Observer != "omada" {
		t.Fatalf("edges=%v", edges)
	}
}
