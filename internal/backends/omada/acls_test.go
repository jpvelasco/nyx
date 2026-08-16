package omada

import (
	"testing"

	"github.com/jpvelasco/nyx/internal/intent"
)

func TestACLPolicyMapping(t *testing.T) {
	if ACLPolicyDeny.String() != "drop" || ACLPolicyPermit.String() != "accept" {
		t.Errorf("String() = %q/%q, want drop/accept", ACLPolicyDeny.String(), ACLPolicyPermit.String())
	}
	if ACLPolicyDeny.Action() != "deny" || ACLPolicyPermit.Action() != "allow" {
		t.Errorf("Action() = %q/%q, want deny/allow", ACLPolicyDeny.Action(), ACLPolicyPermit.Action())
	}
	if !ACLPolicyDeny.IsDeny() || ACLPolicyPermit.IsDeny() {
		t.Error("IsDeny mismatch")
	}
	if !ACLPolicyDeny.MatchesAction("deny") || ACLPolicyPermit.MatchesAction("deny") {
		t.Error("MatchesAction deny mismatch")
	}
	p, ok := PolicyFromAction("allow")
	if !ok || p != ACLPolicyPermit {
		t.Errorf("PolicyFromAction(allow) = %v, %v", p, ok)
	}
	d, ok := PolicyFromAction("deny")
	if !ok || d != ACLPolicyDeny {
		t.Errorf("PolicyFromAction(deny) = %v, %v", d, ok)
	}
	if _, ok := PolicyFromAction("drop"); ok {
		t.Error("PolicyFromAction(drop) should reject unknown action")
	}
	unknown := ACLPolicy(9)
	if unknown.String() != "9" || unknown.Action() != "" {
		t.Errorf("unknown policy String/Action = %q/%q", unknown.String(), unknown.Action())
	}
}

func TestProtocolsLabel(t *testing.T) {
	cases := []struct {
		in   []int
		want string
	}{
		{nil, ""},
		{[]int{ProtocolAll}, "all"},
		{[]int{6, ProtocolAll, 17}, "all"},
		{[]int{6, 17}, "6,17"},
	}
	for _, tc := range cases {
		if got := ProtocolsLabel(tc.in); got != tc.want {
			t.Errorf("ProtocolsLabel(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestResolveRulesAndMatch(t *testing.T) {
	nets := []Network{
		{ID: "n1", Name: "Trusted"},
		{ID: "n2", Name: "IoT"},
	}
	rules := []ACLRule{{
		SourceIDs: []string{"n2"},
		DestIDs:   []string{"n1"},
	}}
	ResolveRules(rules, nets)
	if rules[0].SourceName != "IoT" || rules[0].DestName != "Trusted" {
		t.Errorf("resolved names = %q -> %q, want IoT -> Trusted", rules[0].SourceName, rules[0].DestName)
	}
	if !RuleMatchesEndpoints(rules[0], nets[1], nets[0]) {
		t.Error("RuleMatchesEndpoints should match by IDs")
	}
	if !RuleMatchesNames(rules[0], "iot", "trusted") {
		t.Error("RuleMatchesNames should match sanitized names")
	}
	if RuleMatchesNames(rules[0], "guest", "trusted") {
		t.Error("RuleMatchesNames should reject a different source")
	}

	named := ACLRule{SourceName: "IoT", DestName: "Trusted"}
	if !RuleMatchesEndpoints(named, Network{Name: "IoT"}, Network{Name: "Trusted"}) {
		t.Error("RuleMatchesEndpoints should fall back to names when IDs are absent")
	}
	if idsContain(nil, "") || namesMatch("", "x") || namesForIDs(nil, nil) != "" {
		t.Error("empty-input helpers should be false/empty")
	}

	already := []ACLRule{{SourceName: "keep", DestName: "keep", SourceIDs: []string{"n2"}, DestIDs: []string{"n1"}}}
	ResolveRules(already, nets)
	if already[0].SourceName != "keep" || already[0].DestName != "keep" {
		t.Error("ResolveRules must not overwrite names already set")
	}
}

func TestResolveRuleEndpointIDs(t *testing.T) {
	nets := map[string]intent.Network{"net-1": {Name: "lan"}, "net-2": {Name: "iot"}}
	got := resolveRuleEndpoint("network", "", []string{"net-1", "net-2"}, nets)
	if got != "lan,iot" {
		t.Errorf("multi-id resolve = %q, want lan,iot", got)
	}
	got = resolveRuleEndpoint("network", "Guest", []string{"net-1"}, nets)
	if got != "guest" {
		t.Errorf("name should win = %q, want guest", got)
	}
	got = resolveRuleEndpoint("inet", "", nil, nets)
	if got != "inet" {
		t.Errorf("empty ids fallback = %q, want inet", got)
	}
}
