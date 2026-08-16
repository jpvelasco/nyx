package omada

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/jpvelasco/nyx/internal/intent"
)

func TestEndpointKindUnmarshal(t *testing.T) {
	cases := []struct {
		in   string
		want EndpointKind
	}{
		{`0`, EndpointNetwork},
		{`"network"`, EndpointNetwork},
		{`"Network"`, EndpointNetwork},
		{`2`, EndpointKind(2)},
	}
	for _, tc := range cases {
		var k EndpointKind
		if err := json.Unmarshal([]byte(tc.in), &k); err != nil {
			t.Fatalf("Unmarshal(%s): %v", tc.in, err)
		}
		if k != tc.want {
			t.Errorf("Unmarshal(%s) = %v, want %v", tc.in, k, tc.want)
		}
	}
	var bad EndpointKind
	if err := json.Unmarshal([]byte(`"ip-group"`), &bad); err == nil {
		t.Error("expected error for unknown string kind")
	}
	if err := json.Unmarshal([]byte(`{`), &bad); err == nil {
		t.Error("expected error for truncated JSON")
	}
	if err := json.Unmarshal([]byte(`true`), &bad); err == nil {
		t.Error("expected error for bool JSON")
	}
	if EndpointKind(2).String() != "2" {
		t.Errorf("String() for kind 2 = %q, want 2", EndpointKind(2).String())
	}
}

func TestFetchACLsLiveGatewayShape(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("type") != "0" {
			writeEnvelope(w, -1, "General error.", "null")
			return
		}
		writeEnvelope(w, 0, "", `{
			"totalRows":1,"data":[{
				"id":"6a00b0c0d0e0f0a0b0c0d0e1","type":0,"index":1,"name":"iot-lan-deny",
				"status":true,"policy":0,"protocols":[256],
				"sourceType":0,"sourceIds":["n-iot"],
				"destinationType":0,"destinationIds":["n-lan","n-guest"],
				"direction":{"lanToWan":false,"lanToLan":true,"wanInIds":[],"vpnInIds":[]}
			}],
			"aclDisable":true
		}`)
	}))
	list, err := c.FetchACLs(context.Background(), "s1", ACLTypeGateway)
	if err != nil {
		t.Fatalf("FetchACLs: %v", err)
	}
	if !list.ACLDisable || len(list.Rules) != 1 {
		t.Fatalf("list = %+v, want one gateway rule", list)
	}
	r := list.Rules[0]
	if r.SourceType != EndpointNetwork || r.DestType != EndpointNetwork {
		t.Errorf("kinds = src %v dst %v, want network", r.SourceType, r.DestType)
	}
	if !r.Direction.LANToLAN || r.Direction.LANToWAN {
		t.Errorf("direction = %+v, want lanToLan only", r.Direction)
	}
	if len(r.DestIDs) != 2 || r.Policy != ACLPolicyDeny {
		t.Errorf("rule = %+v, want deny to two dest networks", r)
	}
}

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
