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

// BDD S3.7 — gateway ACL rows come from the per-scope acls/osg-acls path
// (no "type" query, no aclDisable), with the rule name on "description".
func TestFetchACLsLiveGatewayShape(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/abc123/openapi/v1/sites/s1/acls/osg-acls" {
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		writeEnvelope(w, 0, "", `{
			"totalRows":1,"data":[{
				"id":"6a00b0c0d0e0f0a0b0c0d0e1","index":1,"description":"iot-lan-deny",
				"status":true,"policy":0,"protocols":[256],
				"sourceType":0,"sourceIds":["n-iot"],
				"destinationType":0,"destinationIds":["n-lan","n-guest"],
				"direction":{"lanToWan":false,"lanToLan":true,"wanInIds":[],"vpnInIds":[]}
			}]
		}`)
	}))
	list, err := c.FetchACLs(context.Background(), "s1", ACLTypeGateway)
	if err != nil {
		t.Fatalf("FetchACLs: %v", err)
	}
	if len(list.Rules) != 1 {
		t.Fatalf("list = %+v, want one gateway rule", list)
	}
	r := list.Rules[0]
	if r.Name != "iot-lan-deny" {
		t.Errorf("rule name = %q, want the description from the wire", r.Name)
	}
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
	if idsContain(nil, "") || nameInSet(nil, "x") || nameInSet([]string{"iot"}, "") || namesForIDs(nil, nil) != "" {
		t.Error("empty-input helpers should be false/empty")
	}

	// Multi-endpoint rules: a rule side resolves to a comma-joined name list,
	// and the requested name must be a member of that set.
	multi := ACLRule{SourceName: "iot", DestName: "lan,lab,mgmt,camera,guest"}
	if !RuleMatchesNames(multi, "iot", "mgmt") {
		t.Error("RuleMatchesNames should match a member of a multi-dest rule")
	}
	if !RuleMatchesNames(multi, "IoT", "GUEST") {
		t.Error("RuleMatchesNames should be case-insensitive on multi-dest rules")
	}
	if RuleMatchesNames(multi, "iot", "trusted") {
		t.Error("RuleMatchesNames should reject a non-member destination")
	}
	if RuleMatchesNames(multi, "lab", "mgmt") {
		t.Error("RuleMatchesNames should reject a non-member source")
	}
	// The request side is also a comma-joined list (a spec policy can address
	// several networks): covered only when every requested member is in the
	// rule's set.
	if !RuleMatchesNames(multi, "iot", "lan,lab") {
		t.Error("RuleMatchesNames should accept a multi-dest request fully in the rule")
	}
	if RuleMatchesNames(multi, "iot", "lan,trusted") {
		t.Error("RuleMatchesNames should reject a multi-dest request with one non-member")
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

func TestRuleCovers(t *testing.T) {
	rule := ACLRule{
		SourceIDs:  []string{"n-iot"},
		DestIDs:    []string{"n-lan", "n-guest", "n-camera"},
		SourceName: "iot",
		DestName:   "lan,guest,camera",
	}
	src := Network{ID: "n-iot", Name: "iot"}
	cases := []struct {
		name string
		srcs []Network
		dsts []Network
		want bool
	}{
		{"exact pair", []Network{src}, []Network{{ID: "n-lan", Name: "lan"}}, true},
		{"multi-dest rule covers singleton request", []Network{src}, []Network{{ID: "n-guest", Name: "guest"}}, true},
		{"subset of multi-dest rule", []Network{src}, []Network{{ID: "n-lan", Name: "lan"}, {ID: "n-camera", Name: "camera"}}, true},
		{"request endpoint missing from rule", []Network{src}, []Network{{ID: "n-trusted", Name: "trusted"}}, false},
		{"different source", []Network{{ID: "n-lab", Name: "lab"}}, []Network{{ID: "n-lan", Name: "lan"}}, false},
		{"unresolved request falls back to names", []Network{{Name: "iot"}}, []Network{{Name: "guest"}}, true},
		{"name fallback rejects non-member", []Network{{Name: "iot"}}, []Network{{Name: "trusted"}}, false},
		{"nameless request is never covered", []Network{{}}, []Network{{Name: "lan"}}, false},
	}
	for _, tc := range cases {
		if got := RuleCovers(rule, tc.srcs, tc.dsts); got != tc.want {
			t.Errorf("%s: RuleCovers = %v, want %v", tc.name, got, tc.want)
		}
	}
	// A rule with no IDs (fetched before resolution) still covers by name.
	if !RuleCovers(
		ACLRule{SourceName: "lab", DestName: "lan,guest"},
		[]Network{{Name: "lab"}}, []Network{{Name: "guest"}},
	) {
		t.Error("name-only rule should cover a matching name request")
	}
}

func TestNormalizeProtocols(t *testing.T) {
	cases := []struct {
		in   []int
		want []int
	}{
		{nil, []int{ProtocolAll}},
		{[]int{}, []int{ProtocolAll}},
		{[]int{6, 17}, []int{6, 17}},
		{[]int{6, ProtocolAll, 17}, []int{ProtocolAll}},
		{[]int{ProtocolAll}, []int{ProtocolAll}},
	}
	for _, tc := range cases {
		if got := NormalizeProtocols(tc.in); !ProtocolsEqual(got, tc.want) {
			t.Errorf("NormalizeProtocols(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestProtocolsEqual(t *testing.T) {
	cases := []struct {
		a, b []int
		want bool
	}{
		{nil, nil, true},
		{nil, []int{ProtocolAll}, true},                   // empty ≡ all
		{[]int{6, 17}, []int{17, 6}, true},                // order-independent
		{[]int{6, ProtocolAll}, []int{ProtocolAll}, true}, // any set with 256 ≡ {256}
		{[]int{ProtocolAll}, []int{ProtocolAll, ProtocolAll}, true},
		{[]int{6}, nil, false}, // narrower ≠ all (no cover)
		{[]int{6, 17}, []int{6}, false},
		{[]int{6}, []int{6, 17}, false},
	}
	for _, tc := range cases {
		if got := ProtocolsEqual(tc.a, tc.b); got != tc.want {
			t.Errorf("ProtocolsEqual(%v, %v) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestScopeFromLabel(t *testing.T) {
	cases := []struct {
		label string
		want  ACLType
		ok    bool
	}{
		{"gateway", ACLTypeGateway, true},
		{" GATEWAY ", ACLTypeGateway, true},
		{"switch", ACLTypeSwitch, true},
		{"", ACLTypeSwitch, true}, // default scope
		{"eap", 0, false},         // not supported by the mutation surface
		{"bogus", 0, false},
	}
	for _, tc := range cases {
		got, ok := ScopeFromLabel(tc.label)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Errorf("ScopeFromLabel(%q) = %v, %v; want %v, %v", tc.label, got, ok, tc.want, tc.ok)
		}
	}
}
