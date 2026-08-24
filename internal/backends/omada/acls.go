package omada

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// ACL types on the unified 6.x endpoint (sites/<id>/setting/firewall/acls?type=N).
const (
	ACLTypeGateway ACLType = 0
	ACLTypeSwitch  ACLType = 1
	ACLTypeEAP     ACLType = 2
)

// ACL policies as sent on the wire. The controller UI maps 0 → deny, 1 → permit.
const (
	ACLPolicyDeny   ACLPolicy = 0
	ACLPolicyPermit ACLPolicy = 1
)

// ProtocolAll is the Omada sentinel for "all IP protocols" ([256]).
const ProtocolAll = 256

// NormalizeProtocols returns the canonical protocol set for a rule: the
// [256] sentinel when the set is empty or already contains all-protocols,
// otherwise the set unchanged.
func NormalizeProtocols(protocols []int) []int {
	if len(protocols) == 0 {
		return []int{ProtocolAll}
	}
	for _, p := range protocols {
		if p == ProtocolAll {
			return []int{ProtocolAll}
		}
	}
	return protocols
}

// ProtocolsEqual reports whether two protocol sets describe the same
// surface after normalization (order-independent, all-protocols ≡ empty).
func ProtocolsEqual(a, b []int) bool {
	na, nb := NormalizeProtocols(a), NormalizeProtocols(b)
	if len(na) != len(nb) {
		return false
	}
	for _, p := range na {
		if !intsContain(nb, p) {
			return false
		}
	}
	return true
}

func intsContain(set []int, want int) bool {
	for _, p := range set {
		if p == want {
			return true
		}
	}
	return false
}

// ACLType is the controller's ACL scope: gateway, switch, or EAP.
type ACLType int

// ScopeFromLabel maps an agent-facing scope label to its ACL type. EAP
// rules are not supported by the mutation surface (their wire shape has not
// been observed), so it is deliberately not accepted here.
func ScopeFromLabel(label string) (ACLType, bool) {
	switch strings.ToLower(strings.TrimSpace(label)) {
	case "gateway":
		return ACLTypeGateway, true
	case "switch", "":
		return ACLTypeSwitch, true
	default:
		return 0, false
	}
}

// ACLPolicy is the controller's numeric policy (0=deny, 1=permit).
type ACLPolicy int

// String returns the controller-facing policy label used in agent output.
func (p ACLPolicy) String() string {
	switch p {
	case ACLPolicyDeny:
		return "drop"
	case ACLPolicyPermit:
		return "accept"
	default:
		return strconv.Itoa(int(p))
	}
}

// Action returns the intent-spec action ("deny" / "allow"), or "" if unknown.
func (p ACLPolicy) Action() string {
	switch p {
	case ACLPolicyDeny:
		return "deny"
	case ACLPolicyPermit:
		return "allow"
	default:
		return ""
	}
}

// IsDeny reports whether the policy is a deny/drop rule.
func (p ACLPolicy) IsDeny() bool { return p == ACLPolicyDeny }

// MatchesAction reports whether this policy implements the intent action.
func (p ACLPolicy) MatchesAction(action string) bool {
	return p.Action() == action
}

// PolicyFromAction maps an intent action to the controller policy.
// Unknown actions return false.
func PolicyFromAction(action string) (ACLPolicy, bool) {
	switch action {
	case "deny":
		return ACLPolicyDeny, true
	case "allow":
		return ACLPolicyPermit, true
	default:
		return 0, false
	}
}

// ProtocolsLabel renders a protocol list for agent-facing output.
// The [256] sentinel (or a single ProtocolAll) is reported as "all".
func ProtocolsLabel(protocols []int) string {
	if len(protocols) == 0 {
		return ""
	}
	if len(protocols) == 1 && protocols[0] == ProtocolAll {
		return "all"
	}
	for _, p := range protocols {
		if p == ProtocolAll {
			return "all"
		}
	}
	parts := make([]string, len(protocols))
	for i, p := range protocols {
		parts[i] = strconv.Itoa(p)
	}
	return strings.Join(parts, ",")
}

// EndpointKind is a source/destination classifier. The live 6.x API sends
// this as an int (0 = network). Older fixtures and some docs use the
// string "network" — both decode.
type EndpointKind int

// EndpointNetwork is a LAN network / VLAN endpoint.
const EndpointNetwork EndpointKind = 0

// String returns the agent-facing label for the endpoint kind.
func (k EndpointKind) String() string {
	if k == EndpointNetwork {
		return "network"
	}
	return strconv.Itoa(int(k))
}

// UnmarshalJSON accepts a JSON number or the string "network".
func (k *EndpointKind) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) > 0 && data[0] == '"' {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		if strings.EqualFold(s, "network") || s == "" {
			*k = EndpointNetwork
			return nil
		}
		return fmt.Errorf("unknown ACL endpoint kind %q", s)
	}
	var n int
	if err := json.Unmarshal(data, &n); err != nil {
		return err
	}
	*k = EndpointKind(n)
	return nil
}

// ACLDirection is the gateway rule's path: LAN-to-LAN, LAN-to-WAN, WAN-in, VPN-in.
type ACLDirection struct {
	LANToWAN bool     `json:"lanToWan"`
	LANToLAN bool     `json:"lanToLan"`
	WANInIDs []string `json:"wanInIds"`
	VPNInIDs []string `json:"vpnInIds"`
}

// ACLRule is one row of the Omada Open API ACL list (per-scope paths). The
// Open API list result carries no type field — the scope comes from the
// path the rule was fetched from (set after fetching). Endpoint names are
// not on the wire — resolve them with ResolveRules after fetching networks.
type ACLRule struct {
	ID          string       `json:"id"`
	Name        string       `json:"description"`
	Type        ACLType      `json:"type"`
	Status      bool         `json:"status"`
	Policy      ACLPolicy    `json:"policy"`
	Protocols   []int        `json:"protocols"`
	SourceType  EndpointKind `json:"sourceType"`
	SourceIDs   []string     `json:"sourceIds"`
	DestType    EndpointKind `json:"destinationType"`
	DestIDs     []string     `json:"destinationIds"`
	Direction   ACLDirection `json:"direction"`
	Index       int          `json:"index"`
	TimeRangeID string       `json:"timeRangeId,omitempty"`
	// BindingType is switch-scope only (0 = all ports, 1 = custom ports,
	// 2 = all switch VLAN, 3 = custom switch VLAN). The controller
	// rejects switch-scope creates that omit it (errorCode -1); it is
	// absent on gateway-scope rules and reads as 0.
	BindingType int `json:"bindingType"`

	// Resolved from LAN networks; omitted on the wire.
	SourceName string `json:"-"`
	DestName   string `json:"-"`
}

// ACLList is a typed fetch of one ACL scope. The meta fields are retained
// for the legacy internal API; the Open API read paths carry no capability
// flags, so they stay zero-valued.
type ACLList struct {
	Type            ACLType
	Rules           []ACLRule
	ACLDisable      bool
	SupportLanToLan bool
	ExistLanToLan   bool
}

// FetchACLs loads every page of the ACL list for one scope: osw-acls for
// switch rules, osg-acls for gateway rules. An empty list is success (no
// rules in that scope).
func (c *Client) FetchACLs(ctx context.Context, siteID string, typ ACLType) (ACLList, error) {
	rules, _, err := fetchPaged[ACLRule](ctx, c, aclReadPath(siteID, typ), defaultPageSize)
	if err != nil {
		return ACLList{}, fmt.Errorf("fetching ACL rules (type %d): %w", typ, err)
	}
	if rules == nil {
		rules = []ACLRule{}
	}
	for i := range rules {
		rules[i].Type = typ
	}
	return ACLList{Type: typ, Rules: rules}, nil
}

// GetACLRules returns switch (inter-VLAN) ACL rules (type=1).
func (c *Client) GetACLRules(ctx context.Context, siteID string) ([]ACLRule, error) {
	list, err := c.FetchACLs(ctx, siteID, ACLTypeSwitch)
	if err != nil {
		return nil, err
	}
	return list.Rules, nil
}

// GetGatewayACLRules returns gateway ACL rules (type=0).
func (c *Client) GetGatewayACLRules(ctx context.Context, siteID string) ([]ACLRule, error) {
	list, err := c.FetchACLs(ctx, siteID, ACLTypeGateway)
	if err != nil {
		return nil, err
	}
	return list.Rules, nil
}

// aclReadPath is the Open API read path for one ACL scope. Writes still use
// the unified setting/firewall/acls collection (see aclItemPath).
func aclReadPath(siteID string, typ ACLType) string {
	if typ == ACLTypeSwitch {
		return fmt.Sprintf("sites/%s/acls/osw-acls", siteID)
	}
	return fmt.Sprintf("sites/%s/acls/osg-acls", siteID)
}

// aclCollectionPath is the unified write collection for ACL rules;
// refactored to the per-scope Open API paths in ref5.
func aclCollectionPath(siteID string) string {
	return fmt.Sprintf("sites/%s/setting/firewall/acls", siteID)
}

func aclItemPath(siteID, ruleID string) string {
	return fmt.Sprintf("sites/%s/setting/firewall/acls/%s", siteID, ruleID)
}

// ResolveRules fills SourceName/DestName from LAN network IDs. Names already
// set are left alone. Unknown IDs stay empty.
func ResolveRules(rules []ACLRule, networks []Network) {
	byID := make(map[string]Network, len(networks))
	for _, n := range networks {
		byID[n.ID] = n
	}
	for i := range rules {
		if rules[i].SourceName == "" {
			rules[i].SourceName = namesForIDs(rules[i].SourceIDs, byID)
		}
		if rules[i].DestName == "" {
			rules[i].DestName = namesForIDs(rules[i].DestIDs, byID)
		}
	}
}

func namesForIDs(ids []string, byID map[string]Network) string {
	if len(ids) == 0 {
		return ""
	}
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		if n, ok := byID[id]; ok {
			parts = append(parts, n.Name)
		}
	}
	return strings.Join(parts, ",")
}

// RuleCovers reports whether the rule's endpoint sets include all of the
// given source and destination networks. A multi-endpoint rule (several
// sourceIds/destinationIds) therefore covers any request whose endpoints are
// a subset of its sets. IDs are tried first, with a resolved-name fallback
// for rules fetched before resolution or with unknown IDs.
func RuleCovers(rule ACLRule, srcs, dsts []Network) bool {
	if !allIn(rule.SourceIDs, srcs) || !allIn(rule.DestIDs, dsts) {
		return false
	}
	if allResolved(srcs) && allResolved(dsts) {
		return true
	}
	// Name fallback: every requested network must be a member of the rule's
	// resolved name list on its side.
	return allNameInSet(srcs, splitNames(rule.SourceName)) && allNameInSet(dsts, splitNames(rule.DestName))
}

// RuleMatchesEndpoints reports whether a rule is the from→to pair identified
// by the given networks (IDs first, then resolved names).
func RuleMatchesEndpoints(rule ACLRule, src, dst Network) bool {
	return RuleCovers(rule, []Network{src}, []Network{dst})
}

// allIn reports whether every network's ID is present in ids. A requested
// network without an ID is not covered (IDs are the primary identity).
func allIn(ids []string, nets []Network) bool {
	for _, n := range nets {
		if n.ID != "" && !idsContain(ids, n.ID) {
			return false
		}
	}
	return true
}

// allResolved reports whether every network carries a resolved ID.
func allResolved(nets []Network) bool {
	for _, n := range nets {
		if n.ID == "" {
			return false
		}
	}
	return true
}

// allNameInSet reports whether every network's name is a member of the
// comma-resolved rule side (case-insensitive, sanitized).
func allNameInSet(nets []Network, set []string) bool {
	for _, n := range nets {
		if !nameInSet(set, n.Name) {
			return false
		}
	}
	return true
}

// RuleMatchesNames reports whether the rule covers the given from/to
// endpoints (case-insensitive, sanitized). Used by acl_check, which keys
// off spec names. Both the rule sides (resolved names of a multi-endpoint
// rule) and the request sides (spec policies address several networks) are
// comma-joined lists, so coverage is set membership per side: every
// requested member must be a member of the rule's endpoint set.
func RuleMatchesNames(rule ACLRule, from, to string) bool {
	return namesInSet(splitNames(from), splitNames(rule.SourceName)) &&
		namesInSet(splitNames(to), splitNames(rule.DestName))
}

// namesInSet reports whether every wanted name (case-insensitive,
// sanitized) is a member of the candidate set. An empty want list never
// matches: a rule with no endpoint on that side covers nothing.
func namesInSet(wants, candidates []string) bool {
	if len(wants) == 0 {
		return false
	}
	for _, want := range wants {
		if !nameInSet(candidates, want) {
			return false
		}
	}
	return true
}

// splitNames breaks a comma-joined resolved name list into its members.
func splitNames(joined string) []string {
	parts := strings.Split(joined, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func nameInSet(candidates []string, want string) bool {
	if want == "" || len(candidates) == 0 {
		return false
	}
	for _, got := range candidates {
		if strings.EqualFold(got, want) || strings.EqualFold(sanitizeName(got), sanitizeName(want)) {
			return true
		}
	}
	return false
}

func idsContain(ids []string, want string) bool {
	if want == "" {
		return false
	}
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}
