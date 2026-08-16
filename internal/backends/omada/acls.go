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

// ACLType is the controller's ACL scope: gateway, switch, or EAP.
type ACLType int

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

// ACLRule is one row of the Omada 6.x unified ACL list. Endpoint names are
// not on the wire — resolve them with ResolveRules after fetching networks.
type ACLRule struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
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

	// Resolved from LAN networks; omitted on the wire.
	SourceName string `json:"-"`
	DestName   string `json:"-"`
}

// ACLList is a typed fetch of the unified ACL endpoint, including the
// capability flags the controller returns on page 1. ACLDisable is the
// site-level master switch for the ACL scope: when true, rules of this type
// are stored but not enforced.
type ACLList struct {
	Type            ACLType
	Rules           []ACLRule
	ACLDisable      bool
	SupportLanToLan bool
	ExistLanToLan   bool
}

type aclListMeta struct {
	ACLDisable      bool `json:"aclDisable"`
	SupportLanToLan bool `json:"supportLanToLan"`
	ExistLanToLan   bool `json:"existLanToLan"`
}

// FetchACLs loads every page of sites/<id>/setting/firewall/acls?type=N.
// An empty list is success (no rules of that type). The type query is
// required: without it the controller returns errorCode -1.
func (c *Client) FetchACLs(ctx context.Context, siteID string, typ ACLType) (ACLList, error) {
	path := aclCollectionPath(siteID)
	extra := "type=" + strconv.Itoa(int(typ))
	rules, _, meta, err := fetchPagedMeta[ACLRule, aclListMeta](ctx, c, path, defaultPageSize, extra)
	if err != nil {
		return ACLList{}, fmt.Errorf("fetching ACL rules (type %d): %w", typ, err)
	}
	if rules == nil {
		rules = []ACLRule{}
	}
	for i := range rules {
		rules[i].Type = typ
	}
	return ACLList{
		Type:            typ,
		Rules:           rules,
		ACLDisable:      meta.ACLDisable,
		SupportLanToLan: meta.SupportLanToLan,
		ExistLanToLan:   meta.ExistLanToLan,
	}, nil
}

// GetACLRules returns switch (inter-VLAN) ACL rules (type=1).
func (c *Client) GetACLRules(ctx context.Context, siteID string) ([]ACLRule, error) {
	list, err := c.FetchACLs(ctx, siteID, ACLTypeSwitch)
	if err != nil {
		return nil, err
	}
	return list.Rules, nil
}

// GetGatewayACLRules returns gateway ACL rules (type=0). Rules are returned
// even when the scope is globally disabled (aclDisable) — they are stored
// but not enforced; inspect FetchACLs for the flag.
func (c *Client) GetGatewayACLRules(ctx context.Context, siteID string) ([]ACLRule, error) {
	list, err := c.FetchACLs(ctx, siteID, ACLTypeGateway)
	if err != nil {
		return nil, err
	}
	return list.Rules, nil
}

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

// RuleMatchesEndpoints reports whether a rule is the from→to pair identified
// by the given networks (IDs first, then resolved names).
func RuleMatchesEndpoints(rule ACLRule, src, dst Network) bool {
	if idsContain(rule.SourceIDs, src.ID) && idsContain(rule.DestIDs, dst.ID) {
		return true
	}
	return strings.EqualFold(rule.SourceName, src.Name) && strings.EqualFold(rule.DestName, dst.Name)
}

// RuleMatchesNames reports whether the rule covers the given from/to
// endpoints (case-insensitive, sanitized). Used by acl_check, which keys
// off spec names. Resolved names are comma-joined when a rule side spans
// several networks, so each side is matched as a set: the requested name
// must be a member of the rule's endpoint set.
func RuleMatchesNames(rule ACLRule, from, to string) bool {
	return nameInSet(splitNames(rule.SourceName), from) && nameInSet(splitNames(rule.DestName), to)
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
