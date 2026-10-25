package opnsense

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// FilterWrite is the create/update payload for an MVC filter rule.
type FilterWrite struct {
	Action      string
	Interface   string
	Protocol    string
	Source      string
	Destination string
	SourcePort  string
	DestPort    string
	Direction   string
	IPProtocol  string
	Description string
	Enabled     bool
}

// AliasWrite is the create/update payload for a firewall alias.
type AliasWrite struct {
	Name        string
	Type        string
	Addresses   []string
	Description string
	Enabled     bool
}

const (
	filterAddPath    = "/firewall/filter/add_rule"
	filterSetPath    = "/firewall/filter/set_rule/%s"
	filterDelPath    = "/firewall/filter/del_rule/%s"
	aliasAddPath     = "/firewall/alias/add_item"
	aliasSetPath     = "/firewall/alias/set_item/%s"
	aliasDelPath     = "/firewall/alias/del_item/%s"
	aliasReconfigure = "/firewall/alias/reconfigure"
)

func filterWire(w FilterWrite) ([]byte, error) {
	rule := map[string]interface{}{
		"action": strings.ToLower(firstNonEmpty(w.Action, "block")),
	}
	if w.Enabled {
		rule["enabled"] = "1"
	} else {
		rule["enabled"] = "0"
	}
	if w.Interface != "" {
		rule["interface"] = w.Interface
	}
	if w.Protocol != "" {
		rule["protocol"] = strings.ToLower(w.Protocol)
	}
	if w.Source != "" {
		rule["source_net"] = w.Source
	}
	if w.Destination != "" {
		rule["destination_net"] = w.Destination
	}
	if w.SourcePort != "" {
		rule["source_port"] = w.SourcePort
	}
	if w.DestPort != "" {
		rule["destination_port"] = w.DestPort
	}
	if w.Direction != "" {
		rule["direction"] = w.Direction
	}
	if w.IPProtocol != "" {
		rule["ipprotocol"] = w.IPProtocol
	} else {
		rule["ipprotocol"] = "inet"
	}
	if w.Description != "" {
		rule["description"] = w.Description
	}
	return json.Marshal(map[string]interface{}{"rule": rule})
}

func aliasWire(w AliasWrite) ([]byte, error) {
	item := map[string]interface{}{
		"name":    w.Name,
		"type":    firstNonEmpty(w.Type, "network"),
		"content": strings.Join(w.Addresses, "\n"),
	}
	if w.Enabled {
		item["enabled"] = "1"
	} else {
		item["enabled"] = "0"
	}
	if w.Description != "" {
		item["description"] = w.Description
	}
	return json.Marshal(map[string]interface{}{"alias": item})
}

// CreateFilterRule POSTs add_rule and returns the uuid.
func (c *Client) CreateFilterRule(ctx context.Context, w FilterWrite) (string, error) {
	body, err := filterWire(w)
	if err != nil {
		return "", err
	}
	return c.natAdd(ctx, filterAddPath, body)
}

// SetFilterRule POSTs set_rule/<uuid>.
func (c *Client) SetFilterRule(ctx context.Context, uuid string, w FilterWrite) error {
	body, err := filterWire(w)
	if err != nil {
		return err
	}
	return c.natSet(ctx, fmt.Sprintf(filterSetPath, uuid), body)
}

// DeleteFilterRule POSTs del_rule/<uuid>.
func (c *Client) DeleteFilterRule(ctx context.Context, uuid string) error {
	return c.natSet(ctx, fmt.Sprintf(filterDelPath, uuid), []byte(`{}`))
}

// CreateAlias POSTs add_item and returns the uuid.
func (c *Client) CreateAlias(ctx context.Context, w AliasWrite) (string, error) {
	body, err := aliasWire(w)
	if err != nil {
		return "", err
	}
	return c.natAdd(ctx, aliasAddPath, body)
}

// SetAlias POSTs set_item/<uuid>.
func (c *Client) SetAlias(ctx context.Context, uuid string, w AliasWrite) error {
	body, err := aliasWire(w)
	if err != nil {
		return err
	}
	return c.natSet(ctx, fmt.Sprintf(aliasSetPath, uuid), body)
}

// DeleteAlias POSTs del_item/<uuid>.
func (c *Client) DeleteAlias(ctx context.Context, uuid string) error {
	return c.natSet(ctx, fmt.Sprintf(aliasDelPath, uuid), []byte(`{}`))
}

// ReconfigureAliases activates staged alias changes.
func (c *Client) ReconfigureAliases(ctx context.Context) error {
	return c.postOK(ctx, aliasReconfigure)
}

// FindFilterRule matches by uuid or description. An explicitly selected
// UUID is authoritative: it is resolved in a dedicated pass across the
// whole collection, and when it is absent the lookup misses — a natural-
// key (label) match must never silently retarget the mutation onto a
// different object.
func FindFilterRule(rows []FirewallRule, uuid, label string) (FirewallRule, bool) {
	if uuid != "" {
		for _, r := range rows {
			if strings.EqualFold(r.RuleUUID, uuid) {
				return r, true
			}
		}
		return FirewallRule{}, false
	}
	if label != "" {
		for _, r := range rows {
			if strings.EqualFold(r.Label, label) {
				return r, true
			}
		}
	}
	return FirewallRule{}, false
}

// FindAlias matches by uuid or name with the same UUID-authoritative
// precedence as FindFilterRule.
func FindAlias(rows []Alias, uuid, name string) (Alias, bool) {
	if uuid != "" {
		for _, a := range rows {
			if strings.EqualFold(a.UUID, uuid) {
				return a, true
			}
		}
		return Alias{}, false
	}
	if name != "" {
		for _, a := range rows {
			if strings.EqualFold(a.Name, name) {
				return a, true
			}
		}
	}
	return Alias{}, false
}

// FilterMatchesWrite reports whether an existing rule already carries the
// requested configuration. Every field the write model carries participates
// in the comparison: a requested field that differs must produce an update,
// never a silent no-op. Fields the wire omits when empty (interface,
// protocol, ports, direction, description) compare only when requested;
// the IP protocol defaults to "inet" on both sides, matching the wire.
func FilterMatchesWrite(r FirewallRule, w FilterWrite) bool {
	if w.Action != "" && !strings.EqualFold(r.Action, w.Action) {
		return false
	}
	if w.Interface != "" && !interfacesMatch(r.Interface, w.Interface) {
		return false
	}
	if w.Protocol != "" && !strings.EqualFold(r.Protocol, w.Protocol) {
		return false
	}
	if w.Source != "" && !strings.EqualFold(r.Source, w.Source) {
		return false
	}
	if w.Destination != "" && !strings.EqualFold(r.Destination, w.Destination) {
		return false
	}
	if w.SourcePort != "" && !strings.EqualFold(r.SourcePort, w.SourcePort) {
		return false
	}
	if w.DestPort != "" && !strings.EqualFold(r.DestPort, w.DestPort) {
		return false
	}
	if w.Direction != "" && !strings.EqualFold(r.Direction, w.Direction) {
		return false
	}
	if !strings.EqualFold(firstNonEmpty(r.IPProtocol, "inet"), firstNonEmpty(w.IPProtocol, "inet")) {
		return false
	}
	if w.Description != "" && !strings.EqualFold(r.Label, w.Description) {
		return false
	}
	wantEnabled := w.Enabled
	haveEnabled := !r.Disabled
	return wantEnabled == haveEnabled
}

// interfacesMatch compares the read model's interface list against the
// write's comma-separated selection as normalized sets.
func interfacesMatch(read []string, write string) bool {
	want := make(map[string]bool)
	for _, w := range strings.Split(write, ",") {
		w = strings.TrimSpace(w)
		if w != "" {
			want[strings.ToLower(w)] = true
		}
	}
	if len(want) == 0 {
		return true
	}
	if len(read) != len(want) {
		return false
	}
	for _, r := range read {
		key := strings.ToLower(strings.TrimSpace(r))
		if !want[key] {
			return false
		}
		want[key] = false // mark seen so duplicates cannot match twice
	}
	return true
}

// AliasMatchesWrite reports whether an existing alias already carries the
// requested configuration. The wire payload always carries the enabled
// state, so the comparison does too: enabling a disabled alias (or the
// reverse) is a change. A requested description must match; an omitted one
// leaves the existing description untouched, matching the wire.
func AliasMatchesWrite(a Alias, w AliasWrite) bool {
	if w.Name != "" && !strings.EqualFold(a.Name, w.Name) {
		return false
	}
	if w.Type != "" && !strings.EqualFold(a.Type, w.Type) {
		return false
	}
	if !BridgeMembersMatch(a.Addresses, w.Addresses) {
		return false
	}
	if !a.Disabled != w.Enabled {
		return false
	}
	if w.Description != "" && !strings.EqualFold(a.Description, w.Description) {
		return false
	}
	return true
}
