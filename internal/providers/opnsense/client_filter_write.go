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

// FindFilterRule matches by uuid or description.
func FindFilterRule(rows []FirewallRule, uuid, label string) (FirewallRule, bool) {
	for _, r := range rows {
		if uuid != "" && strings.EqualFold(r.RuleUUID, uuid) {
			return r, true
		}
		if label != "" && strings.EqualFold(r.Label, label) {
			return r, true
		}
	}
	return FirewallRule{}, false
}

// FindAlias matches by uuid or name.
func FindAlias(rows []Alias, uuid, name string) (Alias, bool) {
	for _, a := range rows {
		if uuid != "" && strings.EqualFold(a.UUID, uuid) {
			return a, true
		}
		if name != "" && strings.EqualFold(a.Name, name) {
			return a, true
		}
	}
	return Alias{}, false
}

// FilterMatchesWrite reports whether an existing rule already has the
// requested action, endpoints, and description.
func FilterMatchesWrite(r FirewallRule, w FilterWrite) bool {
	if w.Action != "" && !strings.EqualFold(r.Action, w.Action) {
		return false
	}
	if w.Source != "" && !strings.EqualFold(r.Source, w.Source) {
		return false
	}
	if w.Destination != "" && !strings.EqualFold(r.Destination, w.Destination) {
		return false
	}
	if w.Description != "" && !strings.EqualFold(r.Label, w.Description) {
		return false
	}
	wantEnabled := w.Enabled
	haveEnabled := !r.Disabled
	return wantEnabled == haveEnabled
}

// AliasMatchesWrite reports whether an existing alias already has the
// requested type, name, and address set.
func AliasMatchesWrite(a Alias, w AliasWrite) bool {
	if w.Name != "" && !strings.EqualFold(a.Name, w.Name) {
		return false
	}
	if w.Type != "" && !strings.EqualFold(a.Type, w.Type) {
		return false
	}
	return BridgeMembersMatch(a.Addresses, w.Addresses)
}
