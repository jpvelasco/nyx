package opnsense

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// NatRule is the flat representation of a single NAT row. The wire shape is
// a paged row carrying a `rule` array (the first element is the rule); the
// source/destination nets may be split across `network` and `address`
// fields. Decoding is lenient — a missing field is an empty value, never an
// error, because the controller adds fields across versions.
type NatRule struct {
	RuleUUID    string   `json:"uuid"`
	Interface   []string `json:"interface"`
	Protocol    string   `json:"protocol"`
	Source      string   `json:"-"`
	Destination string   `json:"-"`
	Port        string   `json:"-"`
	LocalPort   string   `json:"-"`
	Target      string   `json:"-"`
	Mode        string   `json:"mode"`
	Type        string   `json:"type"`
	SNATMode    string   `json:"snat_mode"`
	Label       string   `json:"descr"`
	Disabled    bool     `json:"-"`
}

// natEndpoint is the source/destination object inside a NAT rule element:
// the net may be carried in `network`, in `address`, or both.
type natEndpoint struct {
	Network string `json:"network"`
	Address string `json:"address"`
	Port    string `json:"port"`
}

// natRuleElement is the first element of a row's `rule` array.
type natRuleElement struct {
	UUID        string      `json:"uuid"`
	Interface   []string    `json:"interface"`
	Protocol    string      `json:"protocol"`
	Source      natEndpoint `json:"source"`
	Destination natEndpoint `json:"destination"`
	LocalPort   string      `json:"local-port"`
	Target      string      `json:"target"`
	Mode        string      `json:"mode"`
	Type        string      `json:"type"`
	SNATMode    string      `json:"snat_mode"`
	Description string      `json:"descr"`
	Disabled    bool        `json:"disabled"`
	Enabled     *string     `json:"enabled"`
}

// decodeNatRow flattens the first rule element of a paged row into a
// NatRule. A row without a well-formed `rule` element yields nil (skipped,
// not an error).
func decodeNatRow(raw json.RawMessage) *NatRule {
	var row struct {
		Rules []json.RawMessage `json:"rule"`
	}
	if err := json.Unmarshal(raw, &row); err != nil || len(row.Rules) == 0 {
		return nil
	}
	var el natRuleElement
	if err := json.Unmarshal(row.Rules[0], &el); err != nil {
		return nil
	}
	r := &NatRule{
		RuleUUID:    el.UUID,
		Interface:   el.Interface,
		Protocol:    strings.ToUpper(el.Protocol),
		Source:      el.Source.Network,
		Destination: el.Destination.Network,
		Port:        el.Destination.Port,
		LocalPort:   el.LocalPort,
		Target:      el.Target,
		Mode:        el.Mode,
		Type:        el.Type,
		SNATMode:    el.SNATMode,
		Label:       el.Description,
		Disabled:    el.Disabled,
	}
	if r.Source == "" {
		r.Source = el.Source.Address
	}
	if r.Destination == "" {
		r.Destination = el.Destination.Address
	}
	// Some versions carry the enabled flag as a "1"/"0" string instead of
	// the bool above; the string wins when present.
	if el.Enabled != nil {
		r.Disabled = *el.Enabled != "1"
	}
	return r
}

// rawRows turns the rows RawMessage of a paged envelope into per-row
// RawMessages. An empty or malformed envelope yields no rows.
func rawRows(rows json.RawMessage) []json.RawMessage {
	if len(rows) == 0 {
		return nil
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(rows, &arr); err != nil {
		return nil
	}
	return arr
}

// natRules walks one of the NAT search_rule endpoints and flattens the rows.
// decodeErr is the error prefix used when the paging envelope itself is
// malformed.
func (c *Client) natRules(ctx context.Context, path, decodeErr string) ([]NatRule, error) {
	resp, err := c.do(ctx, http.MethodGet, path+"?current=1&rowCount="+strconv.Itoa(listPageSize), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var env pagedEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return nil, fmt.Errorf("%s: %w", decodeErr, err)
	}
	var out []NatRule
	for _, raw := range rawRows(env.Rows) {
		if r := decodeNatRow(raw); r != nil {
			out = append(out, *r)
		}
	}
	return out, nil
}

// GetFirewallRule returns a single firewall rule by UUID
// (GET /api/firewall/filter/get_rule/$uuid).
func (c *Client) GetFirewallRule(ctx context.Context, uuid string) (*FirewallRule, error) {
	resp, err := c.do(ctx, http.MethodGet, "/firewall/filter/get_rule/"+uuid, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var rule FirewallRule
	if err := json.NewDecoder(resp.Body).Decode(&rule); err != nil {
		return nil, fmt.Errorf("decoding firewall rule response: %w", err)
	}
	rule.Disabled = rule.Enabled != "1"
	return &rule, nil
}

// GetPortForwardRules returns all destination NAT (port forward) rules
// (GET /api/firewall/d_nat/search_rule).
func (c *Client) GetPortForwardRules(ctx context.Context) ([]NatRule, error) {
	return c.natRules(ctx, "/firewall/d_nat/search_rule", "decoding port forward rules response")
}

// GetOneToOneRules returns all one-to-one NAT rules
// (GET /api/firewall/one_to_one/search_rule).
func (c *Client) GetOneToOneRules(ctx context.Context) ([]NatRule, error) {
	return c.natRules(ctx, "/firewall/one_to_one/search_rule", "decoding one-to-one rules response")
}

// GetSourceNatRules returns all source NAT rules, including the generic
// outbound-NAT row (GET /api/firewall/source_nat/search_rule). The generic
// row carries the snat_mode field, which also identifies the device's
// outbound NAT posture.
func (c *Client) GetSourceNatRules(ctx context.Context) ([]NatRule, error) {
	return c.natRules(ctx, "/firewall/source_nat/search_rule", "decoding source NAT rules response")
}

// Alias is a firewall address alias (GET /api/firewall/alias/search_item
// row shape).
type Alias struct {
	UUID        string   `json:"uuid"`
	Name        string   `json:"name"`
	Type        string   `json:"type"` // host / net / group / geoip
	Addresses   []string `json:"-"`
	Description string   `json:"description"`
	Disabled    bool     `json:"-"`
}

// aliasRow is the raw row shape; address and details are both present
// depending on version.
type aliasRow struct {
	UUID        string   `json:"uuid"`
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Address     string   `json:"address"`
	Details     []string `json:"details"`
	Enabled     string   `json:"enabled"`
	Disabled    bool     `json:"disabled"`
	Description string   `json:"description"`
}

// GetAliases returns all firewall aliases (GET /api/firewall/alias/search_item).
func (c *Client) GetAliases(ctx context.Context) ([]Alias, error) {
	resp, err := c.do(ctx, http.MethodGet, "/firewall/alias/search_item?current=1&rowCount="+strconv.Itoa(listPageSize), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var env pagedEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return nil, fmt.Errorf("decoding aliases response: %w", err)
	}
	var out []Alias
	for _, raw := range rawRows(env.Rows) {
		var row aliasRow
		if err := json.Unmarshal(raw, &row); err != nil {
			continue
		}
		alias := Alias{
			UUID:        row.UUID,
			Name:        row.Name,
			Type:        row.Type,
			Description: row.Description,
			Disabled:    row.Disabled,
		}
		if row.Enabled != "" {
			alias.Disabled = row.Enabled != "1"
		}
		switch {
		case len(row.Details) > 0:
			alias.Addresses = row.Details
		case row.Address != "":
			alias.Addresses = strings.Split(row.Address, ",")
		}
		out = append(out, alias)
	}
	return out, nil
}

// GetOutboundNatMode returns the outbound (source) NAT mode from the general
// firewall config (GET /api/firewall/filter_base/get). The mode is one of
// "automatic", "hybrid", "advanced", or "disabled" — the key signal for the
// double-NAT check: a transparent-proxy OPNsense should report "disabled"
// (or "advanced" with no source NAT rules).
func (c *Client) GetOutboundNatMode(ctx context.Context) (string, error) {
	resp, err := c.do(ctx, http.MethodGet, "/firewall/filter_base/get", nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result struct {
		General struct {
			SNATMode string `json:"snat_mode"`
		} `json:"general"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decoding firewall base response: %w", err)
	}
	return result.General.SNATMode, nil
}
