package service

import (
	"context"
	"fmt"
	"strings"

	opnsensebackend "github.com/jpvelasco/nyx/internal/providers/opnsense"
)

// OpnsenseFirewallRule is a firewall filter rule in a flat, agent-friendly
// shape. Disabled is true when the rule is not active.
type OpnsenseFirewallRule struct {
	Sequence    string   `json:"sequence,omitempty"`
	UUID        string   `json:"uuid"`
	Enabled     bool     `json:"enabled"`
	Disabled    bool     `json:"disabled"`
	Action      string   `json:"action"`
	Interfaces  []string `json:"interfaces"`
	Protocol    string   `json:"protocol"`
	Source      string   `json:"source"`
	Destination string   `json:"destination"`
	SourcePort  string   `json:"source_port,omitempty"`
	DestPort    string   `json:"destination_port,omitempty"`
	Direction   string   `json:"direction,omitempty"`
	IPProtocol  string   `json:"ipprotocol,omitempty"`
	Label       string   `json:"label"`
	Categories  []string `json:"categories,omitempty"`
}

// OpnsenseAlias is a firewall address alias.
type OpnsenseAlias struct {
	UUID        string   `json:"uuid"`
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Addresses   []string `json:"addresses"`
	Description string   `json:"description,omitempty"`
	Disabled    bool     `json:"disabled"`
}

// ListFirewallRules returns the firewall filter rules.
func (s *OpnsenseService) ListFirewallRules(ctx context.Context, opts OpnsenseOptions) ([]OpnsenseFirewallRule, error) {
	client := s.client(opts)
	rules, err := client.GetFirewallRules(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]OpnsenseFirewallRule, 0, len(rules))
	for _, r := range rules {
		out = append(out, flattenFirewallRule(r))
	}
	return out, nil
}

// GetFirewallRule returns a single firewall rule by UUID.
func (s *OpnsenseService) GetFirewallRule(ctx context.Context, opts OpnsenseOptions, uuid string) (*OpnsenseFirewallRule, error) {
	client := s.client(opts)
	rule, err := client.GetFirewallRule(ctx, uuid)
	if err != nil {
		return nil, err
	}
	r := flattenFirewallRule(*rule)
	return &r, nil
}

func flattenFirewallRule(r opnsensebackend.FirewallRule) OpnsenseFirewallRule {
	return OpnsenseFirewallRule{
		UUID: r.RuleUUID, Sequence: r.Sequence,
		Enabled:     !r.Disabled,
		Disabled:    r.Disabled,
		Action:      r.Action,
		Interfaces:  r.Interface,
		Protocol:    r.Protocol,
		Source:      r.Source,
		Destination: r.Destination,
		SourcePort:  r.SourcePort,
		DestPort:    r.DestPort,
		Direction:   r.Direction,
		IPProtocol:  r.IPProtocol,
		Label:       r.Label,
		Categories:  r.Categories,
	}
}

// ListAliases returns all firewall aliases.
func (s *OpnsenseService) ListAliases(ctx context.Context, opts OpnsenseOptions) ([]OpnsenseAlias, error) {
	client := s.client(opts)
	aliases, err := client.GetAliases(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching aliases: %w", err)
	}
	out := make([]OpnsenseAlias, 0, len(aliases))
	for _, a := range aliases {
		out = append(out, OpnsenseAlias{
			UUID:        a.UUID,
			Name:        a.Name,
			Type:        a.Type,
			Addresses:   a.Addresses,
			Description: a.Description,
			Disabled:    a.Disabled,
		})
	}
	return out, nil
}

// OpnsenseFilterRequest is a plan/apply filter-rule or alias mutation.
type OpnsenseFilterRequest struct {
	CreateOnly      bool   // Preserve an existing resource if a composed create plan becomes an update.
	Kind            string // filter (default) | alias
	UUID            string
	Name            string
	Action          string
	Interface       string
	Protocol        string
	SourcePort      string
	DestinationPort string
	Direction       string
	AddressFamily   string
	Source          string
	Destination     string
	Addresses       []string
	AliasType       string
	Description     string
	Enabled         bool
	Delete          bool
}

// OpnsenseFilterPlan previews a filter/alias mutation.
type OpnsenseFilterPlan struct {
	Before  *OpnsenseFirewallRule `json:"before,omitempty"`
	Desired *OpnsenseFirewallRule `json:"desired,omitempty"`
	Action  string                `json:"action"`
	Kind    string                `json:"kind"`
	UUID    string                `json:"uuid,omitempty"`
}

// OpnsenseFilterApplyResult is the apply outcome.
type OpnsenseFilterApplyResult struct {
	Outcome string `json:"outcome"`
	Kind    string `json:"kind"`
	UUID    string `json:"uuid,omitempty"`
	DryRun  bool   `json:"dry_run"`
}

func filterKind(kind string) string {
	if strings.EqualFold(kind, "alias") {
		return "alias"
	}
	return "filter"
}

// PlanFilter previews creating, updating, or deleting a filter rule or alias.
func (s *OpnsenseService) PlanFilter(ctx context.Context, opts OpnsenseOptions, req OpnsenseFilterRequest) (*OpnsenseFilterPlan, error) {
	if err := req.validateSelectors(); err != nil {
		return nil, err
	}
	kind := filterKind(req.Kind)
	plan := &OpnsenseFilterPlan{Kind: kind, UUID: req.UUID}
	client := s.client(opts)
	if kind == "alias" {
		if req.Name == "" && req.UUID == "" {
			return nil, fmt.Errorf("name or uuid is required for alias mutations")
		}
		aliases, err := client.GetAliases(ctx)
		if err != nil {
			return nil, err
		}
		cur, ok := opnsensebackend.FindAlias(aliases, req.UUID, req.Name)
		if req.Delete {
			if !ok {
				plan.Action = "unchanged"
				return plan, nil
			}
			plan.Action = "delete"
			plan.UUID = cur.UUID
			return plan, nil
		}
		w := opnsensebackend.AliasWrite{Name: req.Name, Type: req.AliasType, Addresses: req.Addresses, Description: req.Description, Enabled: req.Enabled}
		if !ok {
			plan.Action = "create"
			return plan, nil
		}
		plan.UUID = cur.UUID
		if opnsensebackend.AliasMatchesWrite(cur, w) {
			plan.Action = "unchanged"
			return plan, nil
		}
		plan.Action = "update"
		return plan, nil
	}
	if req.UUID == "" && req.Name == "" && !req.Delete {
		if req.Source == "" || req.Destination == "" {
			return nil, fmt.Errorf("source and destination are required to create a filter rule")
		}
	}
	rules, err := client.GetFirewallRules(ctx)
	if err != nil {
		return nil, err
	}
	cur, ok, err := req.findRule(rules)
	if err != nil {
		return nil, err
	}
	if req.Delete {
		if !ok {
			plan.Action = "unchanged"
			return plan, nil
		}
		plan.Action = "delete"
		plan.UUID = cur.RuleUUID
		return plan, nil
	}
	w := req.write()
	if req.scoped() {
		plan.Desired = &OpnsenseFirewallRule{
			Enabled: w.Enabled, Disabled: !w.Enabled, Action: w.Action,
			Interfaces: strings.Split(w.Interface, ","),
			Protocol:   firstNonEmptySvc(w.Protocol, "any"),
			Source:     w.Source, Destination: w.Destination,
			SourcePort: firstNonEmptySvc(w.SourcePort, "any"),
			DestPort:   firstNonEmptySvc(w.DestPort, "any"),
			Direction:  firstNonEmptySvc(w.Direction, "in"),
			IPProtocol: w.IPProtocol, Label: w.Description,
		}
		if ok {
			before := flattenFirewallRule(cur)
			plan.Before = &before
			plan.Desired.Sequence = cur.Sequence
		}
	}
	if !ok {
		plan.Action = "create"
		return plan, nil
	}
	plan.UUID = cur.RuleUUID
	if (req.scoped() && opnsensebackend.ExactFilterMatch(cur, w)) || (!req.scoped() && opnsensebackend.FilterMatchesWrite(cur, w)) {
		plan.Action = "unchanged"
		return plan, nil
	}
	plan.Action = "update"
	return plan, nil
}

func firstNonEmptySvc(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// ApplyFilter creates/updates/deletes a filter rule or alias. Real apply
// reconfigures aliases and always POSTs firewall/filter/apply.
func (s *OpnsenseService) ApplyFilter(ctx context.Context, opts OpnsenseOptions, req OpnsenseFilterRequest, dryRun bool) (*OpnsenseFilterApplyResult, error) {
	plan, err := s.PlanFilter(ctx, opts, req)
	if err != nil {
		return nil, err
	}
	res := &OpnsenseFilterApplyResult{Outcome: plan.Action, Kind: plan.Kind, UUID: plan.UUID, DryRun: dryRun}
	if err := preserveExisting(req.CreateOnly, plan.Action); err != nil {
		return nil, err
	}
	if dryRun || plan.Action == "unchanged" {
		return res, nil
	}
	client := s.client(opts)
	if plan.Kind == "alias" {
		w := opnsensebackend.AliasWrite{Name: req.Name, Type: req.AliasType, Addresses: req.Addresses, Description: req.Description, Enabled: req.Enabled}
		switch plan.Action {
		case "create":
			id, err := client.CreateAlias(ctx, w)
			if err != nil {
				return nil, err
			}
			res.UUID = id
			res.Outcome = "created"
		case "update":
			if err := client.SetAlias(ctx, plan.UUID, w); err != nil {
				return nil, err
			}
			res.Outcome = "updated"
		case "delete":
			if err := client.DeleteAlias(ctx, plan.UUID); err != nil {
				return nil, err
			}
			res.Outcome = "deleted"
		}
		if err := client.ReconfigureAliases(ctx); err != nil {
			return nil, err
		}
		if err := client.ApplyFirewallFilter(ctx); err != nil {
			return nil, err
		}
		return res, nil
	}
	w := req.write()
	switch plan.Action {
	case "create":
		id, err := client.CreateFilterRule(ctx, w)
		if err != nil {
			return nil, err
		}
		res.UUID = id
		res.Outcome = "created"
	case "update":
		if err := client.SetFilterRule(ctx, plan.UUID, w); err != nil {
			return nil, err
		}
		res.Outcome = "updated"
	case "delete":
		if err := client.DeleteFilterRule(ctx, plan.UUID); err != nil {
			return nil, err
		}
		res.Outcome = "deleted"
	}
	if err := client.ApplyFirewallFilter(ctx); err != nil {
		return nil, err
	}
	if req.scoped() {
		rows, err := client.GetFirewallRules(ctx)
		if err != nil {
			return nil, err
		}
		observed, ok := opnsensebackend.FindFilterRule(rows, res.UUID, "")
		if res.UUID == "" || !ok || !opnsensebackend.ExactFilterMatch(observed, w) || observed.ExtraConditions {
			return nil, fmt.Errorf("filter readback did not confirm the requested service exception")
		}
	}
	return res, nil
}
