package service

import (
	"context"
	"fmt"

	"github.com/jpvelasco/nyx/internal/providers"
	opnsensebackend "github.com/jpvelasco/nyx/internal/providers/opnsense"
)

// OpnsenseNatRule is a NAT rule (port forward, one-to-one, or source NAT)
// in a flat, agent-friendly shape.
type OpnsenseNatRule struct {
	UUID        string   `json:"uuid"`
	Enabled     bool     `json:"enabled"`
	Interfaces  []string `json:"interfaces"`
	Protocol    string   `json:"protocol"`
	Source      string   `json:"source"`
	Destination string   `json:"destination"`
	Port        string   `json:"port,omitempty"`
	LocalPort   string   `json:"local_port,omitempty"`
	Target      string   `json:"target,omitempty"`
	Mode        string   `json:"mode,omitempty"`
	Type        string   `json:"type,omitempty"`
	SNATMode    string   `json:"snat_mode,omitempty"`
	Label       string   `json:"label,omitempty"`
}

// OpnsenseNatSummary is the site's full NAT posture in one read: the
// outbound (source) NAT mode plus every NAT rule set. The mode is the key
// double-NAT signal — a transparent-proxy OPNsense reports "disabled".
type OpnsenseNatSummary struct {
	OutboundNatMode  string            `json:"outbound_nat_mode"`
	PortForwardRules []OpnsenseNatRule `json:"port_forward_rules"`
	OneToOneRules    []OpnsenseNatRule `json:"one_to_one_rules"`
	SourceNatRules   []OpnsenseNatRule `json:"source_nat_rules"`
}

// OpnsenseNatRuleSpec is the flat desired-state of a NAT rule for one
// collection. Collection-specific fields are ignored by the provider.
type OpnsenseNatRuleSpec struct {
	Interfaces  []string `json:"interfaces,omitempty"`
	Protocol    string   `json:"protocol,omitempty"`
	Source      string   `json:"source,omitempty"`
	Destination string   `json:"destination,omitempty"`
	Port        string   `json:"port,omitempty"`
	LocalPort   string   `json:"local_port,omitempty"`
	Target      string   `json:"target,omitempty"`
	Mode        string   `json:"mode,omitempty"`
	Type        string   `json:"type,omitempty"`
	Label       string   `json:"label,omitempty"`
}

// OpnsenseNatApplyRequest is a single NAT mutation against one of the
// three collections. RuleUUID is required for action update/delete/toggle;
// Spec is required for create/update. ToggleDisable only applies to the
// port-forward toggle (d_nat polarity: 1 = disabled).
type OpnsenseNatApplyRequest struct {
	Operation      string              `json:"operation"`
	Action         string              `json:"action,omitempty"` // "create" (default) | "update" | "delete" | "toggle"
	RuleUUID       string              `json:"rule_uuid,omitempty"`
	Spec           OpnsenseNatRuleSpec `json:"spec"`
	ToggleDisable  bool                `json:"toggle_disable,omitempty"`
	AllowDoubleNat bool                `json:"allow_double_nat,omitempty"`
	DryRun         bool                `json:"dry_run,omitempty"`
}

// flattenNat maps the client's flat NAT rows into the service shape.
func flattenNat(rules []opnsensebackend.NatRule) []OpnsenseNatRule {
	out := make([]OpnsenseNatRule, 0, len(rules))
	for _, r := range rules {
		out = append(out, OpnsenseNatRule{
			UUID:        r.RuleUUID,
			Enabled:     !r.Disabled,
			Interfaces:  r.Interface,
			Protocol:    r.Protocol,
			Source:      r.Source,
			Destination: r.Destination,
			Port:        r.Port,
			LocalPort:   r.LocalPort,
			Target:      r.Target,
			Mode:        r.Mode,
			Type:        r.Type,
			SNATMode:    r.SNATMode,
			Label:       r.Label,
		})
	}
	return out
}

// ListPortForwardRules returns the destination-NAT (port forward) rules.
func (s *OpnsenseService) ListPortForwardRules(ctx context.Context, opts OpnsenseOptions) ([]OpnsenseNatRule, error) {
	client := s.client(opts)
	rules, err := client.GetPortForwardRules(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching port forward rules: %w", err)
	}
	return flattenNat(rules), nil
}

// ListOneToOneRules returns the one-to-one NAT rules.
func (s *OpnsenseService) ListOneToOneRules(ctx context.Context, opts OpnsenseOptions) ([]OpnsenseNatRule, error) {
	client := s.client(opts)
	rules, err := client.GetOneToOneRules(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching one-to-one rules: %w", err)
	}
	return flattenNat(rules), nil
}

// ListSourceNatRules returns the source-NAT rules, including the generic
// outbound-NAT row that carries the snat_mode field.
func (s *OpnsenseService) ListSourceNatRules(ctx context.Context, opts OpnsenseOptions) ([]OpnsenseNatRule, error) {
	client := s.client(opts)
	rules, err := client.GetSourceNatRules(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching source NAT rules: %w", err)
	}
	return flattenNat(rules), nil
}

// GetOutboundNatMode returns the outbound (source) NAT mode — one of
// automatic|hybrid|advanced|disabled. It is the key double-NAT signal.
func (s *OpnsenseService) GetOutboundNatMode(ctx context.Context, opts OpnsenseOptions) (string, error) {
	client := s.client(opts)
	mode, err := client.GetOutboundNatMode(ctx)
	if err != nil {
		return "", fmt.Errorf("fetching outbound NAT mode: %w", err)
	}
	return mode, nil
}

// GetNAT returns the full NAT posture in one call: outbound mode + every NAT
// rule set. A failure on any read is surfaced — a partial NAT picture would
// mislead the double-NAT verdict.
func (s *OpnsenseService) GetNAT(ctx context.Context, opts OpnsenseOptions) (*OpnsenseNatSummary, error) {
	client := s.client(opts)
	mode, err := client.GetOutboundNatMode(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching outbound NAT mode: %w", err)
	}
	var pf, o2o, snat []opnsensebackend.NatRule
	if pf, err = client.GetPortForwardRules(ctx); err != nil {
		return nil, fmt.Errorf("fetching port forward rules: %w", err)
	}
	if o2o, err = client.GetOneToOneRules(ctx); err != nil {
		return nil, fmt.Errorf("fetching one-to-one rules: %w", err)
	}
	if snat, err = client.GetSourceNatRules(ctx); err != nil {
		return nil, fmt.Errorf("fetching source NAT rules: %w", err)
	}
	return &OpnsenseNatSummary{
		OutboundNatMode:  mode,
		PortForwardRules: flattenNat(pf),
		OneToOneRules:    flattenNat(o2o),
		SourceNatRules:   flattenNat(snat),
	}, nil
}

// PlanNat previews a NAT mutation without mutating: it returns the action's
// endpoint, the current collection state as Before evidence, and the
// double-NAT guard verdict. It issues zero POSTs.
func (s *OpnsenseService) PlanNat(ctx context.Context, opts OpnsenseOptions, req OpnsenseNatApplyRequest) (*providers.NatPlan, error) {
	mutator, err := s.natMutator()
	if err != nil {
		return nil, err
	}
	return mutator.PlanNat(ctx, s.natRequest(req), s.natOpts(opts))
}

// ApplyNat performs a NAT mutation when the double-NAT guard passes and
// DryRun is false. A dry-run or an idempotent no-op (a create whose 5-tuple
// already exists with the same spec) issues zero POSTs.
func (s *OpnsenseService) ApplyNat(ctx context.Context, opts OpnsenseOptions, req OpnsenseNatApplyRequest) (*providers.NatApplyResult, error) {
	mutator, err := s.natMutator()
	if err != nil {
		return nil, err
	}
	return mutator.ApplyNat(ctx, s.natRequest(req), s.natOpts(opts))
}

// newNatMutator resolves the provider's NAT mutation surface (type-assertion
// safety rail, mirrors the Omada applier).
func (s *OpnsenseService) natMutator() (providers.NatMutationProvider, error) {
	p := providers.Get(opnsensebackend.ProviderName)
	mutator, ok := p.(providers.NatMutationProvider)
	if !ok {
		return nil, fmt.Errorf("provider %q does not implement NAT mutation", opnsensebackend.ProviderName)
	}
	return mutator, nil
}

// natOpts maps service options to the provider's import options.
func (s *OpnsenseService) natOpts(opts OpnsenseOptions) providers.ImportOptions {
	return providers.ImportOptions{
		Host:          opts.Host,
		ClientID:      opts.APIKey,
		ClientSecret:  opts.APISecret,
		SkipTLSVerify: opts.SkipTLSVerify,
		CACertPath:    opts.CACertPath,
	}
}

// natRequest maps the service request to the provider's NAT request shape.
func (s *OpnsenseService) natRequest(req OpnsenseNatApplyRequest) providers.NatApplyRequest {
	return providers.NatApplyRequest{
		Operation:      req.Operation,
		Action:         req.Action,
		RuleUUID:       req.RuleUUID,
		Spec:           s.natSpec(req.Spec),
		ToggleDisable:  req.ToggleDisable,
		AllowDoubleNat: req.AllowDoubleNat,
		DryRun:         req.DryRun,
	}
}

// natSpec maps the service rule spec to the provider shape.
func (s *OpnsenseService) natSpec(spec OpnsenseNatRuleSpec) providers.NatRuleSpec {
	return providers.NatRuleSpec{
		Interfaces:  spec.Interfaces,
		Protocol:    spec.Protocol,
		Source:      spec.Source,
		Destination: spec.Destination,
		Port:        spec.Port,
		LocalPort:   spec.LocalPort,
		Target:      spec.Target,
		Mode:        spec.Mode,
		Type:        spec.Type,
		Label:       spec.Label,
	}
}
