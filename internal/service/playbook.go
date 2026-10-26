// Playbooks (#140): composed operations that select the correct backend
// and actions from topology signals already available to nyx. The
// port-forward playbook observes the NAT posture, decides which provider
// owns the egress-path NAT, and defers to that provider's plan/apply
// surface — the provider's own safety gates (double-NAT guard, the Omada
// write-path hold) still make the call. Dry-run is the default posture
// for the apply path, exactly like every other mutation surface.
package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/topology"
)

// Playbook decision names — why a backend was selected (or not).
const (
	// PlaybookDecisionNatOwner: the topology reports this provider as the
	// on-path NAT router, so its plan/apply surface owns the change.
	PlaybookDecisionNatOwner = "nat_owner"
	// PlaybookDecisionUnsafe: the topology verdict blocks the operation
	// (double NAT) — resolve the topology first.
	PlaybookDecisionUnsafe = "unsafe_topology"
	// PlaybookDecisionIndeterminate: no on-path NAT owner could be
	// determined from the observed facts.
	PlaybookDecisionIndeterminate = "indeterminate"
)

// Playbook outcome for refusals that happen at the playbook level
// (before any provider surface is consulted).
const PlaybookOutcomeRefused = "refused"

// PortForwardRequest is the desired port-forward rule, provider-neutral:
// the external (WAN) port forwarded to a target on the local network.
type PortForwardRequest struct {
	ExternalPort string   // external (WAN) port or range, required
	Target       string   // internal LAN IP, required
	LocalPort    string   // forwarded internal port or range (default: same as ExternalPort)
	Protocol     string   // tcp, udp (empty = any)
	Label        string   // rule name
	Interfaces   []string // optional interface restriction (OPNsense wire shape)
}

// Validate checks the playbook's request shape: an external port and a
// target are the minimum intent.
func (r PortForwardRequest) Validate() error {
	if strings.TrimSpace(r.ExternalPort) == "" {
		return fmt.Errorf("external_port is required (the WAN port or range to forward)")
	}
	if strings.TrimSpace(r.Target) == "" {
		return fmt.Errorf("target is required (the internal LAN IP to forward to)")
	}
	return nil
}

// PlaybookOptions carries the provider connection options for the
// composition: at least one provider must be configured, exactly like
// the topology report.
type PlaybookOptions struct {
	Omada    *OmadaOptions
	Opnsense *OpnsenseOptions
}

// PortForwardPlan is the composed plan: which backend the topology
// selected, why, what that backend's plan says, and the evidence trail.
type PortForwardPlan struct {
	Provider string   `json:"provider"`
	Decision string   `json:"decision"`
	Risk     string   `json:"risk"`
	Outcome  string   `json:"outcome"`
	RuleUUID string   `json:"rule_uuid,omitempty"`
	Before   string   `json:"before"`
	Warnings []string `json:"warnings,omitempty"`
	Playbook string   `json:"playbook"`
}

// OpnsenseNatSurface is the OPNsense service's plan/apply pair the
// playbook composes over.
type OpnsenseNatSurface interface {
	PlanNat(ctx context.Context, opts OpnsenseOptions, req OpnsenseNatApplyRequest) (*providers.NatPlan, error)
	ApplyNat(ctx context.Context, opts OpnsenseOptions, req OpnsenseNatApplyRequest) (*providers.NatApplyResult, error)
}

// OmadaNatSurface is the Omada service's plan/apply pair (the honest
// HOLD from #139) the playbook composes over.
type OmadaNatSurface interface {
	PlanNat(ctx context.Context, opts OmadaOptions, req OmadaNatApplyRequest) (*providers.NatPlan, error)
	ApplyNat(ctx context.Context, opts OmadaOptions, req OmadaNatApplyRequest) (*providers.NatApplyResult, error)
}

// PlaybookService composes the topology observation with the providers'
// NAT mutation surfaces.
type PlaybookService struct {
	Topology TopologySurface
	Opnsense OpnsenseNatSurface
	Omada    OmadaNatSurface
}

// TopologySurface is the observation the playbook composes over.
type TopologySurface interface {
	Report(ctx context.Context, opts TopologyOptions) (*TopologyReport, error)
}

// natOwnerFromReport selects the on-path NAT router from the classified
// topology. It returns the provider name, whether one was found, and
// whether the path is ambiguous (two on-path NAT routers = double NAT).
func natOwnerFromReport(rep *TopologyReport) (provider string, found, ambiguous bool) {
	seen := map[string]bool{}
	for i := range rep.Devices {
		d := &rep.Devices[i]
		if d.Role != topology.RoleNatRouter || !d.OnPath {
			continue
		}
		seen[d.Provider] = true
		provider = d.Provider
	}
	return provider, len(seen) > 0, len(seen) > 1
}

// playbookTrail records the decision inputs: the topology signal and the
// site-level risk that were live when the routing decision was made.
func playbookTrail(rep *TopologyReport) string {
	roles := make([]string, 0, len(rep.Devices))
	for _, d := range rep.Devices {
		roles = append(roles, fmt.Sprintf("%s=%s(on_path=%v)", d.Provider, d.Role, d.OnPath))
	}
	return fmt.Sprintf("topology: %s; risk=%s", strings.Join(roles, ", "), rep.Risk)
}

// NewPlaybookService builds the composed playbook over the real
// observation and mutation surfaces: the topology service provides the
// routing signals, and the provider services provide the plan/apply
// surfaces the routing defers to.
func NewPlaybookService(topo TopologySurface) *PlaybookService {
	return &PlaybookService{
		Topology: topo,
		Opnsense: &OpnsenseService{},
		Omada:    &OmadaService{},
	}
}

// PlanPortForward composes the topology observation with the selected
// backend's plan. Read-only: it issues the topology reads plus the
// backend's plan (itself read-only), never a mutation.
func (s *PlaybookService) PlanPortForward(ctx context.Context, opts PlaybookOptions, req PortForwardRequest) (*PortForwardPlan, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	rep, err := s.observeTopology(ctx, opts)
	if err != nil {
		return nil, err
	}

	owner, found, ambiguous := natOwnerFromReport(rep)
	if ambiguous || topology.DoubleNatRisk(rep.Risk) == topology.RiskDouble {
		return &PortForwardPlan{
			Provider: owner,
			Decision: PlaybookDecisionUnsafe,
			Risk:     rep.Risk,
			Outcome:  PlaybookOutcomeRefused,
			Playbook: playbookTrail(rep) + "; refused: double NAT — resolve the topology before planning a port forward",
			Warnings: []string{"the topology reports two on-path NAT routers (double NAT); resolve it before planning a port forward"},
		}, nil
	}
	if !found {
		return &PortForwardPlan{
			Decision: PlaybookDecisionIndeterminate,
			Risk:     rep.Risk,
			Outcome:  PlaybookOutcomeRefused,
			Playbook: playbookTrail(rep) + "; refused: no on-path NAT router could be determined from the observed facts — fix the topology facts or use the provider-specific tools",
		}, nil
	}

	plan, err := s.planWithProvider(ctx, owner, opts, req)
	if err != nil {
		return nil, err
	}
	return &PortForwardPlan{
		Provider: owner,
		Decision: PlaybookDecisionNatOwner,
		Risk:     rep.Risk,
		Outcome:  plan.Outcome,
		RuleUUID: plan.RuleUUID,
		Before:   plan.Before,
		Warnings: plan.Warnings,
		Playbook: playbookTrail(rep) + "; routed to " + owner + " (the on-path NAT router)",
	}, nil
}

// ApplyPortForward composes the topology observation with the selected
// backend's apply. The dry-run flag is the repository's mutation
// posture: the caller (MCP defaults it true; the CLI requires an
// explicit opt-in) decides, and the provider's own gates still apply.
func (s *PlaybookService) ApplyPortForward(ctx context.Context, opts PlaybookOptions, req PortForwardRequest, dryRun bool) (*PortForwardPlan, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	rep, err := s.observeTopology(ctx, opts)
	if err != nil {
		return nil, err
	}

	owner, found, ambiguous := natOwnerFromReport(rep)
	if ambiguous || topology.DoubleNatRisk(rep.Risk) == topology.RiskDouble {
		return &PortForwardPlan{
			Provider: owner,
			Decision: PlaybookDecisionUnsafe,
			Risk:     rep.Risk,
			Outcome:  PlaybookOutcomeRefused,
			Playbook: playbookTrail(rep) + "; refused: double NAT — resolve the topology before applying a port forward",
			Warnings: []string{"the topology reports two on-path NAT routers (double NAT); resolve it before applying a port forward"},
		}, nil
	}
	if !found {
		return &PortForwardPlan{
			Decision: PlaybookDecisionIndeterminate,
			Risk:     rep.Risk,
			Outcome:  PlaybookOutcomeRefused,
			Playbook: playbookTrail(rep) + "; refused: no on-path NAT router could be determined from the observed facts — fix the topology facts or use the provider-specific tools",
		}, nil
	}

	res, err := s.applyWithProvider(ctx, owner, opts, req, dryRun)
	if err != nil {
		return nil, err
	}
	return &PortForwardPlan{
		Provider: owner,
		Decision: PlaybookDecisionNatOwner,
		Risk:     rep.Risk,
		Outcome:  res.Outcome,
		RuleUUID: res.RuleUUID,
		Before:   res.Before,
		Warnings: res.Warnings,
		Playbook: playbookTrail(rep) + "; routed to " + owner + " (the on-path NAT router)" + fmt.Sprintf("; dry_run=%v", res.DryRun),
	}, nil
}

// observeTopology builds the topology report from the configured
// providers. At least one provider must be configured — the playbook
// composes over topology facts, and none means nothing to compose.
func (s *PlaybookService) observeTopology(ctx context.Context, opts PlaybookOptions) (*TopologyReport, error) {
	if opts.Omada == nil && opts.Opnsense == nil {
		return nil, fmt.Errorf("the port-forward playbook needs a host for at least one provider: set omada_host or opnsense_host (or the OMADA_HOST / OPNSENSE_HOST environment variables or the credential store)")
	}
	return s.Topology.Report(ctx, TopologyOptions{Omada: opts.Omada, Opnsense: opts.Opnsense})
}

// planWithProvider routes the plan to the selected provider's service
// surface, translating the provider-neutral request to the provider's
// request shape.
func (s *PlaybookService) planWithProvider(ctx context.Context, provider string, opts PlaybookOptions, req PortForwardRequest) (*providers.NatPlan, error) {
	switch provider {
	case "opnsense":
		if s.Opnsense == nil || opts.Opnsense == nil {
			return nil, fmt.Errorf("the topology selected opnsense as the NAT owner, but no opnsense credentials are configured")
		}
		return s.Opnsense.PlanNat(ctx, *opts.Opnsense, s.opnsenseRequest(req, true))
	case "omada":
		if s.Omada == nil || opts.Omada == nil {
			return nil, fmt.Errorf("the topology selected omada as the NAT owner, but no omada credentials are configured")
		}
		return s.Omada.PlanNat(ctx, *opts.Omada, s.omadaRequest(req, true))
	default:
		return nil, fmt.Errorf("topology named an unknown NAT owner %q", provider)
	}
}

// applyWithProvider routes the apply to the selected provider's service
// surface with the dry-run flag.
func (s *PlaybookService) applyWithProvider(ctx context.Context, provider string, opts PlaybookOptions, req PortForwardRequest, dryRun bool) (*providers.NatApplyResult, error) {
	switch provider {
	case "opnsense":
		if s.Opnsense == nil || opts.Opnsense == nil {
			return nil, fmt.Errorf("the topology selected opnsense as the NAT owner, but no opnsense credentials are configured")
		}
		return s.Opnsense.ApplyNat(ctx, *opts.Opnsense, s.opnsenseRequest(req, dryRun))
	case "omada":
		if s.Omada == nil || opts.Omada == nil {
			return nil, fmt.Errorf("the topology selected omada as the NAT owner, but no omada credentials are configured")
		}
		return s.Omada.ApplyNat(ctx, *opts.Omada, s.omadaRequest(req, dryRun))
	default:
		return nil, fmt.Errorf("topology named an unknown NAT owner %q", provider)
	}
}

// opnsenseRequest builds the OPNsense service request from the
// provider-neutral playbook request.
func (s *PlaybookService) opnsenseRequest(req PortForwardRequest, dryRun bool) OpnsenseNatApplyRequest {
	local := req.LocalPort
	if local == "" {
		local = req.ExternalPort
	}
	return OpnsenseNatApplyRequest{
		Operation: "port_forward",
		Action:    "create",
		Spec: OpnsenseNatRuleSpec{
			Interfaces: req.Interfaces,
			Protocol:   req.Protocol,
			Port:       req.ExternalPort,
			LocalPort:  local,
			Target:     req.Target,
			Label:      req.Label,
		},
		DryRun: dryRun,
	}
}

// omadaRequest builds the Omada service request (the honest #139 HOLD
// surface) from the provider-neutral playbook request.
func (s *PlaybookService) omadaRequest(req PortForwardRequest, dryRun bool) OmadaNatApplyRequest {
	local := req.LocalPort
	if local == "" {
		local = req.ExternalPort
	}
	return OmadaNatApplyRequest{
		Operation: "port_forward",
		Action:    "create",
		Spec: providers.NatRuleSpec{
			Protocol:  req.Protocol,
			Port:      req.ExternalPort,
			LocalPort: local,
			Target:    req.Target,
			Label:     req.Label,
		},
		DryRun: dryRun,
	}
}
