package service

import (
	"context"
	"fmt"
	"sort"

	"github.com/jpvelasco/nyx/internal/audit"
	omadabackend "github.com/jpvelasco/nyx/internal/backends/omada"
	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/models"
	providers "github.com/jpvelasco/nyx/internal/providers"
	omadaprovider "github.com/jpvelasco/nyx/internal/providers/omada"
)

// OmadaOptions carries everything needed to talk to an Omada SDN controller.
// The password is held only for the duration of a request; it is never
// written to logs, evidence, or tool output.
type OmadaOptions struct {
	Host          string
	Username      string
	Password      string
	Site          string
	SkipTLSVerify bool
	CACertPath    string
}

// OmadaInfo is the unauthenticated controller metadata surfaced to agents.
type OmadaInfo struct {
	Provider   string `json:"provider"`
	Host       string `json:"host"`
	Version    string `json:"version"`
	APIVersion string `json:"api_version"`
	OmadaCID   string `json:"omada_cid"`
	Configured bool   `json:"configured"`
}

// OmadaNetwork is a LAN network/VLAN with derived CIDR and gateway.
type OmadaNetwork struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Purpose     string `json:"purpose"`
	VLANID      int    `json:"vlan_id"`
	CIDR        string `json:"cidr"`
	Gateway     string `json:"gateway"`
	Isolated    bool   `json:"isolated"`
	DHCPEnabled bool   `json:"dhcp_enabled"`
}

// OmadaACLRule is a switch or gateway ACL rule in a flat, agent-friendly shape.
type OmadaACLRule struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Enabled    bool   `json:"enabled"`
	Policy     string `json:"policy"`
	Protocols  string `json:"protocols"`
	SourceType string `json:"source_type"`
	SourceName string `json:"source_name"`
	DestType   string `json:"dest_type"`
	DestName   string `json:"dest_name"`
	Index      int    `json:"index"`
}

// OmadaClient is a connected client in a flat, agent-friendly shape.
type OmadaClient struct {
	MAC         string `json:"mac"`
	IP          string `json:"ip"`
	Name        string `json:"name"`
	Hostname    string `json:"hostname"`
	NetworkName string `json:"network_name"`
	SSID        string `json:"ssid"`
	VLANID      int    `json:"vlan_id"`
	Wireless    bool   `json:"wireless"`
	Vendor      string `json:"vendor"`
	DeviceType  string `json:"device_type"`
	Active      bool   `json:"active"`
	Uptime      int64  `json:"uptime_seconds"`
}

// OmadaImport is the generated intent spec plus the fetch summary, letting
// agents compare intended state (spec) against observed state.
type OmadaImport struct {
	Spec              *intent.Spec `json:"spec"`
	Site              string       `json:"site"`
	ControllerVersion string       `json:"controller_version"`
	NetworkCount      int          `json:"network_count"`
	ACLRuleCount      int          `json:"acl_rule_count"`
	ClientCount       int          `json:"client_count"`
	Warnings          []string     `json:"warnings"`
}

// OmadaPolicyDiff describes one policy pair in a plan: unchanged, to add, to
// remove, or to change. Action is the effective action; CurrentAction and
// ProposedAction are set on changes so the agent sees both sides.
type OmadaPolicyDiff struct {
	Name           string `json:"name,omitempty"`
	From           string `json:"from"`
	To             string `json:"to"`
	Action         string `json:"action,omitempty"`
	CurrentAction  string `json:"current_action,omitempty"`
	ProposedAction string `json:"proposed_action,omitempty"`
}

// OmadaPlan is a read-only actuator preview: the difference between the
// controller's current ACL rules and a proposed intent spec. No changes are
// applied. Warnings flag proposal endpoints that are not declared networks.
type OmadaPlan struct {
	Site          string            `json:"site"`
	ProposedSite  string            `json:"proposed_site"`
	CurrentRules  int               `json:"current_rules"`
	ProposedRules int               `json:"proposed_rules"`
	Unchanged     []OmadaPolicyDiff `json:"unchanged"`
	ToAdd         []OmadaPolicyDiff `json:"to_add"`
	ToRemove      []OmadaPolicyDiff `json:"to_remove"`
	ToChange      []OmadaPolicyDiff `json:"to_change"`
	Warnings      []string          `json:"warnings"`
}

// OmadaACLApplyRequest describes a single desired ACL change on the site.
// DryRun previews without mutating; PostAudit (default true) runs a targeted
// isolation audit after a real apply.
type OmadaACLApplyRequest struct {
	PolicyName string
	From       string
	To         string
	Action     string // "allow" or "deny"
	DryRun     bool
	PostAudit  bool
}

// OmadaPostAudit is the targeted re-verification run after a real apply.
type OmadaPostAudit struct {
	Status  string              `json:"status"`
	Summary string              `json:"summary"`
	Finding *models.CheckResult `json:"finding,omitempty"`
}

// OmadaACLApplyResult is the structured outcome of an apply with
// before/after evidence and the post-apply audit.
type OmadaACLApplyResult struct {
	DryRun      bool            `json:"dry_run"`
	Outcome     string          `json:"outcome"` // "created" | "enabled" | "unchanged"
	RuleID      string          `json:"rule_id,omitempty"`
	FromCIDR    string          `json:"from_cidr"`
	ToCIDR      string          `json:"to_cidr"`
	FromGateway string          `json:"from_gateway,omitempty"`
	ToGateway   string          `json:"to_gateway,omitempty"`
	Before      string          `json:"before"`
	After       string          `json:"after"`
	PostAudit   *OmadaPostAudit `json:"post_audit,omitempty"`
}

// OmadaService exposes the Omada observation surface shared by the MCP server
// and any future CLI commands. NewClient is a seam for tests; PostAudit runs
// the targeted post-apply audit and defaults to the real audit engine.
type OmadaService struct {
	NewClient func(ctx context.Context, host string, skipTLSVerify bool, caCertPath string) (*omadabackend.Client, error)
	PostAudit func(ctx context.Context, spec *intent.Spec) (*models.AuditReport, error)
}

// NewOmadaService creates an OmadaService using the real controller client.
func NewOmadaService() *OmadaService {
	return &OmadaService{
		NewClient: omadabackend.NewClient,
		PostAudit: func(ctx context.Context, spec *intent.Spec) (*models.AuditReport, error) {
			return audit.NewEngine(spec).Run(ctx)
		},
	}
}

// Info fetches controller metadata without authentication.
func (s *OmadaService) Info(ctx context.Context, opts OmadaOptions) (*OmadaInfo, error) {
	client, err := s.newClient(ctx, opts)
	if err != nil {
		return nil, err
	}
	info := client.Info()
	return &OmadaInfo{
		Provider:   "omada",
		Host:       opts.Host,
		Version:    info.ControllerVer,
		APIVersion: info.APIVer,
		OmadaCID:   info.OmadaCID,
		Configured: info.Configured,
	}, nil
}

// ListNetworks returns the LAN networks of the selected site.
func (s *OmadaService) ListNetworks(ctx context.Context, opts OmadaOptions) ([]OmadaNetwork, error) {
	client, site, err := s.session(ctx, opts)
	if err != nil {
		return nil, err
	}
	defer client.Logout(ctx) //nolint:errcheck

	nets, err := client.GetNetworks(ctx, site.EffectiveID())
	if err != nil {
		return nil, fmt.Errorf("fetching networks: %w", err)
	}
	out := make([]OmadaNetwork, 0, len(nets))
	for _, n := range nets {
		out = append(out, OmadaNetwork{
			ID:          n.ID,
			Name:        n.Name,
			Purpose:     n.Purpose,
			VLANID:      n.VLANID,
			CIDR:        n.CIDR(),
			Gateway:     n.Gateway(),
			Isolated:    n.Isolated,
			DHCPEnabled: n.DHCPEnabled,
		})
	}
	return out, nil
}

// ListACLs returns switch and gateway ACL rules for the selected site,
// switch rules first. Both fetches must succeed so agents never see a
// partial rule set.
func (s *OmadaService) ListACLs(ctx context.Context, opts OmadaOptions) ([]OmadaACLRule, error) {
	client, site, err := s.session(ctx, opts)
	if err != nil {
		return nil, err
	}
	defer client.Logout(ctx) //nolint:errcheck

	siteID := site.EffectiveID()
	rules, err := client.GetACLRules(ctx, siteID)
	if err != nil {
		return nil, fmt.Errorf("fetching ACL rules: %w", err)
	}
	gwRules, err := client.GetGatewayACLRules(ctx, siteID)
	if err != nil {
		return nil, fmt.Errorf("fetching gateway ACL rules: %w", err)
	}
	all := append(rules, gwRules...)
	if nets, nerr := client.GetNetworks(ctx, siteID); nerr == nil {
		omadabackend.ResolveRules(all, nets)
	}

	out := make([]OmadaACLRule, 0, len(all))
	for _, r := range all {
		out = append(out, OmadaACLRule{
			ID:         r.ID,
			Name:       r.Name,
			Enabled:    r.Status,
			Policy:     r.Policy.String(),
			Protocols:  omadabackend.ProtocolsLabel(r.Protocols),
			SourceType: r.SourceType,
			SourceName: r.SourceName,
			DestType:   r.DestType,
			DestName:   r.DestName,
			Index:      r.Index,
		})
	}
	return out, nil
}

// ListClients returns the connected clients of the selected site.
func (s *OmadaService) ListClients(ctx context.Context, opts OmadaOptions) ([]OmadaClient, error) {
	client, site, err := s.session(ctx, opts)
	if err != nil {
		return nil, err
	}
	defer client.Logout(ctx) //nolint:errcheck

	clients, err := client.GetClients(ctx, site.EffectiveID())
	if err != nil {
		return nil, fmt.Errorf("fetching clients: %w", err)
	}
	out := make([]OmadaClient, 0, len(clients))
	for _, c := range clients {
		out = append(out, OmadaClient{
			MAC:         c.MAC,
			IP:          c.IP,
			Name:        c.Name,
			Hostname:    c.Hostname,
			NetworkName: c.NetworkName,
			SSID:        c.SSID,
			VLANID:      c.VLANID,
			Wireless:    c.Wireless,
			Vendor:      c.Vendor,
			DeviceType:  c.DeviceType,
			Active:      c.Active,
			Uptime:      c.Uptime,
		})
	}
	return out, nil
}

// Import connects, imports the controller state, and produces an intent
// spec reflecting the observed design (networks, policies, assertions).
func (s *OmadaService) Import(ctx context.Context, opts OmadaOptions) (*OmadaImport, error) {
	result, err := omadabackend.ImportSpec(ctx, opts.Host, opts.Username, opts.Password, opts.Site,
		false, opts.SkipTLSVerify, opts.CACertPath, nil)
	if err != nil {
		return nil, err
	}
	return &OmadaImport{
		Spec:              result.Spec,
		Site:              result.Site.Name,
		ControllerVersion: result.ControllerVersion,
		NetworkCount:      result.NetworkCount,
		ACLRuleCount:      result.ACLRuleCount,
		ClientCount:       result.ClientCount,
		Warnings:          result.Warnings,
	}, nil
}

// Plan previews the difference between the controller's current ACL rules
// and a proposed intent spec. It is read-only: nothing is applied. The
// proposal is validated before any controller request is made.
func (s *OmadaService) Plan(ctx context.Context, opts OmadaOptions, proposedYAML string) (*OmadaPlan, error) {
	proposed, err := intent.ParseSpec([]byte(proposedYAML))
	if err != nil {
		return nil, err
	}

	client, site, err := s.session(ctx, opts)
	if err != nil {
		return nil, err
	}
	defer client.Logout(ctx) //nolint:errcheck

	nets, err := client.GetNetworks(ctx, site.EffectiveID())
	if err != nil {
		return nil, fmt.Errorf("fetching networks: %w", err)
	}
	rules, err := client.GetACLRules(ctx, site.EffectiveID())
	if err != nil {
		return nil, fmt.Errorf("fetching ACL rules: %w", err)
	}
	gwRules, err := client.GetGatewayACLRules(ctx, site.EffectiveID())
	if err != nil {
		return nil, fmt.Errorf("fetching gateway ACL rules: %w", err)
	}

	current := omadabackend.PoliciesFromRules(append(rules, gwRules...), nets)
	plan := diffPolicies(current, proposed.Policies, networkNames(proposed.Networks))
	plan.Site = site.Name
	plan.ProposedSite = proposed.Site
	return plan, nil
}

// ApplyACL applies a single desired ACL change through the registered
// provider's mutation surface. A real (non-dry-run) apply that changes the
// controller is followed by a targeted isolation audit against the same
// endpoints, returned as post_audit evidence.
func (s *OmadaService) ApplyACL(ctx context.Context, opts OmadaOptions, req OmadaACLApplyRequest) (*OmadaACLApplyResult, error) {
	applier, err := s.newApplier()
	if err != nil {
		return nil, err
	}
	res, err := applier.ApplyACL(ctx, providers.ACLApplyRequest{
		PolicyName: req.PolicyName,
		From:       req.From,
		To:         req.To,
		Action:     req.Action,
		DryRun:     req.DryRun,
	}, providers.ImportOptions{
		Host:          opts.Host,
		Username:      opts.Username,
		Password:      opts.Password,
		Site:          opts.Site,
		SkipTLSVerify: opts.SkipTLSVerify,
		CACertPath:    opts.CACertPath,
	})
	if err != nil {
		return nil, err
	}
	out := &OmadaACLApplyResult{
		DryRun:      res.DryRun,
		Outcome:     res.Outcome,
		RuleID:      res.RuleID,
		FromCIDR:    res.FromCIDR,
		ToCIDR:      res.ToCIDR,
		FromGateway: res.FromGateway,
		ToGateway:   res.ToGateway,
		Before:      res.Before,
		After:       res.After,
	}
	if !res.DryRun && res.Outcome != "unchanged" && req.PostAudit {
		out.PostAudit = s.runPostAudit(ctx, req, res)
	}
	return out, nil
}

// newApplier returns the registered Omada provider's ACLApplier. The registry
// lookup enforces the optional-interface contract: a provider that cannot
// mutate is refused with a clear error.
func (s *OmadaService) newApplier() (providers.ACLApplier, error) {
	p := providers.Get(omadaprovider.ProviderName)
	applier, ok := p.(providers.ACLApplier)
	if !ok {
		return nil, fmt.Errorf("provider %q does not implement ACL mutation", omadaprovider.ProviderName)
	}
	return applier, nil
}

// runPostAudit builds a targeted spec for the changed endpoints and runs the
// isolation assertion through the configured audit engine. The gateways from
// the apply result are mandatory: without them runIsolation has no target to
// ping and the audit is unverifiable by construction.
func (s *OmadaService) runPostAudit(ctx context.Context, req OmadaACLApplyRequest, res *providers.ACLApplyResult) *OmadaPostAudit {
	spec := &intent.Spec{
		Version: 1,
		Site:    "post-mutation",
		Networks: []intent.Network{
			{Name: req.From, CIDR: res.FromCIDR, Gateway: res.FromGateway},
			{Name: req.To, CIDR: res.ToCIDR, Gateway: res.ToGateway},
		},
		Assertions: []intent.Assertion{{
			Type:   "isolation",
			From:   req.From,
			To:     req.To,
			Expect: req.Action,
		}},
	}
	if s.PostAudit == nil {
		return &OmadaPostAudit{Status: string(models.StatusError), Summary: "post-mutation audit unavailable"}
	}
	report, err := s.PostAudit(ctx, spec)
	if err != nil {
		return &OmadaPostAudit{Status: string(models.StatusError), Summary: fmt.Sprintf("post-mutation audit failed: %v", err)}
	}
	for _, f := range report.Findings {
		if f.CheckType == "isolation" {
			finding := f
			return &OmadaPostAudit{Status: string(f.Status), Summary: f.Summary, Finding: &finding}
		}
	}
	return &OmadaPostAudit{Status: string(models.StatusError), Summary: "post-mutation audit returned no isolation finding"}
}

// networkNames returns the declared network names of a spec.
func networkNames(networks []intent.Network) []string {
	names := make([]string, 0, len(networks))
	for _, n := range networks {
		names = append(names, n.Name)
	}
	return names
}

// diffPolicies compares current controller policies against the proposed
// ones. Policies match on the from/to pair; a single pair with a different
// action on each side is a change. Multiple rules for the same pair are
// matched by action counts so no rule is silently dropped. Warnings flag
// proposal endpoints that are not declared in the proposed spec's networks.
func diffPolicies(current, proposed []intent.Policy, declaredNetworks []string) *OmadaPlan {
	declared := make(map[string]bool, len(declaredNetworks))
	for _, n := range declaredNetworks {
		declared[n] = true
	}

	plan := &OmadaPlan{CurrentRules: len(current), ProposedRules: len(proposed)}

	currentGroups := groupPoliciesByKey(current)
	proposedGroups := groupPoliciesByKey(proposed)

	for _, key := range sortedKeys(union(currentGroups, proposedGroups)) {
		cur := currentGroups[key]
		prop := proposedGroups[key]
		switch {
		case len(prop) == 0:
			for _, cp := range cur {
				plan.ToRemove = append(plan.ToRemove, diffFromPolicy(cp, "", cp.Action))
			}
		case len(cur) == 1 && len(prop) == 1 && cur[0].Action != prop[0].Action:
			plan.ToChange = append(plan.ToChange, diffFromPolicy(prop[0], cur[0].Action, prop[0].Action))
			warnIfUndeclared(prop[0], declared, &plan.Warnings)
		default:
			curCounts := countActions(cur)
			propCounts := countActions(prop)
			for action, c := range curCounts {
				p := propCounts[action]
				for i := 0; i < min(c, p); i++ {
					plan.Unchanged = append(plan.Unchanged, diffFromPolicy(policyWithAction(prop, action), "", action))
				}
				for i := 0; i < c-p; i++ {
					plan.ToRemove = append(plan.ToRemove, diffFromPolicy(policyWithAction(cur, action), "", action))
				}
				for i := 0; i < p-c; i++ {
					plan.ToAdd = append(plan.ToAdd, diffFromPolicy(policyWithAction(prop, action), "", action))
					warnIfUndeclared(policyWithAction(prop, action), declared, &plan.Warnings)
				}
			}
			for action, p := range propCounts {
				if curCounts[action] > 0 {
					continue
				}
				for i := 0; i < p; i++ {
					plan.ToAdd = append(plan.ToAdd, diffFromPolicy(policyWithAction(prop, action), "", action))
					warnIfUndeclared(policyWithAction(prop, action), declared, &plan.Warnings)
				}
			}
		}
	}
	return plan
}

// groupPoliciesByKey indexes policies by their from|to pair, preserving all
// entries (including duplicates).
func groupPoliciesByKey(policies []intent.Policy) map[string][]intent.Policy {
	groups := make(map[string][]intent.Policy, len(policies))
	for _, p := range policies {
		key := policyKey(p)
		groups[key] = append(groups[key], p)
	}
	return groups
}

func policyKey(p intent.Policy) string {
	return p.From + "|" + p.To
}

// countActions tallies how many policies use each action within a group.
func countActions(policies []intent.Policy) map[string]int {
	counts := make(map[string]int, len(policies))
	for _, p := range policies {
		counts[p.Action]++
	}
	return counts
}

func policyWithAction(policies []intent.Policy, action string) intent.Policy {
	for _, p := range policies {
		if p.Action == action {
			return p
		}
	}
	return policies[0]
}

func union(a, b map[string][]intent.Policy) map[string]bool {
	keys := make(map[string]bool, len(a)+len(b))
	for k := range a {
		keys[k] = true
	}
	for k := range b {
		keys[k] = true
	}
	return keys
}

func sortedKeys(keys map[string]bool) []string {
	out := make([]string, 0, len(keys))
	for k := range keys {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// warnIfUndeclared appends a warning when a proposal endpoint is not a
// declared network in the proposed spec.
func warnIfUndeclared(p intent.Policy, declared map[string]bool, warnings *[]string) {
	if p.From != "" && !declared[p.From] {
		*warnings = append(*warnings,
			fmt.Sprintf("policy %q: from %q is not a declared network in the proposed spec", p.Name, p.From))
	}
	if p.To != "" && !declared[p.To] {
		*warnings = append(*warnings,
			fmt.Sprintf("policy %q: to %q is not a declared network in the proposed spec", p.Name, p.To))
	}
}

func diffFromPolicy(p intent.Policy, currentAction, proposedAction string) OmadaPolicyDiff {
	if currentAction == "" || currentAction == proposedAction {
		return OmadaPolicyDiff{Name: p.Name, From: p.From, To: p.To, Action: proposedAction}
	}
	return OmadaPolicyDiff{Name: p.Name, From: p.From, To: p.To, CurrentAction: currentAction, ProposedAction: proposedAction}
}

func (s *OmadaService) newClient(ctx context.Context, opts OmadaOptions) (*omadabackend.Client, error) {
	return s.NewClient(ctx, opts.Host, opts.SkipTLSVerify, opts.CACertPath)
}

// session connects, authenticates, and resolves the target site. The caller
// owns the returned client and must Logout when done.
func (s *OmadaService) session(ctx context.Context, opts OmadaOptions) (*omadabackend.Client, omadabackend.Site, error) {
	client, err := s.newClient(ctx, opts)
	if err != nil {
		return nil, omadabackend.Site{}, err
	}
	if err := client.Login(ctx, opts.Username, opts.Password); err != nil {
		return nil, omadabackend.Site{}, err
	}
	sites, err := client.GetSites(ctx)
	if err != nil {
		_ = client.Logout(ctx)
		return nil, omadabackend.Site{}, fmt.Errorf("fetching sites: %w", err)
	}
	site, err := omadabackend.SelectSite(sites, opts.Site)
	if err != nil {
		_ = client.Logout(ctx)
		return nil, omadabackend.Site{}, err
	}
	return client, site, nil
}
