package service

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/jpvelasco/nyx/internal/audit"
	omadabackend "github.com/jpvelasco/nyx/internal/backends/omada"
	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/models"
	providers "github.com/jpvelasco/nyx/internal/providers"
	omadaprovider "github.com/jpvelasco/nyx/internal/providers/omada"
)

// OmadaOptions carries everything needed to talk to an Omada SDN controller.
// The client credentials are held only for the duration of a request; they
// are never written to logs, evidence, or tool output.
type OmadaOptions struct {
	Host          string
	ClientID      string
	ClientSecret  string
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

// OmadaClient is a connected client in a flat, agent-friendly shape. The
// controller reports thin rows (MAC, name, type); IP, network name, and VLAN
// id are filled in from the site's DHCP user list on a best-effort basis.
type OmadaClient struct {
	MAC         string `json:"mac"`
	IP          string `json:"ip"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	NetworkName string `json:"network_name"`
	VLANID      int    `json:"vlan_id"`
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

// OmadaACLApplyRequest describes a desired ACL change on the site: the
// action to take between each From endpoint and each To endpoint
// (one-to-many and many-to-many supported). DryRun previews without
// mutating; PostAudit (default true) runs a targeted isolation audit after
// a real apply.
type OmadaACLApplyRequest struct {
	PolicyName string
	From       []string // source network names
	To         []string // destination network names
	Action     string   // "allow" or "deny"
	Scope      string   // "switch" (default) or "gateway"; "eap" is refused
	Protocols  []int    // IP protocols; empty means all
	DryRun     bool
	PostAudit  bool
}

// OmadaPostAudit is the targeted re-verification run after a real apply:
// one isolation finding per source endpoint, against the destination set.
type OmadaPostAudit struct {
	Status   string               `json:"status"`
	Summary  string               `json:"summary"`
	Findings []models.CheckResult `json:"findings,omitempty"`
}

// OmadaACLApplyResult is the structured outcome of an apply with
// before/after evidence and the post-apply audit. FromCIDRs/ToCIDRs and the
// gateway slices are in request order of the endpoints.
type OmadaACLApplyResult struct {
	DryRun        bool            `json:"dry_run"`
	Outcome       string          `json:"outcome"` // "created" | "enabled" | "unchanged"
	RuleID        string          `json:"rule_id,omitempty"`
	RuleName      string          `json:"rule_name,omitempty"`
	Scope         string          `json:"scope"`
	ScopeDisabled bool            `json:"scope_disabled,omitempty"`
	FromCIDRs     []string        `json:"from_cidrs"`
	ToCIDRs       []string        `json:"to_cidrs"`
	FromGateways  []string        `json:"from_gateways,omitempty"`
	ToGateways    []string        `json:"to_gateways,omitempty"`
	Before        string          `json:"before"`
	After         string          `json:"after"`
	PostAudit     *OmadaPostAudit `json:"post_audit,omitempty"`
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
			SourceType: r.SourceType.String(),
			SourceName: r.SourceName,
			DestType:   r.DestType.String(),
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

	siteID := site.EffectiveID()
	clients, err := client.GetClients(ctx, siteID)
	if err != nil {
		return nil, fmt.Errorf("fetching clients: %w", err)
	}
	// The thin client wire has no IP or network name. Enrichment from the
	// DHCP user list is best-effort: on a failure the clients are returned
	// with the wire fields as-is.
	var nets []omadabackend.Network
	if netList, nerr := client.GetNetworks(ctx, siteID); nerr == nil {
		nets = netList
	}
	// Best-effort: on a fetch or decode failure the clients keep their
	// thin wire fields.
	_ = client.EnrichFromDHCP(ctx, siteID, clients, nets)
	out := make([]OmadaClient, 0, len(clients))
	for _, c := range clients {
		out = append(out, OmadaClient{
			MAC:         c.MAC,
			IP:          c.IP,
			Name:        c.Name,
			Type:        c.Type,
			NetworkName: c.NetworkName,
			VLANID:      c.VLANID,
		})
	}
	return out, nil
}

// OmadaInventory is the site's point-in-time observation in a flat,
// agent-friendly shape: devices, networks with gateway bindings, ACL scope
// states, and the active client count.
type OmadaInventory struct {
	Site               string            `json:"site"`
	ControllerVersion  string            `json:"controller_version"`
	ControllerCategory string            `json:"controller_category,omitempty"`
	Devices            []serviceDevice   `json:"devices"`
	NetworkGateways    map[string]string `json:"network_gateways,omitempty"`
	ACLScopes          []serviceACLScope `json:"acl_scopes,omitempty"`
	ClientCount        int               `json:"client_count"`
	Warnings           []string          `json:"warnings,omitempty"`
}

// serviceDevice is one managed device (gateway, switch, or AP).
type serviceDevice struct {
	Type     string   `json:"type"`
	Name     string   `json:"name"`
	Model    string   `json:"model"`
	IP       string   `json:"ip,omitempty"`
	Firmware string   `json:"firmware,omitempty"`
	Upgrade  bool     `json:"upgrade_available,omitempty"`
	Networks []string `json:"networks,omitempty"`
}

// serviceACLScope is the enabled state of one ACL scope (gateway | switch).
type serviceACLScope struct {
	Scope           string `json:"scope"`
	Enabled         bool   `json:"enabled"`
	RuleCount       int    `json:"rule_count"`
	SupportLanToLan *bool  `json:"support_lan_to_lan,omitempty"`
}

// Inventory returns the site's device/network/ACL-scope/client observation.
// It is read-only: no controller state is mutated.
func (s *OmadaService) Inventory(ctx context.Context, opts OmadaOptions) (*OmadaInventory, error) {
	client, site, err := s.session(ctx, opts)
	if err != nil {
		return nil, err
	}
	defer client.Logout(ctx) //nolint:errcheck

	snap, err := client.FetchInventory(ctx, site.EffectiveID())
	if err != nil {
		return nil, err
	}
	inv := &OmadaInventory{
		Site:               site.Name,
		ControllerVersion:  snap.ControllerVersion,
		ControllerCategory: snap.ControllerCategory,
		Devices:            []serviceDevice{},
		ACLScopes:          []serviceACLScope{},
		ClientCount:        len(snap.Clients),
		Warnings:           snap.Warnings,
		NetworkGateways:    map[string]string{},
	}
	specInv := omadabackend.BuildSpecInventory(snap)
	inv.NetworkGateways = specInv.NetworkGateways
	for _, d := range specInv.Devices {
		inv.Devices = append(inv.Devices, serviceDevice{
			Type:     d.Type,
			Name:     d.Name,
			Model:    d.Model,
			IP:       d.IP,
			Firmware: d.Firmware,
			Upgrade:  d.Upgrade,
			Networks: d.Networks,
		})
	}
	for _, sc := range specInv.ACLScopes {
		inv.ACLScopes = append(inv.ACLScopes, serviceACLScope{
			Scope:           sc.Scope,
			Enabled:         sc.Enabled,
			RuleCount:       sc.RuleCount,
			SupportLanToLan: sc.SupportLanToLan,
		})
	}
	return inv, nil
}

// Import connects, imports the controller state, and produces an intent
// spec reflecting the observed design (networks, policies, assertions).
func (s *OmadaService) Import(ctx context.Context, opts OmadaOptions) (*OmadaImport, error) {
	result, err := omadabackend.ImportSpec(ctx, opts.Host, opts.ClientID, opts.ClientSecret, opts.Site,
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
	// Normalise endpoint sets once, before the provider and the post-audit
	// spec both consume them.
	req.From = dedupeNames(req.From)
	req.To = dedupeNames(req.To)
	res, err := applier.ApplyACL(ctx, providers.ACLApplyRequest{
		PolicyName: req.PolicyName,
		From:       req.From,
		To:         req.To,
		Action:     req.Action,
		Scope:      req.Scope,
		Protocols:  req.Protocols,
		DryRun:     req.DryRun,
	}, providers.ImportOptions{
		Host:          opts.Host,
		ClientID:      opts.ClientID,
		ClientSecret:  opts.ClientSecret,
		Site:          opts.Site,
		SkipTLSVerify: opts.SkipTLSVerify,
		CACertPath:    opts.CACertPath,
	})
	if err != nil {
		return nil, err
	}
	out := &OmadaACLApplyResult{
		DryRun:        res.DryRun,
		Outcome:       res.Outcome,
		RuleID:        res.RuleID,
		RuleName:      res.RuleName,
		Scope:         res.Scope,
		ScopeDisabled: res.ScopeDisabled,
		FromCIDRs:     res.FromCIDRs,
		ToCIDRs:       res.ToCIDRs,
		FromGateways:  res.FromGateways,
		ToGateways:    res.ToGateways,
		Before:        res.Before,
		After:         res.After,
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
// isolation assertions through the configured audit engine: one assertion
// per source endpoint, each checked against the full comma-joined
// destination set. The gateways from the apply result are mandatory:
// without them runIsolation has no target to ping and the audit is
// unverifiable by construction.
func (s *OmadaService) runPostAudit(ctx context.Context, req OmadaACLApplyRequest, res *providers.ACLApplyResult) *OmadaPostAudit {
	// A spec may not declare duplicate network names, so merge the endpoint
	// sets; From endpoints come first (the assertions name them).
	networks := make([]intent.Network, 0, len(req.From)+len(req.To))
	added := make(map[string]bool, len(req.From)+len(req.To))
	add := func(n intent.Network) {
		key := strings.ToLower(n.Name)
		if added[key] {
			return
		}
		added[key] = true
		networks = append(networks, n)
	}
	destNames := strings.Join(req.To, ",")
	assertions := make([]intent.Assertion, 0, len(req.From))
	for i, name := range req.From {
		add(intent.Network{Name: name, CIDR: at(res.FromCIDRs, i), Gateway: at(res.FromGateways, i)})
		assertions = append(assertions, intent.Assertion{Type: "isolation", From: name, To: destNames, Expect: req.Action})
	}
	for i, name := range req.To {
		add(intent.Network{Name: name, CIDR: at(res.ToCIDRs, i), Gateway: at(res.ToGateways, i)})
	}
	spec := &intent.Spec{Version: 1, Site: "post-mutation", Networks: networks, Assertions: assertions}
	if s.PostAudit == nil {
		return &OmadaPostAudit{Status: string(models.StatusError), Summary: "post-mutation audit unavailable"}
	}
	report, err := s.PostAudit(ctx, spec)
	if err != nil {
		return &OmadaPostAudit{Status: string(models.StatusError), Summary: fmt.Sprintf("post-mutation audit failed: %v", err)}
	}
	findings := make([]models.CheckResult, 0, len(assertions))
	for _, f := range report.Findings {
		if f.CheckType == "isolation" {
			findings = append(findings, f)
		}
	}
	if len(findings) == 0 {
		return &OmadaPostAudit{Status: string(models.StatusError), Summary: "post-mutation audit returned no isolation finding"}
	}
	return &OmadaPostAudit{
		Status:   string(models.ComputeOverallStatus(findings)),
		Summary:  fmt.Sprintf("post-mutation audit: %d isolation check(s), overall %s", len(findings), models.ComputeOverallStatus(findings)),
		Findings: findings,
	}
}

// at returns s[i] when in range, "" otherwise: result slices are
// positional against the request endpoints, and an absent value must not
// crash the post-audit.
func at(s []string, i int) string {
	if i >= 0 && i < len(s) {
		return s[i]
	}
	return ""
}

// dedupeNames drops empty and repeated endpoint names (case-insensitive,
// matching the controller's name resolution), keeping the first spelling.
func dedupeNames(names []string) []string {
	seen := make(map[string]bool, len(names))
	out := names[:0]
	for _, n := range names {
		key := strings.ToLower(strings.TrimSpace(n))
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, strings.TrimSpace(n))
	}
	return out
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
	if err := client.Login(ctx, opts.ClientID, opts.ClientSecret); err != nil {
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
