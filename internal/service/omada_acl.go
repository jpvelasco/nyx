package service

import (
	"context"
	"fmt"
	"sort"
	"strings"

	omadabackend "github.com/jpvelasco/nyx/internal/backends/omada"
	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/models"
	providers "github.com/jpvelasco/nyx/internal/providers"
	omadaprovider "github.com/jpvelasco/nyx/internal/providers/omada"
)

// OmadaACLRule is a switch or gateway ACL rule in a flat, agent-friendly shape.
type OmadaACLRule struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Enabled       bool   `json:"enabled"`
	Policy        string `json:"policy"`
	Protocols     string `json:"protocols"`
	SourceType    string `json:"source_type"`
	SourceName    string `json:"source_name"`
	DestType      string `json:"dest_type"`
	DestName      string `json:"dest_name"`
	Index         int    `json:"index"`
	BiDirectional *bool  `json:"bi_directional,omitempty"`
	AppliedState  string `json:"applied_state,omitempty"`
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
	DryRun       bool            `json:"dry_run"`
	Outcome      string          `json:"outcome"` // "created" | "enabled" | "unchanged"
	RuleID       string          `json:"rule_id,omitempty"`
	RuleName     string          `json:"rule_name,omitempty"`
	Scope        string          `json:"scope"`
	FromCIDRs    []string        `json:"from_cidrs"`
	ToCIDRs      []string        `json:"to_cidrs"`
	FromGateways []string        `json:"from_gateways,omitempty"`
	ToGateways   []string        `json:"to_gateways,omitempty"`
	Before       string          `json:"before"`
	After        string          `json:"after"`
	PostAudit    *OmadaPostAudit `json:"post_audit,omitempty"`
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
		rule := OmadaACLRule{
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
		}
		if r.Type == omadabackend.ACLTypeSwitch {
			rule.BiDirectional = r.BiDirectional
			rule.AppliedState = omadabackend.SwitchACLAppliedStateHint
		}
		out = append(out, rule)
	}
	return out, nil
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
		DryRun:       res.DryRun,
		Outcome:      res.Outcome,
		RuleID:       res.RuleID,
		RuleName:     res.RuleName,
		Scope:        res.Scope,
		FromCIDRs:    res.FromCIDRs,
		ToCIDRs:      res.ToCIDRs,
		FromGateways: res.FromGateways,
		ToGateways:   res.ToGateways,
		Before:       res.Before,
		After:        res.After,
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
