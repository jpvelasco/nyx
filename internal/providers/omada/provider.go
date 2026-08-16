// Package omadaprovider implements the providers.Provider interface for TP-Link Omada SDN controllers (v6+).
package omadaprovider

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/jpvelasco/nyx/internal/audit"
	omadabackend "github.com/jpvelasco/nyx/internal/backends/omada"
	"github.com/jpvelasco/nyx/internal/models"
	providers "github.com/jpvelasco/nyx/internal/providers"
)

// ProviderName is the registry identifier for the Omada provider.
const ProviderName = "omada"

// OmadaProvider implements providers.Provider for TP-Link Omada SDN controllers.
type OmadaProvider struct{}

// Name returns the provider identifier "omada".
func (o *OmadaProvider) Name() string { return ProviderName }

// Capabilities lists the supported operations for this provider.
func (o *OmadaProvider) Capabilities() []string {
	return []string{"info", "import", "check", "inventory"}
}

// Info returns basic controller information without requiring authentication.
func (o *OmadaProvider) Info(ctx context.Context, opts providers.ImportOptions) (*providers.ProviderInfo, error) {
	client, err := omadabackend.NewClient(ctx, opts.Host, opts.SkipTLSVerify, opts.CACertPath)
	if err != nil {
		return nil, fmt.Errorf("connecting to omada controller: %w", err)
	}
	client.SetLogger(opts.Logger)
	info := client.Info()
	return &providers.ProviderInfo{
		Provider: "omada",
		Host:     opts.Host,
		Version:  info.ControllerVer,
		Extra: map[string]string{
			"api_version": info.APIVer,
			"omada_cid":   info.OmadaCID,
		},
	}, nil
}

// ImportSpec imports networks, policies, and clients from the Omada controller and returns a generated intent spec.
func (o *OmadaProvider) ImportSpec(ctx context.Context, opts providers.ImportOptions) (*providers.ImportResult, error) {
	result, err := omadabackend.ImportSpec(ctx, opts.Host, opts.Username, opts.Password, opts.Site, opts.Debug, opts.SkipTLSVerify, opts.CACertPath, opts.Logger)
	if err != nil {
		return nil, err
	}
	return &providers.ImportResult{
		Spec: result.Spec,
		ProviderInfo: providers.ProviderInfo{
			Provider: "omada",
			Host:     opts.Host,
			Version:  result.ControllerVersion,
		},
		NetworkCount: result.NetworkCount,
		PolicyCount:  result.ACLRuleCount,
		ClientCount:  result.ClientCount,
		Warnings:     result.Warnings,
	}, nil
}

// Check imports a spec from the controller and runs an audit against it.
func (o *OmadaProvider) Check(ctx context.Context, opts providers.ImportOptions) (*providers.AuditResult, error) {
	imported, err := o.ImportSpec(ctx, opts)
	if err != nil {
		return nil, err
	}
	engine := audit.NewEngine(imported.Spec)
	report, err := engine.Run(ctx)
	if err != nil {
		return nil, fmt.Errorf("audit failed: %w", err)
	}
	return &providers.AuditResult{
		Report:   report,
		Warnings: imported.Warnings,
	}, nil
}

// Inventory returns the site's point-in-time observation: device inventory,
// LAN networks with their gateway bindings, both ACL scopes and their
// enabled state, and the active client count. It is read-only and never
// mutates.
func (o *OmadaProvider) Inventory(ctx context.Context, opts providers.ImportOptions) (*providers.ProviderInventory, error) {
	client, err := omadabackend.NewClient(ctx, opts.Host, opts.SkipTLSVerify, opts.CACertPath)
	if err != nil {
		return nil, fmt.Errorf("connecting to omada controller: %w", err)
	}
	client.SetLogger(opts.Logger)
	if err := client.Login(ctx, opts.Username, opts.Password); err != nil {
		return nil, err
	}
	defer client.Logout(ctx) //nolint:errcheck

	sites, err := client.GetSites(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching sites: %w", err)
	}
	site, err := omadabackend.SelectSite(sites, opts.Site)
	if err != nil {
		return nil, err
	}

	snap, err := client.FetchInventory(ctx, site.EffectiveID())
	if err != nil {
		return nil, err
	}
	return &providers.ProviderInventory{
		Site:        site.Name,
		Human:       omadabackend.RenderInventory(snap, site.Name),
		Inventory:   omadabackend.BuildSpecInventory(snap),
		ClientCount: len(snap.Clients),
		Warnings:    snap.Warnings,
	}, nil
}

// CheckACL verifies that an ACL policy is enforced (or not) on the Omada controller.
func (o *OmadaProvider) CheckACL(ctx context.Context, req providers.ACLCheckRequest, opts providers.ImportOptions) (*models.CheckResult, error) {
	result := models.NewCheckResult("omada", "acl_check", "omada", req.PolicyName)

	client, err := omadabackend.NewClient(ctx, opts.Host, opts.SkipTLSVerify, opts.CACertPath)
	if err != nil {
		result.Status = models.StatusError
		result.Summary = fmt.Sprintf("failed to connect to Omada: %v", err)
		result.Finish()
		return result, nil
	}
	client.SetLogger(opts.Logger)
	if err := client.Login(ctx, opts.Username, opts.Password); err != nil {
		result.Status = models.StatusError
		result.Summary = fmt.Sprintf("Omada login failed: %v", err)
		result.Finish()
		return result, nil
	}
	defer client.Logout(ctx)

	// The ACL endpoints address the site by its ID, not its display name —
	// resolve the configured site name first.
	sites, err := client.GetSites(ctx)
	if err != nil {
		result.Status = models.StatusError
		result.Summary = fmt.Sprintf("failed to fetch sites: %v", err)
		result.Finish()
		return result, nil
	}
	site, err := omadabackend.SelectSite(sites, opts.Site)
	if err != nil {
		result.Status = models.StatusError
		result.Summary = err.Error()
		result.Finish()
		return result, nil
	}
	siteID := site.EffectiveID()

	// Fetch both ACL scopes with their capability flags. A scope's
	// aclDisable master switch means its rules are stored but not enforced —
	// the verdict must reflect that, so the raw FetchACLs meta is kept.
	swList, swErr := client.FetchACLs(ctx, siteID, omadabackend.ACLTypeSwitch)
	gwList, gwErr := client.FetchACLs(ctx, siteID, omadabackend.ACLTypeGateway)
	if swErr != nil {
		result.Status = models.StatusError
		result.Summary = fmt.Sprintf("failed to fetch switch ACL rules: %v", swErr)
		result.Finish()
		return result, nil
	}
	allRules := append(swList.Rules, gwList.Rules...)

	if nets, nerr := client.GetNetworks(ctx, siteID); nerr == nil {
		omadabackend.ResolveRules(allRules, nets)
	}

	// A failed gateway ACL fetch leaves the negative verdicts incomplete: a
	// gateway-scoped rule we could not enumerate would flip them. Surface the
	// error and downgrade instead of failing on partial evidence.
	if gwErr != nil {
		result.Evidence = append(result.Evidence,
			fmt.Sprintf("gateway ACL rules could not be fetched: %v — verdict covers switch ACLs only", gwErr))
	}

	// Match by policy (rule) name first — the spec keys acl_check off the
	// policy, which is the sanitized rule name — then fall back to
	// from/to/action matching for hand-written specs.
	match := lookupACLMatch(allRules, req)
	rulesJSON, _ := json.Marshal(allRules)
	result.Evidence = append(result.Evidence, string(rulesJSON))
	result.Observed["rule_count"] = len(allRules)
	if match != nil {
		match.Scope, match.Disabled = aclScopeFlags(swList, gwList, match.Rule)
		result.Observed["scope"] = match.Scope
		result.Observed["scope_disabled"] = match.Disabled
	}
	result.Expected["policy"] = req.PolicyName
	result.Expected["expect"] = "enforced"

	switch {
	case req.ExpectEnforced && match != nil && !match.Disabled:
		result.Status = models.StatusPass
		result.Summary = fmt.Sprintf("ACL policy %q is enforced in Omada", req.PolicyName)
	case req.ExpectEnforced && match != nil && match.Disabled:
		result.Status = models.StatusFail
		result.Summary = fmt.Sprintf("ACL policy %q is stored but NOT enforced: its %s ACL scope is disabled (aclDisable=true)", req.PolicyName, match.Scope)
		result.Violations = append(result.Violations,
			fmt.Sprintf("rule %q exists (status enabled) but the %s ACL master switch is off on the controller — enable the scope before relying on this rule", match.Rule.Name, match.Scope))
	case req.ExpectEnforced && match == nil:
		result.Status = models.StatusFail
		result.Summary = fmt.Sprintf("ACL policy %q is NOT enforced in Omada", req.PolicyName)
		result.Violations = append(result.Violations,
			fmt.Sprintf("no matching ACL rule found for policy %q (%s → %s %s)", req.PolicyName, req.From, req.To, req.Action))
	case !req.ExpectEnforced && match == nil:
		result.Status = models.StatusPass
		result.Summary = fmt.Sprintf("ACL policy %q is correctly not enforced", req.PolicyName)
	default:
		result.Status = models.StatusFail
		result.Summary = fmt.Sprintf("ACL policy %q is enforced but expected not_enforced", req.PolicyName)
	}

	// A negative verdict is only trustworthy when every ACL scope responded:
	// a gateway-scoped rule that could not be fetched would flip it.
	if gwErr != nil && result.Status == models.StatusFail {
		result.Status = models.StatusWarn
		result.Summary += " (gateway ACLs unverified — check the controller for gateway-scoped rules)"
	}

	result.Finish()
	return result, nil
}

// aclCheckMatch identifies the rule a policy refers to, plus whether the
// scope that rule lives in is disabled (stored but not enforced).
type aclCheckMatch struct {
	Rule      omadabackend.ACLRule
	Scope     string // "gateway" | "switch"
	Disabled  bool   // the scope's aclDisable master switch is on
	MatchedBy string // "name" | "endpoints"
}

// lookupACLMatch finds the active rule implementing the requested policy.
// The rule name (sanitized) is the primary key; from/to/action matching is
// the fallback for hand-written specs that name policies freely.
func lookupACLMatch(rules []omadabackend.ACLRule, req providers.ACLCheckRequest) *aclCheckMatch {
	for i := range rules {
		r := rules[i]
		if !r.Status {
			continue
		}
		if strings.EqualFold(omadabackend.SanitizeName(r.Name), req.PolicyName) &&
			r.Policy.MatchesAction(req.Action) {
			return &aclCheckMatch{Rule: r, MatchedBy: "name"}
		}
	}
	for i := range rules {
		r := rules[i]
		if !r.Status {
			continue
		}
		if omadabackend.RuleMatchesNames(r, req.From, req.To) && r.Policy.MatchesAction(req.Action) {
			return &aclCheckMatch{Rule: r, MatchedBy: "endpoints"}
		}
	}
	return nil
}

// aclScopeFlags reports the scope label and disabled flag of the list a rule
// was found in.
func aclScopeFlags(sw, gw omadabackend.ACLList, rule omadabackend.ACLRule) (string, bool) {
	switch rule.Type {
	case omadabackend.ACLTypeGateway:
		return "gateway", gw.ACLDisable
	default:
		return "switch", sw.ACLDisable
	}
}

var _ providers.Provider = (*OmadaProvider)(nil)
var _ providers.ACLApplier = (*OmadaProvider)(nil)
var _ providers.InventoryProvider = (*OmadaProvider)(nil)

func init() {
	_ = providers.Register(&OmadaProvider{})
}

// ApplyACL ensures a switch ACL rule exists from req.From to req.To with the
// requested action. It is idempotent: an already-active matching rule yields
// outcome "unchanged" without a write. Dry-run previews the planned change
// and never mutates. A conflicting rule with a different policy is refused
// with a message pointing at the plan tool. Before/after evidence is the
// controller's rule list as JSON.
func (o *OmadaProvider) ApplyACL(ctx context.Context, req providers.ACLApplyRequest, opts providers.ImportOptions) (*providers.ACLApplyResult, error) {
	if req.From == "" {
		return nil, fmt.Errorf("apply ACL: from is required")
	}
	if req.To == "" {
		return nil, fmt.Errorf("apply ACL: to is required")
	}
	policy, ok := omadabackend.PolicyFromAction(req.Action)
	if !ok {
		return nil, fmt.Errorf("apply ACL: action must be 'allow' or 'deny', got %q", req.Action)
	}

	client, err := omadabackend.NewClient(ctx, opts.Host, opts.SkipTLSVerify, opts.CACertPath)
	if err != nil {
		return nil, fmt.Errorf("connecting to omada controller: %w", err)
	}
	client.SetLogger(opts.Logger)
	if err := client.Login(ctx, opts.Username, opts.Password); err != nil {
		return nil, err
	}
	defer client.Logout(ctx) //nolint:errcheck

	sites, err := client.GetSites(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching sites: %w", err)
	}
	site, err := omadabackend.SelectSite(sites, opts.Site)
	if err != nil {
		return nil, err
	}
	siteID := site.EffectiveID()

	nets, err := client.GetNetworks(ctx, siteID)
	if err != nil {
		return nil, fmt.Errorf("fetching networks: %w", err)
	}
	src, err := networkByName(nets, req.From)
	if err != nil {
		return nil, err
	}
	dst, err := networkByName(nets, req.To)
	if err != nil {
		return nil, err
	}

	rules, err := client.GetACLRules(ctx, siteID)
	if err != nil {
		return nil, fmt.Errorf("fetching ACL rules: %w", err)
	}

	omadabackend.ResolveRules(rules, nets)

	var existing *omadabackend.ACLRule
	for i := range rules {
		if omadabackend.RuleMatchesEndpoints(rules[i], src, dst) {
			existing = &rules[i]
			break
		}
	}

	outcome := "created"
	var rule omadabackend.ACLRule
	switch {
	case existing == nil:
		rule = omadabackend.ACLRule{
			Name:       aclRuleName(req),
			Type:       omadabackend.ACLTypeSwitch,
			Status:     true,
			Policy:     policy,
			Protocols:  []int{omadabackend.ProtocolAll},
			SourceType: omadabackend.EndpointNetwork,
			SourceIDs:  []string{src.ID},
			SourceName: src.Name,
			DestType:   omadabackend.EndpointNetwork,
			DestIDs:    []string{dst.ID},
			DestName:   dst.Name,
		}
	case existing.Policy.MatchesAction(req.Action) && existing.Status:
		outcome = "unchanged"
		rule = *existing
	case existing.Policy.MatchesAction(req.Action) && !existing.Status:
		outcome = "enabled"
		rule = *existing
		rule.Status = true
	default:
		return nil, fmt.Errorf(
			"conflicting ACL rule %q already exists for %s -> %s with policy %q; use the omada_plan tool to reconcile",
			existing.Name, src.Name, dst.Name, existing.Policy.String())
	}

	ruleID := rule.ID
	if !req.DryRun && outcome != "unchanged" {
		var err error
		if outcome == "created" {
			_, err = client.CreateACLRule(ctx, siteID, rule)
		} else {
			_, err = client.UpdateACLRule(ctx, siteID, rule.ID, rule)
		}
		if err != nil {
			return nil, err
		}
	}

	before, _ := json.Marshal(rules)
	after := string(before)
	if !req.DryRun && outcome != "unchanged" {
		refreshed, err := client.GetACLRules(ctx, siteID)
		if err != nil {
			return nil, fmt.Errorf("refetching ACL rules after %s: %w", outcome, err)
		}
		afterJSON, _ := json.Marshal(refreshed)
		after = string(afterJSON)
		if outcome == "created" {
			ruleID = ""
			omadabackend.ResolveRules(refreshed, nets)
			for i := range refreshed {
				if omadabackend.RuleMatchesEndpoints(refreshed[i], src, dst) &&
					refreshed[i].Policy.MatchesAction(req.Action) {
					ruleID = refreshed[i].ID
					break
				}
			}
		}
	}

	return &providers.ACLApplyResult{
		DryRun:      req.DryRun,
		Outcome:     outcome,
		RuleID:      ruleID,
		FromCIDR:    src.CIDR(),
		ToCIDR:      dst.CIDR(),
		FromGateway: src.Gateway(),
		ToGateway:   dst.Gateway(),
		Before:      string(before),
		After:       after,
	}, nil
}

// aclRuleName derives a rule name from the request, defaulting to a
// deterministic from-to-action pattern.
func aclRuleName(req providers.ACLApplyRequest) string {
	if req.PolicyName != "" {
		return req.PolicyName
	}
	return fmt.Sprintf("%s-%s-%s", strings.ToLower(req.From), strings.ToLower(req.To), req.Action)
}

// networkByName resolves a network name case-insensitively, listing the
// available names in the error for agents.
func networkByName(nets []omadabackend.Network, name string) (omadabackend.Network, error) {
	if n, ok := omadabackend.FindNetwork(nets, name); ok {
		return n, nil
	}
	names := make([]string, 0, len(nets))
	for _, n := range nets {
		names = append(names, n.Name)
	}
	sort.Strings(names)
	return omadabackend.Network{}, fmt.Errorf("no network named %q; available: %s", name, strings.Join(names, ", "))
}
