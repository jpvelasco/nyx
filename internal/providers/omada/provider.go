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
	result, err := omadabackend.ImportSpec(ctx, opts.Host, opts.ClientID, opts.ClientSecret, opts.Site, opts.Debug, opts.SkipTLSVerify, opts.CACertPath, opts.Logger)
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
	// Forward the TLS options so the audit-engine-backed assertions that talk
	// to the controller (acl_check, nat_check) honor the same
	// --skip-tls-verify / --ca-cert the import used. The import path and the
	// direct provider calls already respect them; the engine-backed path
	// builds its own client from the engine's fields.
	engine.SkipTLSVerify = opts.SkipTLSVerify
	engine.CACertPath = opts.CACertPath
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
// LAN networks with their gateway bindings, both ACL scopes and their rule
// counts, and the active client count. It is read-only and never mutates.
func (o *OmadaProvider) Inventory(ctx context.Context, opts providers.ImportOptions) (*providers.ProviderInventory, error) {
	client, err := omadabackend.NewClient(ctx, opts.Host, opts.SkipTLSVerify, opts.CACertPath)
	if err != nil {
		return nil, fmt.Errorf("connecting to omada controller: %w", err)
	}
	client.SetLogger(opts.Logger)
	if err := client.Login(ctx, opts.ClientID, opts.ClientSecret); err != nil {
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
	if err := client.Login(ctx, opts.ClientID, opts.ClientSecret); err != nil {
		result.Status = models.StatusError
		result.Summary = fmt.Sprintf("Omada token mint failed: %v", err)
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

	// Fetch both ACL scopes. The Open API has no scope enable/disable
	// flag, so an enabled matching rule is enforced.
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
		match.Scope = scopeLabel(match.Rule.Type)
		result.Observed["scope"] = match.Scope
	}
	result.Expected["policy"] = req.PolicyName
	result.Expected["expect"] = "enforced"

	switch {
	case req.ExpectEnforced && match != nil:
		result.Status = models.StatusPass
		result.Summary = fmt.Sprintf("ACL policy %q is enforced in Omada", req.PolicyName)
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

// NatCheck reads the site's NAT posture and evaluates it against the
// expected value. Omada exposes no outbound NAT mode — only managed-gateway
// presence and rule counts — so only the "present" expectation is
// definitive; mode expectations are reported as warn (observe the opnsense
// posture instead).
func (o *OmadaProvider) NatCheck(ctx context.Context, req providers.NatCheckRequest, opts providers.ImportOptions) (*models.CheckResult, error) {
	result := models.NewCheckResult("omada", "nat_check", "omada", req.ExpectMode)
	result.Expected["nat_mode"] = req.ExpectMode

	client, err := omadabackend.NewClient(ctx, opts.Host, opts.SkipTLSVerify, opts.CACertPath)
	if err != nil {
		return natCheckResult(result, "failed to connect to Omada: %v", err), nil
	}
	client.SetLogger(opts.Logger)
	if err := client.Login(ctx, opts.ClientID, opts.ClientSecret); err != nil {
		return natCheckResult(result, "Omada token mint failed: %v", err), nil
	}
	defer client.Logout(ctx) //nolint:errcheck

	sites, err := client.GetSites(ctx)
	if err != nil {
		return natCheckResult(result, "failed to fetch sites: %v", err), nil
	}
	site, err := omadabackend.SelectSite(sites, opts.Site)
	if err != nil {
		return natCheckResult(result, "%v", err), nil
	}
	siteID := site.EffectiveID()

	devices, err := client.GetDevices(ctx, siteID)
	if err != nil {
		return natCheckResult(result, "fetching devices: %v", err), nil
	}
	pfs, err := client.GetPortForwardings(ctx, siteID)
	if err != nil {
		return natCheckResult(result, "fetching port-forwarding rules: %v", err), nil
	}
	o2o, err := client.GetOneToOneNAT(ctx, siteID)
	if err != nil {
		return natCheckResult(result, "fetching one-to-one NAT rules: %v", err), nil
	}
	result.Finish()

	var hasGateway bool
	for _, d := range devices {
		if d.IsGateway() {
			hasGateway = true
			break
		}
	}
	result.Observed["managed_gateway"] = hasGateway
	result.Observed["site"] = site.Name
	result.Observed["port_forward_rules"] = len(pfs)
	result.Observed["one_to_one_rules"] = len(o2o)

	switch {
	case hasGateway && req.ExpectMode == "present":
		result.Status = models.StatusPass
		result.Summary = fmt.Sprintf("managed gateway present in site %s (port forward rules: %d, one-to-one rules: %d)", site.Name, len(pfs), len(o2o))
	case !hasGateway && req.ExpectMode == "present":
		result.Status = models.StatusFail
		result.Violations = append(result.Violations, "no managed gateway device in site; outbound NAT mode cannot be assessed")
		result.Summary = fmt.Sprintf("no managed gateway in site %s", site.Name)
	case !hasGateway:
		result.Status = models.StatusWarn
		result.Summary = fmt.Sprintf("no managed gateway in site %s — expect %q is not evaluable for Omada; observe the opnsense posture instead", site.Name, req.ExpectMode)
	default:
		result.Status = models.StatusWarn
		result.Summary = fmt.Sprintf("Omada site %s has a managed gateway; expect %q refers to an outbound NAT mode that Omada does not expose — use provider: opnsense for mode checks", site.Name, req.ExpectMode)
	}
	return result, nil
}

// natCheckResult finishes a failed NatCheck read with a StatusError and the
// given formatted summary.
func natCheckResult(result *models.CheckResult, format string, args ...any) *models.CheckResult {
	result.Status = models.StatusError
	result.Summary = fmt.Sprintf(format, args...)
	result.Finish()
	return result
}

// aclCheckMatch identifies the rule a policy refers to and the scope that
// rule lives in.
type aclCheckMatch struct {
	Rule      omadabackend.ACLRule
	Scope     string // "gateway" | "switch"
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

var _ providers.Provider = (*OmadaProvider)(nil)
var _ providers.ACLApplier = (*OmadaProvider)(nil)
var _ providers.InventoryProvider = (*OmadaProvider)(nil)
var _ providers.NatChecker = (*OmadaProvider)(nil)

func init() {
	_ = providers.Register(&OmadaProvider{})
}

// ApplyACL ensures a rule of the requested scope exists covering every
// from→to network pair with the requested action and protocol set. It is
// idempotent: a same-action, status-on rule of the same scope that already
// covers the request with an equal normalized protocol set yields outcome
// "unchanged" without a write, and a covering status-off rule is enabled.
// A covering rule with a different action is refused as a conflict with a
// pointer at the plan tool. Dry-run previews the planned change and never
// mutates. Before/after evidence is the controller's rule list of the
// requested scope, as JSON.
func (o *OmadaProvider) ApplyACL(ctx context.Context, req providers.ACLApplyRequest, opts providers.ImportOptions) (*providers.ACLApplyResult, error) {
	if len(req.From) == 0 {
		return nil, fmt.Errorf("apply ACL: from is required")
	}
	if len(req.To) == 0 {
		return nil, fmt.Errorf("apply ACL: to is required")
	}
	policy, ok := omadabackend.PolicyFromAction(req.Action)
	if !ok {
		return nil, fmt.Errorf("apply ACL: action must be 'allow' or 'deny', got %q", req.Action)
	}
	scopeType, ok := omadabackend.ScopeFromLabel(req.Scope)
	if !ok {
		return nil, fmt.Errorf("apply ACL: scope %q is not supported; use 'switch' or 'gateway'", req.Scope)
	}

	client, err := omadabackend.NewClient(ctx, opts.Host, opts.SkipTLSVerify, opts.CACertPath)
	if err != nil {
		return nil, fmt.Errorf("connecting to omada controller: %w", err)
	}
	client.SetLogger(opts.Logger)
	if err := client.Login(ctx, opts.ClientID, opts.ClientSecret); err != nil {
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
	srcs, err := networksByName(nets, req.From)
	if err != nil {
		return nil, err
	}
	dsts, err := networksByName(nets, req.To)
	if err != nil {
		return nil, err
	}

	list, err := client.FetchACLs(ctx, siteID, scopeType)
	if err != nil {
		return nil, fmt.Errorf("fetching ACL rules: %w", err)
	}
	rules := list.Rules
	omadabackend.ResolveRules(rules, nets)

	outcome, rule, err := classifyApply(rules, srcs, dsts, req, policy, scopeType)
	if err != nil {
		return nil, err
	}

	ruleID := rule.ID
	if !req.DryRun && outcome != "unchanged" {
		if outcome == "created" {
			err = client.CreateACLRule(ctx, siteID, rule)
		} else {
			err = client.UpdateACLRule(ctx, siteID, rule.ID, rule)
		}
		if err != nil {
			return nil, err
		}
	}

	before, _ := json.Marshal(rules)
	after := string(before)
	if !req.DryRun && outcome != "unchanged" {
		refreshedList, err := client.FetchACLs(ctx, siteID, scopeType)
		if err != nil {
			return nil, fmt.Errorf("refetching ACL rules after %s: %w", outcome, err)
		}
		refreshed := refreshedList.Rules
		afterJSON, _ := json.Marshal(refreshed)
		after = string(afterJSON)
		if outcome == "created" {
			ruleID = ""
			omadabackend.ResolveRules(refreshed, nets)
			for i := range refreshed {
				if refreshed[i].Policy.MatchesAction(req.Action) &&
					omadabackend.ProtocolsEqual(refreshed[i].Protocols, req.Protocols) &&
					omadabackend.RuleCovers(refreshed[i], srcs, dsts) {
					ruleID = refreshed[i].ID
					break
				}
			}
		}
	}

	return &providers.ACLApplyResult{
		DryRun:       req.DryRun,
		Outcome:      outcome,
		RuleID:       ruleID,
		RuleName:     rule.Name,
		Scope:        scopeLabel(scopeType),
		FromCIDRs:    networkList(srcs, func(n omadabackend.Network) string { return n.CIDR() }),
		ToCIDRs:      networkList(dsts, func(n omadabackend.Network) string { return n.CIDR() }),
		FromGateways: networkList(srcs, func(n omadabackend.Network) string { return n.Gateway() }),
		ToGateways:   networkList(dsts, func(n omadabackend.Network) string { return n.Gateway() }),
		Before:       string(before),
		After:        after,
	}, nil
}

// classifyApply decides the outcome for a cover-based apply over one scope:
// a covering rule with a different action is a conflict; a covering
// same-action rule is "unchanged" when on and "enabled" when off; otherwise
// a new rule is created.
func classifyApply(rules []omadabackend.ACLRule, srcs, dsts []omadabackend.Network, req providers.ACLApplyRequest, policy omadabackend.ACLPolicy, scopeType omadabackend.ACLType) (string, omadabackend.ACLRule, error) {
	var toEnable *omadabackend.ACLRule
	for i := range rules {
		r := rules[i]
		if !omadabackend.RuleCovers(r, srcs, dsts) || !omadabackend.ProtocolsEqual(r.Protocols, req.Protocols) {
			continue
		}
		if !r.Policy.MatchesAction(req.Action) {
			return "", omadabackend.ACLRule{}, fmt.Errorf(
				"conflicting ACL rule %q already covers %s -> %s with policy %q; use the omada_plan tool to reconcile",
				r.Name, joinNames(srcs), joinNames(dsts), r.Policy.String())
		}
		if r.Status {
			return "unchanged", r, nil
		}
		if toEnable == nil {
			toEnable = &rules[i]
		}
	}
	if toEnable != nil {
		r := *toEnable
		r.Status = true
		return "enabled", r, nil
	}

	rule := omadabackend.ACLRule{
		Name:       aclRuleName(req),
		Type:       scopeType,
		Status:     true,
		Policy:     policy,
		Protocols:  omadabackend.NormalizeProtocols(req.Protocols),
		SourceType: omadabackend.EndpointNetwork,
		SourceIDs:  idList(srcs),
		SourceName: joinNames(srcs),
		DestType:   omadabackend.EndpointNetwork,
		DestIDs:    idList(dsts),
		DestName:   joinNames(dsts),
	}
	if scopeType == omadabackend.ACLTypeGateway {
		// Gateway rules declare their path; the from→to pair is always LAN.
		rule.Direction = omadabackend.ACLDirection{LANToLAN: true}
	}
	return "created", rule, nil
}

// scopeLabel renders an ACL type as the agent-facing scope label.
func scopeLabel(typ omadabackend.ACLType) string {
	if typ == omadabackend.ACLTypeGateway {
		return "gateway"
	}
	return "switch"
}

// joinNames renders a network set as a comma-joined name list.
func joinNames(nets []omadabackend.Network) string {
	names := make([]string, len(nets))
	for i, n := range nets {
		names[i] = n.Name
	}
	return strings.Join(names, ",")
}

// idList collects the network IDs in order.
func idList(nets []omadabackend.Network) []string {
	ids := make([]string, len(nets))
	for i, n := range nets {
		ids[i] = n.ID
	}
	return ids
}

// networkList collects one network attribute per network in request
// order. An empty value is kept in place (as "") so callers can pair the
// slice positionally with the requested endpoint names; a network without
// a gateway subnet simply yields an empty pair.
func networkList(nets []omadabackend.Network, value func(omadabackend.Network) string) []string {
	out := make([]string, len(nets))
	for i, n := range nets {
		out[i] = value(n)
	}
	return out
}

// aclRuleName derives a rule name from the request, defaulting to a
// deterministic from-to-action pattern over the full endpoint sets.
func aclRuleName(req providers.ACLApplyRequest) string {
	if req.PolicyName != "" {
		return req.PolicyName
	}
	return fmt.Sprintf("%s-%s-%s",
		strings.ToLower(strings.Join(req.From, "-")),
		strings.ToLower(strings.Join(req.To, "-")),
		req.Action)
}

// networksByName resolves every requested network name case-insensitively,
// listing the available names in the error for agents.
func networksByName(nets []omadabackend.Network, names []string) ([]omadabackend.Network, error) {
	out := make([]omadabackend.Network, 0, len(names))
	for _, name := range names {
		n, err := networkByName(nets, name)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, nil
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
