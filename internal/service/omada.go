package service

import (
	"context"
	"fmt"
	"sort"

	omadabackend "github.com/jpvelasco/nyx/internal/backends/omada"
	"github.com/jpvelasco/nyx/internal/intent"
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

// OmadaService exposes the Omada observation surface shared by the MCP server
// and any future CLI commands. NewClient is a seam for tests.
type OmadaService struct {
	NewClient func(ctx context.Context, host string, skipTLSVerify bool, caCertPath string) (*omadabackend.Client, error)
}

// NewOmadaService creates an OmadaService using the real controller client.
func NewOmadaService() *OmadaService {
	return &OmadaService{NewClient: omadabackend.NewClient}
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

	rules, err := client.GetACLRules(ctx, site.EffectiveID())
	if err != nil {
		return nil, fmt.Errorf("fetching ACL rules: %w", err)
	}
	gwRules, err := client.GetGatewayACLRules(ctx, site.EffectiveID())
	if err != nil {
		return nil, fmt.Errorf("fetching gateway ACL rules: %w", err)
	}

	out := make([]OmadaACLRule, 0, len(rules)+len(gwRules))
	for _, r := range append(rules, gwRules...) {
		out = append(out, OmadaACLRule{
			ID:         r.ID,
			Name:       r.Name,
			Enabled:    r.Status,
			Policy:     r.Policy,
			Protocols:  r.Protocols,
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
