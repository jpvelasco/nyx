package omada

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/jpvelasco/nyx/internal/intent"
)

// ImportResult holds the generated spec and a summary of what was found.
type ImportResult struct {
	Spec              *intent.Spec
	Site              Site
	ControllerVersion string
	NetworkCount      int
	ACLRuleCount      int
	ClientCount       int
	Warnings          []string
}

// ImportSpec connects to the controller, fetches all relevant configuration,
// and produces an intent.Spec that reflects the observed design. log is an
// optional structured logger for operation events (may be nil).
func ImportSpec(ctx context.Context, host, clientID, clientSecret, siteName string, debug bool, skipTLSVerify bool, caCertPath string, log *slog.Logger) (*ImportResult, error) {
	client, err := NewClient(ctx, host, skipTLSVerify, caCertPath)
	if err != nil {
		return nil, err
	}
	client.Debug = debug
	client.SetLogger(log)
	defer client.Logout(ctx) //nolint:errcheck

	if err := client.Login(ctx, clientID, clientSecret); err != nil {
		return nil, err
	}

	// Get sites
	sites, err := client.GetSites(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching sites: %w", err)
	}
	if len(sites) == 0 {
		return nil, fmt.Errorf("no sites found on controller")
	}

	// Pick the target site
	site, err := SelectSite(sites, siteName)
	if err != nil {
		return nil, err
	}

	result := &ImportResult{
		Site:              site,
		ControllerVersion: client.Info().ControllerVer,
	}

	// Fetch networks, ACLs, clients in parallel would be nice but keep it
	// simple and sequential for now — this is an interactive command, not
	// a hot path.
	omadaNets, err := client.GetNetworks(ctx, site.EffectiveID())
	if err != nil {
		return nil, fmt.Errorf("fetching networks: %w", err)
	}
	result.NetworkCount = len(omadaNets)

	siteID := site.EffectiveID()
	aclList, aclErr := client.FetchACLs(ctx, siteID, ACLTypeSwitch)
	if aclErr != nil {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("could not fetch ACL rules: %v", aclErr))
	}
	aclListOK := aclErr == nil

	gwList, gwErr := client.FetchACLs(ctx, siteID, ACLTypeGateway)
	if gwErr != nil {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("could not fetch gateway ACL rules: %v", gwErr))
	}
	gwListOK := gwErr == nil
	allRules := append(aclList.Rules, gwList.Rules...)
	result.ACLRuleCount = len(allRules)

	clients, err := client.GetClients(ctx, siteID)
	if err != nil {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("could not fetch connected clients: %v", err))
	}
	// The thin client wire has no IP or network name: best-effort
	// enrichment from the site's DHCP user list fills IP, network name,
	// and VLAN per MAC.
	if err := client.EnrichFromDHCP(ctx, siteID, clients, omadaNets); err != nil {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("could not enrich clients from DHCP user list: %v", err))
	}
	result.ClientCount = len(clients)

	devices, err := client.GetDevices(ctx, siteID)
	if err != nil {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("could not fetch device inventory: %v", err))
	}

	// Build the spec
	spec := &intent.Spec{
		Version: 1,
		Site:    site.Name,
	}

	// Map Omada networks → intent.Network
	netsByID := make(map[string]intent.Network)
	for _, n := range omadaNets {
		cidr := n.CIDR()
		if cidr == "" {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("network %q has no subnet configured (gatewaySubnet=%q), skipping", n.Name, n.GatewaySubnet))
			continue
		}
		zone := inferZone(n)
		in := intent.Network{
			Name:    sanitizeName(n.Name),
			CIDR:    cidr,
			Gateway: n.Gateway(),
			Zone:    zone,
			VLAN:    n.VLANID,
		}
		spec.Networks = append(spec.Networks, in)
		netsByID[n.ID] = in
	}

	// Map enabled ACL rules → intent.Policy
	spec.Policies = PoliciesFromRules(allRules, omadaNets)

	// Generate assertions
	spec.Assertions = buildAssertions(spec.Networks, omadaNets, clients, allRules, netsByID)

	// Inventory snapshot: what the controller's devices and ACL scopes look
	// like right now, so audits can flag drift (e.g. ACL rule count).
	spec.Inventory = BuildSpecInventory(&InventorySnapshot{
		ControllerVersion:  result.ControllerVersion,
		ControllerCategory: client.Info().Category,
		Devices:            devices,
		Networks:           omadaNets,
		GatewayACLs:        gwList,
		GatewayACLsOK:      gwListOK,
		SwitchACLs:         aclList,
		SwitchACLsOK:       aclListOK,
		Clients:            clients,
	})

	result.Spec = spec
	return result, nil
}

// PoliciesFromRules converts enabled ACL rules to intent policies the same
// way ImportSpec does, so a plan can be diffed against a proposed spec.
// Disabled rules are skipped; endpoints resolve to sanitized network names.
func PoliciesFromRules(rules []ACLRule, networks []Network) []intent.Policy {
	netsByID := make(map[string]intent.Network, len(networks))
	for _, n := range networks {
		netsByID[n.ID] = intent.Network{Name: sanitizeName(n.Name), CIDR: n.CIDR(), Gateway: n.Gateway()}
	}
	var policies []intent.Policy
	for _, rule := range rules {
		if !rule.Status {
			continue // skip disabled rules
		}
		action := rule.Policy.Action()
		if action == "" {
			action = "deny"
		}
		from := resolveRuleEndpoint(rule.SourceType.String(), rule.SourceName, rule.SourceIDs, netsByID)
		to := resolveRuleEndpoint(rule.DestType.String(), rule.DestName, rule.DestIDs, netsByID)
		policies = append(policies, intent.Policy{
			Name:   sanitizeName(rule.Name),
			From:   from,
			To:     to,
			Action: action,
		})
	}
	return policies
}

// buildAssertions generates a useful set of assertions from the imported data.
func buildAssertions(networks []intent.Network, omadaNets []Network, clients []ConnectedClient, rules []ACLRule, netsByID map[string]intent.Network) []intent.Assertion {
	var assertions []intent.Assertion

	// Count clients per network using the raw Omada network name
	// (before sanitization) — clients arrive enriched via EnrichFromDHCP,
	// so NetworkName is populated for every client the controller reports.
	clientsPerNet := make(map[string]int)
	for _, c := range clients {
		if c.NetworkName != "" {
			clientsPerNet[c.NetworkName]++
		}
	}

	// Build a map from sanitized name → original Omada name for lookup
	origName := make(map[string]string)
	for _, n := range omadaNets {
		origName[sanitizeName(n.Name)] = n.Name
	}

	// subnet_discovery + route_check per network
	for _, n := range networks {
		orig := origName[n.Name]
		observed := clientsPerNet[orig]
		// Min is 0 — many devices (IoT, mobile) block ICMP so nmap won't see them
		// Max is generous: observed client count × 3, at least 20
		minVal := 0
		maxVal := maxInt(observed*3, 20)

		assertions = append(assertions, intent.Assertion{
			Type:           "subnet_discovery",
			Network:        n.Name,
			ExpectHostsMin: &minVal,
			ExpectHostsMax: &maxVal,
		})

		// Route check to gateway
		if n.Gateway != "" {
			assertions = append(assertions, intent.Assertion{
				Type:   "route_check",
				Target: n.Gateway,
			})
		}
	}

	// Enforced-state assertions: one acl_check per enabled ACL rule, keyed
	// off the sanitized rule name (the spec's policy name). A rule counts
	// as enforced when a covering rule is present and enabled in its
	// scope.
	for _, rule := range rules {
		if !rule.Status {
			continue
		}
		assertions = append(assertions, intent.Assertion{
			Type:     "acl_check",
			Provider: "omada",
			Policy:   sanitizeName(rule.Name),
			Expect:   "enforced",
		})
	}

	// Isolation assertions derived from deny ACL rules
	for _, rule := range rules {
		if !rule.Status {
			continue
		}
		if !rule.Policy.IsDeny() {
			continue
		}
		from := resolveRuleEndpoint(rule.SourceType.String(), rule.SourceName, rule.SourceIDs, netsByID)
		to := resolveRuleEndpoint(rule.DestType.String(), rule.DestName, rule.DestIDs, netsByID)
		if from == "" || to == "" {
			continue
		}
		assertions = append(assertions, intent.Assertion{
			Type:   "isolation",
			From:   from,
			To:     to,
			Expect: "deny",
		})
	}

	// Always add internet reachability check
	assertions = append(assertions, intent.Assertion{
		Type:   "route_check",
		Target: "8.8.8.8",
	})

	return assertions
}

// inferZone maps Omada network properties to a zone name.
func inferZone(n Network) string {
	lower := strings.ToLower(n.Name)
	switch {
	case strings.Contains(lower, "mgmt") || strings.Contains(lower, "manage"):
		return "management"
	case strings.Contains(lower, "iot"):
		return "iot"
	case strings.Contains(lower, "guest"):
		return "guest"
	case strings.Contains(lower, "server"):
		return "servers"
	case strings.Contains(lower, "media") || strings.Contains(lower, "theater"):
		return "media"
	case strings.Contains(lower, "game") || strings.Contains(lower, "gaming"):
		return "gaming"
	case strings.Contains(lower, "mobile") || strings.Contains(lower, "wifi"):
		return "personal"
	default:
		if n.Isolated {
			return "isolated"
		}
		return "trusted"
	}
}

// resolveRuleEndpoint returns a human-readable zone/network name for an ACL
// rule source or destination. Names win; otherwise IDs are resolved against
// the network map (joined with commas when a rule has several).
func resolveRuleEndpoint(epType, name string, ids []string, netsByID map[string]intent.Network) string {
	if name != "" {
		return sanitizeName(name)
	}
	if len(ids) == 0 {
		// "network" with no IDs is unresolved, not an endpoint named "network".
		if epType == "" || epType == EndpointNetwork.String() {
			return ""
		}
		return epType
	}
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		if n, ok := netsByID[id]; ok {
			parts = append(parts, n.Name)
			continue
		}
		parts = append(parts, id)
	}
	return strings.Join(parts, ",")
}

// SanitizeName is the cross-package form of sanitizeName: the provider layer
// matches spec names (sanitized slugs) against raw controller rule names.
func SanitizeName(s string) string {
	return sanitizeName(s)
}

// sanitizeName converts an Omada display name to a lowercase slug safe for
// use as a YAML key. Strips parenthetical suffixes like "(Default)".
func sanitizeName(s string) string {
	// Strip parenthetical suffixes e.g. "Trusted(Default)" → "Trusted"
	if i := strings.Index(s, "("); i > 0 {
		s = s[:i]
	}
	s = strings.TrimSpace(s)
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, " ", "-")
	s = strings.ReplaceAll(s, "_", "-")
	var out strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			out.WriteRune(r)
		}
	}
	return strings.Trim(out.String(), "-")
}

// SelectSite finds the site matching siteName, or returns the first site if
// siteName is empty. Returns an error if siteName is set but not found.
func SelectSite(sites []Site, siteName string) (Site, error) {
	if siteName == "" {
		return sites[0], nil
	}
	for _, s := range sites {
		if strings.EqualFold(s.Name, siteName) {
			return s, nil
		}
	}
	names := make([]string, len(sites))
	for i, s := range sites {
		names[i] = s.Name
	}
	return Site{}, fmt.Errorf("site %q not found; available sites: %s",
		siteName, strings.Join(names, ", "))
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
