package omada

import (
	"context"
	"fmt"
	"strings"

	"github.com/velasco-jp/netaudit/internal/intent"
)

// ImportResult holds the generated spec and a summary of what was found.
type ImportResult struct {
	Spec          *intent.Spec
	Site          Site
	NetworkCount  int
	ACLRuleCount  int
	ClientCount   int
	Warnings      []string
}

// ImportSpec connects to the controller, fetches all relevant configuration,
// and produces an intent.Spec that reflects the observed design.
func ImportSpec(ctx context.Context, host, username, password, siteName string, debug bool) (*ImportResult, error) {
	client, err := NewClient(ctx, host)
	if err != nil {
		return nil, err
	}
	client.Debug = debug
	defer client.Logout(ctx) //nolint:errcheck

	if err := client.Login(ctx, username, password); err != nil {
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
	site, err := selectSite(sites, siteName)
	if err != nil {
		return nil, err
	}

	result := &ImportResult{Site: site}

	// Fetch networks, ACLs, clients in parallel would be nice but keep it
	// simple and sequential for now — this is an interactive command, not
	// a hot path.
	omadaNets, err := client.GetNetworks(ctx, site.EffectiveID())
	if err != nil {
		return nil, fmt.Errorf("fetching networks: %w", err)
	}
	result.NetworkCount = len(omadaNets)

	aclRules, err := client.GetACLRules(ctx, site.EffectiveID())
	if err != nil {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("could not fetch ACL rules: %v", err))
	}

	gwRules, err := client.GetGatewayACLRules(ctx, site.EffectiveID())
	if err != nil {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("could not fetch gateway ACL rules: %v", err))
	}
	allRules := append(aclRules, gwRules...)
	result.ACLRuleCount = len(allRules)

	clients, err := client.GetClients(ctx, site.EffectiveID())
	if err != nil {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("could not fetch connected clients: %v", err))
	}
	result.ClientCount = len(clients)

	// Build the spec
	spec := &intent.Spec{
		Version: 1,
		Site:    site.Name,
	}

	// Map Omada networks → intent.Network
	netsByID := make(map[string]intent.Network)
	for _, n := range omadaNets {
		if n.Subnet == "" {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("network %q has no subnet configured, skipping", n.Name))
			continue
		}
		zone := inferZone(n)
		in := intent.Network{
			Name:    sanitizeName(n.Name),
			CIDR:    n.Subnet,
			Gateway: n.Gateway,
			Zone:    zone,
			VLAN:    n.VLANID,
		}
		spec.Networks = append(spec.Networks, in)
		netsByID[n.ID] = in
	}

	// Map enabled ACL rules → intent.Policy
	for _, rule := range allRules {
		if !rule.Status {
			continue // skip disabled rules
		}
		action := "deny"
		if strings.EqualFold(rule.Policy, "accept") {
			action = "allow"
		}
		from := resolveRuleEndpoint(rule.SourceType, rule.SourceName, rule.SourceID, netsByID)
		to := resolveRuleEndpoint(rule.DestType, rule.DestName, rule.DestID, netsByID)
		spec.Policies = append(spec.Policies, intent.Policy{
			Name:   sanitizeName(rule.Name),
			From:   from,
			To:     to,
			Action: action,
		})
	}

	// Generate assertions
	spec.Assertions = buildAssertions(spec.Networks, clients, allRules, netsByID)

	result.Spec = spec
	return result, nil
}

// buildAssertions generates a useful set of assertions from the imported data.
func buildAssertions(networks []intent.Network, clients []ConnectedClient, rules []ACLRule, netsByID map[string]intent.Network) []intent.Assertion {
	var assertions []intent.Assertion

	// Count clients per network to set reasonable discovery bounds
	clientsPerNet := make(map[string]int)
	for _, c := range clients {
		if c.NetworkName != "" {
			clientsPerNet[c.NetworkName]++
		}
	}

	// subnet_discovery + route_check per network
	for _, n := range networks {
		// Discovery assertion — bounds based on observed client count
		observed := clientsPerNet[n.Name]
		minHosts := 1 // at least the gateway
		maxHosts := max(observed*3, 20) // generous upper bound

		minVal := minHosts
		maxVal := maxHosts
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

	// Isolation assertions derived from deny ACL rules
	for _, rule := range rules {
		if !rule.Status {
			continue
		}
		if !strings.EqualFold(rule.Policy, "drop") && !strings.EqualFold(rule.Policy, "deny") {
			continue
		}
		from := resolveRuleEndpoint(rule.SourceType, rule.SourceName, rule.SourceID, netsByID)
		to := resolveRuleEndpoint(rule.DestType, rule.DestName, rule.DestID, netsByID)
		if from == "" || to == "" {
			continue
		}
		assertions = append(assertions, intent.Assertion{
			Type:       "isolation",
			From:       from,
			To:         to,
			ExpectDeny: "deny",
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
	case strings.Contains(lower, "mgmt") || strings.Contains(lower, "manage") || strings.Contains(lower, "opus"):
		return "management"
	case strings.Contains(lower, "iot") || strings.Contains(lower, "pinball"):
		return "iot"
	case strings.Contains(lower, "guest"):
		return "guest"
	case strings.Contains(lower, "server") || strings.Contains(lower, "papyrus"):
		return "servers"
	case strings.Contains(lower, "cinema") || strings.Contains(lower, "media"):
		return "media"
	case strings.Contains(lower, "arcade") || strings.Contains(lower, "gaming") || strings.Contains(lower, "game"):
		return "gaming"
	case strings.Contains(lower, "valhalla") || strings.Contains(lower, "mobile") || strings.Contains(lower, "wifi"):
		return "mobile"
	default:
		if n.Isolated {
			return "isolated"
		}
		return "trusted"
	}
}

// resolveRuleEndpoint returns a human-readable zone/network name for an ACL
// rule source or destination.
func resolveRuleEndpoint(epType, name, id string, netsByID map[string]intent.Network) string {
	if name != "" {
		return sanitizeName(name)
	}
	if n, ok := netsByID[id]; ok {
		return n.Name
	}
	if id != "" {
		return id
	}
	return epType
}

// sanitizeName converts an Omada display name to a lowercase slug safe for
// use as a YAML key.
func sanitizeName(s string) string {
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, " ", "-")
	s = strings.ReplaceAll(s, "_", "-")
	// Remove any characters that aren't alphanumeric or hyphen
	var out strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			out.WriteRune(r)
		}
	}
	return strings.Trim(out.String(), "-")
}

// selectSite finds the site matching siteName, or returns the first site if
// siteName is empty. Returns an error if siteName is set but not found.
func selectSite(sites []Site, siteName string) (Site, error) {
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

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
