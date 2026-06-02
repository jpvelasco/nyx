// Package recommendations analyzes audit failures and produces prioritized, actionable recommendations
// with optional spec patches. It classifies into categories like vantage_point, isolation_breach, etc.
package recommendations

import (
	"fmt"
	"net"
	"slices"
	"strings"

	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/models"
)

// Recommendation represents an actionable fix for one or more failures.
type Recommendation struct {
	Priority    int      `json:"priority"`
	Category    string   `json:"category"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Remediation string   `json:"remediation"`
	Affected    []string `json:"affected"`
	SpecPatch   string   `json:"spec_patch,omitempty"`
}

// failureGroup classifies a set of failures by their root cause.
type failureGroup struct {
	category string
	failures []models.CheckResult
	// isolationContext is populated only for vantage_point / isolation_breach groups.
	isolationCtx *isolationContext
}

// isolationContext captures vantage-point details for an isolation check.
type isolationContext struct {
	fromZone         string
	toZone           string
	runnerInFrom     bool
	probeInFromZone  bool
	probeName        string
	policyName       string
	fromNetworkNames []string // all networks in the from zone
}

// GenerateRecommendations analyzes failures and produces prioritized, context-aware recommendations.
// It uses a two-pass approach:
//  1. classifyFailures: groups failures by root cause (vantage point, real breach, etc.)
//  2. generateFromGroups: produces one recommendation per group, with aggregated context.
func GenerateRecommendations(
	failures []models.CheckResult,
	spec *intent.Spec,
	runner models.RunnerContext,
) ([]Recommendation, error) {
	if len(failures) == 0 {
		return nil, nil
	}

	// Pass 1: classify
	groups := classifyFailures(failures, spec, runner)

	// Pass 2: generate
	recs := generateFromGroups(groups, spec, runner)

	// Cap recommendations so the output stays readable
	if len(recs) > 8 {
		recs = recs[:8]
	}

	return recs, nil
}

// classifyFailures groups failures by their root cause.
func classifyFailures(failures []models.CheckResult, spec *intent.Spec, runner models.RunnerContext) []failureGroup {
	// Initialize groups for each category
	groups := map[string]*failureGroup{
		"vantage_point":         {category: "vantage_point"},
		"isolation_breach":      {category: "isolation_breach"},
		"acl_not_enforced":      {category: "acl_not_enforced"},
		"network_unreachable":   {category: "network_unreachable"},
		"vpn_misconfigured":     {category: "vpn_misconfigured"},
		"discovery_count":       {category: "discovery_count"},
		"service_down":          {category: "service_down"},
		"dns_failure":           {category: "dns_failure"},
		"network_degraded":      {category: "network_degraded"},
		"host_down_or_filtered": {category: "host_down_or_filtered"},
	}

	for _, f := range failures {
		switch f.CheckType {
		case "isolation":
			classifyIsolation(f, groups, spec, runner)
		case "subnet_discovery":
			classifyDiscovery(f, groups, spec, runner)
		case "vpn_route":
			groups["vpn_misconfigured"].failures = append(groups["vpn_misconfigured"].failures, f)
		case "port_check":
			classifyServiceCheck(f, groups)
		case "dns_check":
			classifyDNSCheck(f, groups)
		case "network_health":
			classifyHealthCheck(f, groups)
		case "acl_check":
			groups["acl_not_enforced"].failures = append(groups["acl_not_enforced"].failures, f)
		}
	}

	// Collect non-empty groups
	var result []failureGroup
	for _, g := range groups {
		if len(g.failures) > 0 {
			result = append(result, *g)
		}
	}
	return result
}

// classifyIsolation determines if an isolation failure is a vantage-point issue
// or a real firewall breach.
func classifyIsolation(f models.CheckResult, groups map[string]*failureGroup, spec *intent.Spec, runner models.RunnerContext) {
	summary := strings.ToLower(f.Summary)
	violations := strings.Join(f.Violations, " ")

	// Extract from/to from the target or summary
	from, to := parseIsolationTarget(f.Target)
	if from == "" {
		// Try to extract from summary like "isolation violation: personal can reach gaming"
		from, to = parseIsolationFromSummary(summary)
	}

	// If we couldn't parse from/to, we can't do vantage-point analysis
	if from == "" {
		groups["isolation_breach"].failures = append(groups["isolation_breach"].failures, f)
		return
	}

	ctx := buildIsolationContext(from, to, spec, runner)

	// If the runner is NOT in the source zone, this is a vantage-point issue.
	// The check ran from the wrong place, so the result is meaningless.
	if ctx == nil || !ctx.runnerInFrom {
		g := groups["vantage_point"]
		g.failures = append(g.failures, f)
		if ctx != nil {
			g.isolationCtx = ctx
		}
		return
	}

	// Runner IS in the source zone — the check is valid.
	// If it's a FAIL with expected deny but traffic reachable, it's a real isolation breach.
	if f.Status == models.StatusFail && (strings.Contains(violations, "expected deny") || strings.Contains(summary, "isolation violation")) {
		groups["isolation_breach"].failures = append(groups["isolation_breach"].failures, f)
		if ctx != nil {
			groups["isolation_breach"].isolationCtx = ctx
		}
		return
	}

	// Connectivity failure when we expected reachability
	if f.Status == models.StatusFail && strings.Contains(summary, "connectivity failure") {
		groups["network_unreachable"].failures = append(groups["network_unreachable"].failures, f)
		return
	}

	// WARN (unverifiable / unconfirmed) — vantage point issue
	if f.Status == models.StatusWarn {
		groups["vantage_point"].failures = append(groups["vantage_point"].failures, f)
		if ctx != nil {
			groups["vantage_point"].isolationCtx = ctx
		}
	}
}

// buildIsolationContext determines vantage-point details for an isolation check.
func buildIsolationContext(from, to string, spec *intent.Spec, runner models.RunnerContext) *isolationContext {
	if spec == nil {
		return nil
	}

	ctx := &isolationContext{
		fromZone: from,
		toZone:   to,
	}

	// Find all networks in the "from" zone
	for _, n := range spec.Networks {
		if n.Zone == from || n.Name == from {
			ctx.fromNetworkNames = append(ctx.fromNetworkNames, n.Name)
		}
	}

	// Check if runner is in the source zone
	for _, netName := range runner.Networks {
		for _, n := range spec.Networks {
			if n.Name == netName && (n.Zone == from || n.Name == from) {
				ctx.runnerInFrom = true
				break
			}
		}
	}

	// Check if a probe is declared in the source zone
	for _, p := range spec.Probes {
		if p.VLAN == from {
			ctx.probeInFromZone = true
			ctx.probeName = p.Name
			break
		}
		// Also check if probe's host IP is within a network in the from zone
		if p.Host == "" {
			continue
		}
		for _, n := range spec.Networks {
			if n.Zone != from && n.Name != from {
				continue
			}
			if ipInCIDR(p.Host, n.CIDR) {
				ctx.probeInFromZone = true
				ctx.probeName = p.Name
				goto probeFound
			}
		}
	}
probeFound:

	// Find the matching policy
	for _, p := range spec.Policies {
		if (p.From == from || p.From == ctx.fromZone) && (p.To == to || p.To == ctx.toZone) {
			ctx.policyName = p.Name
			break
		}
	}

	return ctx
}

// classifyDiscovery handles subnet_discovery failures.
func classifyDiscovery(f models.CheckResult, groups map[string]*failureGroup, spec *intent.Spec, runner models.RunnerContext) {
	if f.Status == models.StatusError {
		summary := strings.ToLower(f.Summary)

		// Timeouts or unreachable errors from the wrong vantage point are
		// extremely common and should be treated as vantage-point issues
		// when the runner is clearly not in the target network.
		isTimeout := strings.Contains(summary, "timed out") || strings.Contains(summary, "deadline exceeded")
		if isTimeout || strings.Contains(summary, "unreachable") {
			if spec != nil && f.Target != "" && !runnerInNetwork(runner, f.Target, spec) {
				// Route to vantage_point so it can be aggregated with isolation failures
				// that have the same root cause.
				groups["vantage_point"].failures = append(groups["vantage_point"].failures, f)
				return
			}
		}

		// Fallback: treat as generic network reachability problem
		groups["network_unreachable"].failures = append(groups["network_unreachable"].failures, f)
		return
	}

	// Host count violations
	for _, v := range f.Violations {
		if strings.Contains(strings.ToLower(v), "expected max") ||
			strings.Contains(strings.ToLower(v), "expected min") {
			groups["discovery_count"].failures = append(groups["discovery_count"].failures, f)
			return
		}
	}

	// Zero hosts — could be network unreachable or just empty
	hostCount := 0
	if v, ok := f.Observed["total"]; ok {
		if n, ok := v.(float64); ok {
			hostCount = int(n)
		}
	}
	if hostCount == 0 && f.Status != models.StatusPass {
		// Check if runner is in the target network
		if !runnerInNetwork(runner, f.Target, spec) {
			groups["network_unreachable"].failures = append(groups["network_unreachable"].failures, f)
			return
		}
		groups["host_down_or_filtered"].failures = append(groups["host_down_or_filtered"].failures, f)
	}
}

// classifyServiceCheck handles port_check failures.
func classifyServiceCheck(f models.CheckResult, groups map[string]*failureGroup) {
	if f.Status == models.StatusError {
		groups["network_unreachable"].failures = append(groups["network_unreachable"].failures, f)
		return
	}
	groups["service_down"].failures = append(groups["service_down"].failures, f)
}

// classifyDNSCheck handles dns_check failures.
func classifyDNSCheck(f models.CheckResult, groups map[string]*failureGroup) {
	if f.Status == models.StatusError {
		groups["network_unreachable"].failures = append(groups["network_unreachable"].failures, f)
		return
	}
	groups["dns_failure"].failures = append(groups["dns_failure"].failures, f)
}

// classifyHealthCheck handles network_health failures.
func classifyHealthCheck(f models.CheckResult, groups map[string]*failureGroup) {
	if f.Status == models.StatusError {
		// Check failed at the network level
		groups["network_unreachable"].failures = append(groups["network_unreachable"].failures, f)
		return
	}
	// Host not responding or degraded
	groups["network_degraded"].failures = append(groups["network_degraded"].failures, f)
}

// runnerInNetwork checks if the runner's IPs place it inside the named network.
func runnerInNetwork(runner models.RunnerContext, networkName string, spec *intent.Spec) bool {
	if spec == nil {
		return false
	}
	net := spec.NetworkByName(networkName)
	if net == nil {
		return false
	}
	for _, n := range runner.Networks {
		if n == networkName {
			return true
		}
	}
	return false
}

// generateFromGroups produces one recommendation per failure group.
func generateFromGroups(groups []failureGroup, spec *intent.Spec, runner models.RunnerContext) []Recommendation {
	var recs []Recommendation
	priority := 1

	// Process groups in priority order
	priorityOrder := []string{
		"vantage_point",         // P1 — most common, most actionable
		"isolation_breach",      // P2 — real security issue
		"acl_not_enforced",      // P3 — controller missing deny rule
		"network_unreachable",   // P4 — infrastructure issue
		"vpn_misconfigured",     // P5
		"discovery_count",       // P6
		"dns_failure",           // P7 — DNS issues
		"service_down",          // P8 — port/service unreachable
		"network_degraded",      // P9 — latency/loss issues
		"host_down_or_filtered", // P10 — zero hosts discovered
	}

	for _, cat := range priorityOrder {
		for _, g := range groups {
			if g.category != cat {
				continue
			}
			switch cat {
			case "vantage_point":
				recs = append(recs, recommendVantagePoint(g, spec, runner, priority)...) //nolint:revive
			case "isolation_breach":
				recs = append(recs, recommendIsolationBreach(g, spec, runner, priority)...) //nolint:revive
			case "acl_not_enforced":
				recs = append(recs, recommendACLEnforcement(g, spec, runner, priority)...) //nolint:revive
			case "network_unreachable":
				recs = append(recs, recommendNetworkUnreachable(g, spec, runner, priority)...) //nolint:revive
			case "vpn_misconfigured":
				recs = append(recs, recommendVPN(g, spec, runner, priority)...) //nolint:revive
			case "discovery_count":
				recs = append(recs, recommendDiscovery(g, spec, runner, priority)...) //nolint:revive
			case "dns_failure":
				recs = append(recs, recommendDNSFailure(g, spec, runner, priority)...) //nolint:revive
			case "service_down":
				recs = append(recs, recommendServiceDown(g, spec, runner, priority)...) //nolint:revive
			case "network_degraded":
				recs = append(recs, recommendNetworkDegraded(g, spec, runner, priority)...) //nolint:revive
			case "host_down_or_filtered":
				recs = append(recs, recommendHostDown(g, spec, runner, priority)...) //nolint:revive
			}
			priority++
		}
	}

	return recs
}

// recommendVantagePoint generates recommendations when the runner is in the wrong
// network for the check — the #1 issue in real homelab runs.
// It now handles mixed failure types (isolation + discovery timeouts + dns/port errors)
// so they collapse into one high-signal recommendation with a clean SpecPatch.
func recommendVantagePoint(g failureGroup, spec *intent.Spec, runner models.RunnerContext, priority int) []Recommendation {
	// Collect needed zones from both isolation checks and discovery/network targets.
	neededZones := map[string]struct{}{}

	for _, f := range g.failures {
		// From isolation checks
		from, _ := parseIsolationTarget(f.Target)
		if from == "" {
			from, _ = parseIsolationFromSummary(strings.ToLower(f.Summary))
		}
		if from != "" {
			// Resolve network name to zone name if possible
			if spec != nil {
				if net := spec.NetworkByName(from); net != nil && net.Zone != "" {
					neededZones[net.Zone] = struct{}{}
				} else {
					neededZones[from] = struct{}{}
				}
			} else {
				neededZones[from] = struct{}{}
			}
			continue
		}

		// From discovery / other network-targeted checks (new for ERROR timeout cases)
		if f.Target != "" && spec != nil {
			if net := spec.NetworkByName(f.Target); net != nil && net.Zone != "" {
				neededZones[net.Zone] = struct{}{}
			} else if net != nil {
				neededZones[net.Name] = struct{}{}
			}
		}
	}

	if len(neededZones) == 0 {
		// Nothing actionable for vantage point advice
		return nil
	}

	var affected []string
	for _, f := range g.failures {
		affected = append(affected, f.Target)
	}
	affected = deduplicateStrings(affected)

	runnerLocation := "your current adapter"
	if len(runner.Networks) > 0 {
		runnerLocation = strings.Join(runner.Networks, ", ")
	}

	// Sort zones for deterministic output
	var descParts []string
	for zone := range neededZones {
		descParts = append(descParts, zone)
	}
	slices.Sort(descParts)

	// Warmer, more specific description
	desc := fmt.Sprintf("You're running from %s, which means I can't accurately test checks that need to originate from inside the %s zone(s).", runnerLocation, strings.Join(descParts, ", "))

	remediation := "Add probes inside the required zones and re-run the affected assertions with runner: <probe-name>."
	if len(neededZones) == 1 {
		remediation = fmt.Sprintf("Add a probe inside the %s zone and re-run the affected assertions with runner: <probe-name>.", descParts[0])
	}

	// Use isolationCtx if present for "probe already exists" hint
	var probeHint string
	if g.isolationCtx != nil && g.isolationCtx.probeInFromZone {
		probeHint = fmt.Sprintf("You already have a probe (%s) declared in that zone — just add 'runner: %s' to the failing assertions and I'll run them from there.", g.isolationCtx.probeName, g.isolationCtx.probeName)
	}
	if probeHint != "" {
		remediation = probeHint
	}

	rec := Recommendation{
		Priority:    priority,
		Category:    "vantage_point",
		Title:       "Checks ran from the wrong vantage point",
		Description: desc,
		Remediation: remediation,
		Affected:    affected,
	}

	// Generate SpecPatch with diff-style format
	if spec != nil {
		user := existingProbeUser(spec)
		var patchLines []string

		// Section 1: probes to add
		patchLines = append(patchLines, "# Add probes so I can run checks from the correct VLAN:")
		patchLines = append(patchLines, "# Under 'probes:' in your spec:")
		for _, zone := range descParts {
			net := networkForZone(spec, zone)
			if net == nil {
				net = spec.NetworkByName(zone)
			}
			host := "<ip-inside-" + zone + ">"
			if net != nil {
				host = net.Gateway
				if host == "" {
					host = "<ip-inside-" + zone + ">"
				}
			}
			patchLines = append(patchLines, "+  - name: "+zone+"-probe")
			patchLines = append(patchLines, "+    host: "+host)
			patchLines = append(patchLines, "+    user: "+user)
			patchLines = append(patchLines, "+    vlan: "+zone)
		}

		// Section 2: concrete runner example from first failing assertion
		if len(g.failures) > 0 {
			f := g.failures[0]
			patchLines = append(patchLines, "")
			patchLines = append(patchLines, "# Then add 'runner:' to the failing assertions, e.g.:")
			patchLines = append(patchLines, "   - type: "+f.CheckType)
			if f.Target != "" {
				patchLines = append(patchLines, "     target: "+f.Target)
			}
			patchLines = append(patchLines, "+    runner: "+descParts[0]+"-probe")
		}

		rec.SpecPatch = strings.Join(patchLines, "\n")
	}

	return []Recommendation{rec}
}

// recommendIsolationBreach generates recommendations for real firewall misconfigurations.
func recommendIsolationBreach(g failureGroup, spec *intent.Spec, _ models.RunnerContext, priority int) []Recommendation {
	var affected []string
	var descParts []string

	for _, f := range g.failures {
		affected = append(affected, f.Target)
		descParts = append(descParts, f.Summary)
	}
	affected = deduplicateStrings(affected)

	// Build policy-specific guidance
	var remediation string
	if g.isolationCtx != nil && g.isolationCtx.policyName != "" {
		from := g.isolationCtx.fromZone
		to := g.isolationCtx.toZone
		remediation = fmt.Sprintf("Your firewall should be blocking traffic from %s to %s, but it's not. "+
			"Add a deny rule for this flow and make sure it has higher priority than any allow rule. "+
			"Check policy %q in your controller — it may be missing or misconfigured.", from, to, g.isolationCtx.policyName)
	} else {
		remediation = "Your firewall should be blocking this traffic flow. " +
			"Add a deny rule for the source zone to the destination zone and ensure it has higher priority than any allow rule."
	}

	rec := Recommendation{
		Priority:    priority,
		Category:    "isolation_breach",
		Title:       "Isolation violation — traffic should be blocked",
		Description: fmt.Sprintf("Traffic that should be denied is flowing: %s.", strings.Join(descParts, "; ")),
		Remediation: remediation,
		Affected:    affected,
	}

	// Generate SpecPatch: suggest adding an acl_check assertion
	if spec != nil && g.isolationCtx != nil {
		from := g.isolationCtx.fromZone
		to := g.isolationCtx.toZone
		policyName := g.isolationCtx.policyName
		if policyName == "" {
			policyName = fmt.Sprintf("%s-to-%s-deny", from, to)
		}
		var patchLines []string
		patchLines = append(patchLines, "# Add ACL verification under 'assertions:' to confirm the rule exists:")
		patchLines = append(patchLines, "+  - type: acl_check")
		patchLines = append(patchLines, "+    provider: omada")
		patchLines = append(patchLines, "+    policy: "+policyName)
		patchLines = append(patchLines, "+    expect: enforced")
		if g.isolationCtx.probeName != "" {
			patchLines = append(patchLines, "+    runner: "+g.isolationCtx.probeName)
		}
		rec.SpecPatch = strings.Join(patchLines, "\n")
	}

	return []Recommendation{rec}
}

// recommendACLEnforcement generates recommendations when an ACL policy is not
// enforced on the Omada controller (or vice versa).
func recommendACLEnforcement(g failureGroup, spec *intent.Spec, _ models.RunnerContext, priority int) []Recommendation {
	var affected []string
	for _, f := range g.failures {
		affected = append(affected, f.Target)
	}
	affected = deduplicateStrings(affected)

	desc := fmt.Sprintf("Your Omada controller is missing ACL rules that should be in place. "+
		"Policies that should be enforced: %s.", strings.Join(affected, ", "))

	remediation := "Add the missing ACL rules in your Omada controller. " +
		"Navigate to Security > ACL Rules and create rules matching the policies in your spec. " +
		"Ensure the rules are enabled and have the correct source, destination, and action."

	rec := Recommendation{
		Priority:    priority,
		Category:    "acl_not_enforced",
		Title:       "ACL rules missing on controller",
		Description: desc,
		Remediation: remediation,
		Affected:    affected,
	}

	// Generate SpecPatch: suggest acl_check assertions for each missing policy
	if spec != nil && len(affected) > 0 {
		var patchLines []string
		patchLines = append(patchLines, "# Add acl_check assertions under 'assertions:' to verify enforcement:")
		for _, policyName := range affected {
			patchLines = append(patchLines, "+  - type: acl_check")
			patchLines = append(patchLines, "+    provider: omada")
			patchLines = append(patchLines, "+    policy: "+policyName)
			patchLines = append(patchLines, "+    expect: enforced")
			// If we know a probe is in the source zone, suggest it
			if g.isolationCtx != nil && g.isolationCtx.probeName != "" {
				patchLines = append(patchLines, "+    runner: "+g.isolationCtx.probeName)
			}
		}
		rec.SpecPatch = strings.Join(patchLines, "\n")
	}

	return []Recommendation{rec}
}

// recommendNetworkUnreachable generates recommendations when the target network
// isn't reachable from the runner's vantage point.
func recommendNetworkUnreachable(g failureGroup, spec *intent.Spec, runner models.RunnerContext, priority int) []Recommendation {
	var affected []string
	var checkTypes []string
	seen := map[string]bool{}

	for _, f := range g.failures {
		affected = append(affected, f.Target)
		if !seen[f.CheckType] {
			checkTypes = append(checkTypes, f.CheckType)
			seen[f.CheckType] = true
		}
	}
	affected = deduplicateStrings(affected)

	runnerLocation := "your current adapter"
	if len(runner.Networks) > 0 {
		runnerLocation = strings.Join(runner.Networks, ", ")
	}

	desc := fmt.Sprintf("I couldn't reach these targets from %s. The checks that failed: %s.", runnerLocation, strings.Join(checkTypes, ", "))

	remediation := "The target network may not be reachable from your current adapter. " +
		"Try --interface to scan from a different adapter, or add a probe inside the target network so I can reach it."

	rec := Recommendation{
		Priority:    priority,
		Category:    "network_unreachable",
		Title:       "Target network not reachable from current adapter",
		Description: desc,
		Remediation: remediation,
		Affected:    affected,
	}

	// Generate SpecPatch: suggest probes for unreachable networks + runner example
	if spec != nil && len(affected) > 0 {
		user := existingProbeUser(spec)
		var patchLines []string

		// Find networks for each affected target
		seenZones := map[string]bool{}
		for _, target := range affected {
			net := spec.NetworkByName(target)
			if net == nil {
				continue
			}
			zone := net.Zone
			if zone == "" {
				zone = net.Name
			}
			if seenZones[zone] {
				continue
			}
			seenZones[zone] = true

			host := net.Gateway
			if host == "" {
				host = "<ip-inside-" + zone + ">"
			}

			if len(patchLines) == 0 {
				patchLines = append(patchLines, "# Add probes for unreachable networks under 'probes:'")
			}
			patchLines = append(patchLines, "+  - name: "+zone+"-probe")
			patchLines = append(patchLines, "+    host: "+host)
			patchLines = append(patchLines, "+    user: "+user)
			patchLines = append(patchLines, "+    vlan: "+zone)
		}

		// Show runner example from first failing assertion
		if len(g.failures) > 0 && len(patchLines) > 0 {
			f := g.failures[0]
			patchLines = append(patchLines, "")
			patchLines = append(patchLines, "# Then add 'runner:' to the failing assertions, e.g.:")
			patchLines = append(patchLines, "   - type: "+f.CheckType)
			if f.Target != "" {
				patchLines = append(patchLines, "     target: "+f.Target)
			}
			for z := range seenZones {
				patchLines = append(patchLines, "+    runner: "+z+"-probe")
				break
			}
		}

		rec.SpecPatch = strings.Join(patchLines, "\n")
	}

	return []Recommendation{rec}
}

// recommendVPN generates recommendations for VPN routing failures.
func recommendVPN(g failureGroup, spec *intent.Spec, _ models.RunnerContext, priority int) []Recommendation {
	var affected []string
	for _, f := range g.failures {
		affected = append(affected, f.Target)
	}
	affected = deduplicateStrings(affected)

	if len(affected) == 0 {
		return nil
	}

	desc := fmt.Sprintf("Traffic is not routing through the expected VPN tunnel. Target: %s.", affected[0])

	// Try to find the VPN config for specific guidance
	var vpnName string
	for _, f := range g.failures {
		if v, ok := f.Expected["vpn"]; ok {
			if s, ok := v.(string); ok {
				vpnName = s
				break
			}
		}
	}

	var remediation string
	if vpnName != "" && spec != nil {
		vpn := spec.VPNByName(vpnName)
		if vpn != nil {
			remediation = fmt.Sprintf("Check that the %s VPN is active and its interface (%s) exists on this machine. "+
				"Verify that expected routes are pushed by the VPN server and that policy routing / split-tunnel config is correct.",
				vpnName, vpn.Interface)
		} else {
			remediation = fmt.Sprintf("Check that the %s VPN is active and its interface exists. "+
				"Verify that expected routes are pushed by the VPN server.", vpnName)
		}
	} else {
		remediation = "Check that the VPN is active and its interface exists on this machine. " +
			"Verify that expected routes are pushed by the VPN server and that policy routing / split-tunnel config is correct."
	}

	rec := Recommendation{
		Priority:    priority,
		Category:    "vpn_misconfigured",
		Title:       "Traffic not routing through expected VPN tunnel",
		Description: desc,
		Remediation: remediation,
		Affected:    affected,
	}

	// Generate SpecPatch: suggest updating VPN config or assertion
	if spec != nil && vpnName != "" {
		vpn := spec.VPNByName(vpnName)
		if vpn != nil {
			var patchLines []string
			patchLines = append(patchLines, "# Verify your VPN config under 'vpn:' — interface or routes may be wrong:")
			patchLines = append(patchLines, "   - name: "+vpn.Name)
			patchLines = append(patchLines, "     type: "+vpn.Type)
			if vpn.Interface != "" {
				patchLines = append(patchLines, "     interface: "+vpn.Interface+"  # <-- verify this exists")
			}
			if len(vpn.ExpectedRoutes) > 0 {
				patchLines = append(patchLines, "     expected_routes:")
				for _, r := range vpn.ExpectedRoutes {
					patchLines = append(patchLines, "       - "+r+"  # <-- verify these are pushed")
				}
			}
			patchLines = append(patchLines, "     mode: "+vpn.Mode)
			rec.SpecPatch = strings.Join(patchLines, "\n")
		}
	}

	return []Recommendation{rec}
}

// recommendDiscovery generates recommendations for host count violations.
func recommendDiscovery(g failureGroup, _ *intent.Spec, _ models.RunnerContext, priority int) []Recommendation {
	var recs []Recommendation

	for _, f := range g.failures {
		hostCount := 0
		if v, ok := f.Observed["total"]; ok {
			if n, ok := v.(float64); ok {
				hostCount = int(n)
			}
		}

		var title, remediation string
		var affected []string
		affected = append(affected, f.Target)
		affected = deduplicateStrings(affected)

		for _, v := range f.Violations {
			vLower := strings.ToLower(v)
			if strings.Contains(vLower, "expected max") {
				title = "More hosts discovered than expected"
				expectedMax := extractInt(f.Expected["expect_hosts_max"])
				remediation = fmt.Sprintf("Found %d hosts but expected max %d. "+
					"If this is expected growth, bump expect_hosts_max in your spec. "+
					"Otherwise, investigate what unknown devices are on the network.",
					hostCount, expectedMax)

				var patchLines []string
				patchLines = append(patchLines, "# Update subnet_discovery for "+f.Target+" under 'assertions':")
				patchLines = append(patchLines, "-    expect_hosts_max: "+fmt.Sprintf("%d", expectedMax))
				patchLines = append(patchLines, "+    expect_hosts_max: "+fmt.Sprintf("%d  # bumped; observed %d hosts + 5 buffer", hostCount+5, hostCount))

				rec := Recommendation{
					Priority:    priority,
					Category:    "discovery_count",
					Title:       title,
					Description: f.Summary,
					Remediation: remediation,
					Affected:    affected,
					SpecPatch:   strings.Join(patchLines, "\n"),
				}
				recs = append(recs, rec)
				priority++
			}

			if strings.Contains(vLower, "expected min") {
				title = "Fewer hosts discovered than expected"
				expectedMin := extractInt(f.Expected["expect_hosts_min"])
				remediation = fmt.Sprintf("Found %d hosts but expected at least %d. "+
					"Some devices may be offline, or hosts are sleeping/filtering ARP and ICMP. "+
					"Verify you can reach this network from your adapter — try --interface to test from a different one.",
					hostCount, expectedMin)

				var patchLines []string
				patchLines = append(patchLines, "# Update subnet_discovery for "+f.Target+" under 'assertions':")
				patchLines = append(patchLines, "-    expect_hosts_min: "+fmt.Sprintf("%d", expectedMin))
				newMin := hostCount + 1
				if newMin < 1 {
					newMin = 1
				}
				patchLines = append(patchLines, "+    expect_hosts_min: "+fmt.Sprintf("%d  # lowered; observed only %d host(s)", newMin, hostCount))

				rec := Recommendation{
					Priority:    priority,
					Category:    "discovery_count",
					Title:       title,
					Description: f.Summary,
					Remediation: remediation,
					Affected:    affected,
					SpecPatch:   strings.Join(patchLines, "\n"),
				}
				recs = append(recs, rec)
				priority++
			}
		}
	}

	return recs
}

// recommendHostDown generates recommendations for port/dns/health failures.
func recommendHostDown(g failureGroup, spec *intent.Spec, runner models.RunnerContext, priority int) []Recommendation {
	var affected []string
	for _, f := range g.failures {
		affected = append(affected, f.Target)
	}
	affected = deduplicateStrings(affected)

	runnerLocation := "your current adapter"
	if len(runner.Networks) > 0 {
		runnerLocation = strings.Join(runner.Networks, ", ")
	}

	desc := fmt.Sprintf("These targets aren't responding from %s: %s.", runnerLocation, strings.Join(affected, ", "))

	remediation := "The host may be down, or a firewall is blocking the check. " +
		"Verify the target IP is correct and the service is running. " +
		"If the target is on a different VLAN, try --interface or add a probe in that network."

	rec := Recommendation{
		Priority:    priority,
		Category:    "host_down_or_filtered",
		Title:       "Target not responding",
		Description: desc,
		Remediation: remediation,
		Affected:    affected,
	}

	// Generate SpecPatch: suggest lowering expect_hosts_min for affected networks
	if spec != nil && len(affected) > 0 {
		var patchLines []string
		for _, target := range affected {
			a := lookupAssertion(spec, target, "", "subnet_discovery")
			if a == nil {
				continue
			}
			oldMin := 0
			if a.ExpectHostsMin != nil {
				oldMin = *a.ExpectHostsMin
			}
			patchLines = append(patchLines, "# Update subnet_discovery for "+target+" under 'assertions':")
			patchLines = append(patchLines, "-    expect_hosts_min: "+fmt.Sprintf("%d", oldMin))
			patchLines = append(patchLines, "+    expect_hosts_min: 1  # hosts may be down or filtering; set floor to 1")
		}
		if len(patchLines) > 0 {
			rec.SpecPatch = strings.Join(patchLines, "\n")
		}
	}

	return []Recommendation{rec}
}

// recommendDNSFailure generates recommendations for DNS resolution failures.
func recommendDNSFailure(g failureGroup, spec *intent.Spec, runner models.RunnerContext, priority int) []Recommendation {
	var affected []string
	for _, f := range g.failures {
		affected = append(affected, f.Target)
	}
	affected = deduplicateStrings(affected)

	runnerLocation := "your current adapter"
	if len(runner.Networks) > 0 {
		runnerLocation = strings.Join(runner.Networks, ", ")
	}

	desc := fmt.Sprintf("DNS queries aren't resolving correctly from %s. Affected: %s.", runnerLocation, strings.Join(affected, ", "))

	remediation := "The DNS server may be unreachable, or the expected IP is wrong. " +
		"Verify the DNS server address in your spec, and that it's reachable from your adapter. " +
		"If the query resolved to a different IP, check for stale DNS records or split-horizon DNS issues."

	rec := Recommendation{
		Priority:    priority,
		Category:    "dns_failure",
		Title:       "DNS resolution failure",
		Description: desc,
		Remediation: remediation,
		Affected:    affected,
	}

	// Generate SpecPatch: suggest updating expect_ip with observed IP
	if spec != nil && len(g.failures) > 0 {
		var patchLines []string
		for _, f := range g.failures {
			if f.Observed["resolved_ip"] == nil {
				continue
			}
			observedIP, _ := f.Observed["resolved_ip"].(string)
			if observedIP == "" {
				continue
			}
			oldIP, _ := f.Expected["expect_ip"].(string)
			patchLines = append(patchLines, "# Update dns_check for "+f.Target+" under 'assertions':")
			patchLines = append(patchLines, "-    expect_ip: "+oldIP)
			patchLines = append(patchLines, "+    expect_ip: "+observedIP+"  # observed resolved IP")
		}
		if len(patchLines) > 0 {
			rec.SpecPatch = strings.Join(patchLines, "\n")
		}
	}

	return []Recommendation{rec}
}

// recommendServiceDown generates recommendations for port/service check failures.
func recommendServiceDown(g failureGroup, spec *intent.Spec, runner models.RunnerContext, priority int) []Recommendation {
	var affected []string
	for _, f := range g.failures {
		affected = append(affected, f.Target)
	}
	affected = deduplicateStrings(affected)

	runnerLocation := "your current adapter"
	if len(runner.Networks) > 0 {
		runnerLocation = strings.Join(runner.Networks, ", ")
	}

	desc := fmt.Sprintf("Expected services aren't responding on these hosts from %s: %s.", runnerLocation, strings.Join(affected, ", "))

	remediation := "The service may be down, or a firewall is blocking the port. " +
		"Verify the target is up and the service is listening on the expected port. " +
		"If the target is on a different VLAN, try --interface or add a probe in that network."

	rec := Recommendation{
		Priority:    priority,
		Category:    "service_down",
		Title:       "Service not responding on expected port",
		Description: desc,
		Remediation: remediation,
		Affected:    affected,
	}

	// Generate SpecPatch: suggest updating expect from open to closed
	if spec != nil && len(g.failures) > 0 {
		var patchLines []string
		for _, f := range g.failures {
			ports := ""
			if f.Observed["ports"] != nil {
				if p, ok := f.Observed["ports"].(string); ok {
					ports = p
				}
			}
			patchLines = append(patchLines, "# Update port_check for "+f.Target+" under 'assertions':")
			patchLines = append(patchLines, "-    expect: open")
			if ports != "" {
				patchLines = append(patchLines, "+    expect: closed  # port(s) "+ports+" observed as closed; service may be decommissioned")
			} else {
				patchLines = append(patchLines, "+    expect: closed  # service not responding; may have been decommissioned")
			}
		}
		rec.SpecPatch = strings.Join(patchLines, "\n")
	}

	return []Recommendation{rec}
}

// recommendNetworkDegraded generates recommendations for network health failures.
func recommendNetworkDegraded(g failureGroup, spec *intent.Spec, runner models.RunnerContext, priority int) []Recommendation {
	var affected []string
	for _, f := range g.failures {
		affected = append(affected, f.Target)
	}
	affected = deduplicateStrings(affected)

	runnerLocation := "your current adapter"
	if len(runner.Networks) > 0 {
		runnerLocation = strings.Join(runner.Networks, ", ")
	}

	desc := fmt.Sprintf("These hosts are degraded or unreachable from %s: %s.", runnerLocation, strings.Join(affected, ", "))

	remediation := "The host may be slow, experiencing packet loss, or filtering ICMP. " +
		"Verify the target is up and that your adapter can reach it. " +
		"Try --interface to test from a different adapter, or add a probe closer to the target."

	rec := Recommendation{
		Priority:    priority,
		Category:    "network_degraded",
		Title:       "Network health degraded",
		Description: desc,
		Remediation: remediation,
		Affected:    affected,
	}

	// Generate SpecPatch: suggest adjusting thresholds based on observed values
	if spec != nil && len(g.failures) > 0 {
		var patchLines []string
		for _, f := range g.failures {
			obsLatency := extractInt(f.Observed["latency_ms"])
			obsLoss := extractInt(f.Observed["loss_pct"])
			oldLatency := extractInt(f.Expected["expect_latency_ms"])
			oldLoss := extractInt(f.Expected["expect_loss_pct"])
			newLatency := obsLatency + (obsLatency / 3)
			if newLatency < oldLatency {
				newLatency = oldLatency
			}
			patchLines = append(patchLines, "# Adjust network_health thresholds for "+f.Target+" under 'assertions':")
			if oldLatency > 0 {
				patchLines = append(patchLines, "-    expect_latency_ms: "+fmt.Sprintf("%d", oldLatency))
				patchLines = append(patchLines, "+    expect_latency_ms: "+fmt.Sprintf("%d  # adjusted; observed %dms", newLatency, obsLatency))
			}
			if oldLoss >= 0 {
				patchLines = append(patchLines, "-    expect_loss_pct: "+fmt.Sprintf("%d", oldLoss))
				newLoss := obsLoss + 1
				if newLoss < 1 {
					newLoss = 1
				}
				patchLines = append(patchLines, "+    expect_loss_pct: "+fmt.Sprintf("%d  # adjusted; observed %d%% loss", newLoss, obsLoss))
			}
		}
		rec.SpecPatch = strings.Join(patchLines, "\n")
	}

	return []Recommendation{rec}
}

// extractInt safely extracts an integer from an interface{} value,
// handling both int and float64 (which YAML parsers commonly use).
func extractInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int32:
		return int(n)
	case int64:
		return int(n)
	case float64:
		return int(n)
	case float32:
		return int(n)
	default:
		return 0
	}
}

// ipInCIDR checks if an IP address (or hostname that resolves to an IP) falls
// within the given CIDR block.
func ipInCIDR(ipOrHost, cidr string) bool {
	if cidr == "" {
		return false
	}
	ip := net.ParseIP(ipOrHost)
	if ip == nil {
		// Try to resolve hostname
		addrs, err := net.LookupIP(ipOrHost)
		if err != nil || len(addrs) == 0 {
			return false
		}
		ip = addrs[0]
	}
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return ipnet.Contains(ip)
}

// lookupAssertion finds an existing assertion matching the given network/target and type.
func lookupAssertion(spec *intent.Spec, network, target, checkType string) *intent.Assertion {
	if spec == nil {
		return nil
	}
	for i := range spec.Assertions {
		a := &spec.Assertions[i]
		if a.Type != checkType {
			continue
		}
		if network != "" && a.Network == network {
			return a
		}
		if target != "" && a.Target == target {
			return a
		}
	}
	return nil
}

// existingProbeUser returns the user field from the first declared probe, or "<user>" if none.
func existingProbeUser(spec *intent.Spec) string {
	if spec == nil {
		return "<user>"
	}
	for _, p := range spec.Probes {
		if p.User != "" {
			return p.User
		}
	}
	return "<user>"
}

// networkForZone returns the first network whose zone matches, or nil.
func networkForZone(spec *intent.Spec, zone string) *intent.Network {
	if spec == nil {
		return nil
	}
	for i := range spec.Networks {
		if spec.Networks[i].Zone == zone {
			return &spec.Networks[i]
		}
	}
	return nil
}

// deduplicateStrings returns unique values in first-seen order.
func deduplicateStrings(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

// parseIsolationTarget extracts from/to from an isolation check target like "personal -> gaming".
func parseIsolationTarget(target string) (from, to string) {
	parts := strings.Split(target, " -> ")
	if len(parts) == 2 {
		return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	}
	return "", ""
}

// parseIsolationFromSummary extracts from/to from a summary like "isolation violation: personal can reach gaming".
func parseIsolationFromSummary(summary string) (from, to string) {
	// Pattern: "... personal can reach gaming"
	idx := strings.Index(summary, "can reach")
	if idx < 0 {
		idx = strings.Index(summary, "cannot reach")
	}
	if idx < 0 {
		return "", ""
	}

	// Find the word before "can reach"
	before := strings.TrimSpace(summary[:idx])
	after := strings.TrimSpace(summary[idx+len("can reach"):])

	// The "from" is typically the last word or phrase before "can reach"
	// Look for "expected deny" or "isolation violation" markers
	for _, marker := range []string{"isolation violation:", "expected deny", "isolation confirmed:", "connectivity confirmed:"} {
		if mIdx := strings.Index(before, marker); mIdx >= 0 {
			before = strings.TrimSpace(before[mIdx+len(marker):])
			break
		}
	}

	return before, after
}
