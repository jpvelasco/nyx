package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/velasco-jp/nyx/internal/backends/dns"
	"github.com/velasco-jp/nyx/internal/backends/health"
	"github.com/velasco-jp/nyx/internal/backends/nmap"
	"github.com/velasco-jp/nyx/internal/backends/omada"
	"github.com/velasco-jp/nyx/internal/backends/system"
	"github.com/velasco-jp/nyx/internal/intent"
	"github.com/velasco-jp/nyx/internal/models"
	"github.com/velasco-jp/nyx/internal/probe"
)

const (
	// assertionTimeoutDiscovery is the per-assertion timeout for nmap subnet scans.
	assertionTimeoutDiscovery = 90 * time.Second
	// assertionTimeoutDefault is the per-assertion timeout for all other checks.
	assertionTimeoutDefault = 30 * time.Second
)

// Engine runs audit assertions
type Engine struct {
	Spec      *intent.Spec
	runnerCtx models.RunnerContext // populated once at Run() time

	// Interface, if set, restricts local IP detection and some checks to this specific network interface.
	// Empty means "use all active interfaces" (current default behavior).
	Interface string
}

// NewEngine creates an audit engine for a spec
func NewEngine(spec *intent.Spec) *Engine {
	return &Engine{Spec: spec}
}

// Run executes all assertions concurrently and returns a report.
// Results are returned in the same order as the assertions in the spec.
func (e *Engine) Run(ctx context.Context) (*models.AuditReport, error) {
	e.runnerCtx = localRunnerContext(e.Spec, e.Interface)

	// Warn the user if we can't place them in any spec network (noob-friendly)
	if e.Interface == "" && len(e.runnerCtx.Networks) == 0 && len(e.Spec.Networks) > 0 {
		fmt.Fprintf(os.Stderr, "warning: I couldn't place your current network inside any spec network.\n")
		fmt.Fprintf(os.Stderr, "         You're likely multi-homed. Use --interface to pick which adapter to scan from.\n")
		fmt.Fprintf(os.Stderr, "         (Run 'nyx interfaces' to see the list.)\n")
	}

	assertions := e.Spec.Assertions
	findings := make([]models.CheckResult, len(assertions))

	var wg sync.WaitGroup
	wg.Add(len(assertions))

	for i, assertion := range assertions {
		i, assertion := i, assertion // capture loop vars
		go func() {
			defer wg.Done()
			result, err := e.runAssertion(ctx, assertion)
			if err != nil {
				target := assertion.Target
				if target == "" {
					target = assertion.Network
				}
				if target == "" {
					target = assertion.From
				}
				errResult := models.NewCheckResult("audit", assertion.Type, "local", target)
				errResult.Status = models.StatusError

				// Produce a clearer user-facing explanation instead of raw Go error
				summary, details := explainAssertionError(assertion, err)
				errResult.Summary = summary
				for _, d := range details {
					errResult.Violations = append(errResult.Violations, d)
				}
				errResult.Observed["raw_error"] = err.Error() // keep raw for advanced users / debugging
				errResult.Finish()
				findings[i] = *errResult
				return
			}
			findings[i] = *result
		}()
	}

	wg.Wait()

	report := &models.AuditReport{
		Audit:    e.Spec.Site,
		Status:   models.ComputeOverallStatus(findings),
		Summary:  models.Tally(findings),
		Runner:   e.runnerCtx,
		Findings: findings,
	}
	return report, nil
}

// localRunnerContext detects which of the spec networks this machine is inside.
// If interfaceName is non-empty, only addresses on that specific interface are considered.
func localRunnerContext(spec *intent.Spec, interfaceName string) models.RunnerContext {
	ifaces, err := net.Interfaces()
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not enumerate network interfaces: %v\n", err)
		return models.RunnerContext{}
	}

	var localIPs []net.IP
	var localIPStrs []string

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if interfaceName != "" && iface.Name != interfaceName {
			continue // expert mode: only use the chosen interface
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() || ip.To4() == nil {
				continue
			}
			localIPs = append(localIPs, ip)
			localIPStrs = append(localIPStrs, ip.String())
		}
	}

	var matchedNetworks []string
	for _, n := range spec.Networks {
		_, cidr, err := net.ParseCIDR(n.CIDR)
		if err != nil {
			continue
		}
		for _, ip := range localIPs {
			if cidr.Contains(ip) {
				matchedNetworks = append(matchedNetworks, n.Name)
				break
			}
		}
	}

	// Smart default for multi-homed machines (noob-friendly)
	// When no interface was forced, try to pick the "best" one (the one that matches the most spec networks).
	if interfaceName == "" && len(ifaces) > 1 && len(spec.Networks) > 0 {
		bestIface := pickBestInterface(ifaces, spec)
		if bestIface != "" {
			// Recompute using only the best interface
			return localRunnerContext(spec, bestIface)
		}
		// Still ambiguous → warn the user
		fmt.Fprintf(os.Stderr, "warning: multiple network interfaces, no clear winner for your spec.\n")
		fmt.Fprintf(os.Stderr, "         Use --interface to pick one. (Run 'nyx interfaces' to see the list.)\n")
	}

	return models.RunnerContext{
		LocalIPs: localIPStrs,
		Networks: matchedNetworks,
	}
}

// pickBestInterface tries to find the interface that can reach the most networks in the spec.
// Returns the interface name, or empty if there's no clear winner.
func pickBestInterface(ifaces []net.Interface, spec *intent.Spec) string {
	type score struct {
		name  string
		count int
	}
	var scores []score

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		var ifaceIPs []net.IP
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.To4() != nil {
				ifaceIPs = append(ifaceIPs, ipnet.IP)
			}
		}

		matches := 0
		for _, n := range spec.Networks {
			_, cidr, err := net.ParseCIDR(n.CIDR)
			if err != nil {
				continue
			}
			for _, ip := range ifaceIPs {
				if cidr.Contains(ip) {
					matches++
					break
				}
			}
		}

		if matches > 0 {
			scores = append(scores, score{name: iface.Name, count: matches})
		}
	}

	if len(scores) == 0 {
		return ""
	}

	// Find the highest score
	max := 0
	for _, s := range scores {
		if s.count > max {
			max = s.count
		}
	}

	// Count how many have the max score
	winners := 0
	var winnerName string
	for _, s := range scores {
		if s.count == max {
			winners++
			winnerName = s.name
		}
	}

	if winners == 1 {
		return winnerName // clear winner
	}
	return "" // tie or ambiguous
}

func (e *Engine) runAssertion(ctx context.Context, a intent.Assertion) (*models.CheckResult, error) {
	// Dispatch to probe if runner is set
	if a.Runner != "" && a.Runner != "local" {
		return e.runViaProbe(ctx, a)
	}

	// Give each assertion its own deadline so a single slow check
	// (e.g. a large nmap sweep) cannot starve the rest of the audit.
	timeout := assertionTimeoutDefault
	if a.Type == "subnet_discovery" {
		timeout = assertionTimeoutDiscovery
	}
	assertCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	switch a.Type {
	case "subnet_discovery":
		return e.runDiscovery(assertCtx, a)
	case "isolation":
		return e.runIsolation(assertCtx, a)
	case "vpn_route":
		return e.runVPNRoute(assertCtx, a)
	case "route_check":
		return e.runRouteCheck(assertCtx, a)
	case "port_check":
		return e.runPortCheck(assertCtx, a)
	case "dns_check":
		return e.runDNSCheck(assertCtx, a)
	case "network_health":
		return e.runNetworkHealth(assertCtx, a)
	case "acl_check":
		return e.runACLCheck(assertCtx, a)
	default:
		return nil, fmt.Errorf("unknown assertion type: %s", a.Type)
	}
}

func (e *Engine) runDiscovery(ctx context.Context, a intent.Assertion) (*models.CheckResult, error) {
	net := e.Spec.NetworkByName(a.Network)
	if net == nil {
		return nil, fmt.Errorf("network %q not found in spec", a.Network)
	}

	// Build scan options — default to polite scan mode, use assertion overrides if set.
	opts := nmap.ScanOptionsForMode(nmap.ScanModePolite)
	if a.ScanMode != "" {
		opts = nmap.ScanOptionsForMode(nmap.ScanMode(a.ScanMode))
	}
	if a.ScanTiming > 0 {
		opts.TimingTemplate = a.ScanTiming
	}
	if a.ScanMinRate > 0 {
		opts.MinRate = a.ScanMinRate
	}

	result, err := nmap.DiscoverWithOptions(ctx, net.CIDR, opts)
	if err != nil {
		return nil, fmt.Errorf("nmap discovery failed: %w", err)
	}

	// Populate expected bounds in result metadata before evaluating
	if a.ExpectHostsMin != nil {
		result.Expected["expect_hosts_min"] = *a.ExpectHostsMin
	}
	if a.ExpectHostsMax != nil {
		result.Expected["expect_hosts_max"] = *a.ExpectHostsMax
	}

	// Evaluate host count assertions.
	// The nmap backend serializes DiscoveryResult into Observed, where
	// "total" is the host count (JSON number → float64 after marshal/unmarshal).
	hostCount := 0
	if v, ok := result.Observed["total"]; ok {
		// JSON unmarshal always produces float64 for numbers
		if n, ok := v.(float64); ok {
			hostCount = int(n)
		}
	}

	if a.ExpectHostsMax != nil && hostCount > *a.ExpectHostsMax {
		result.Status = models.StatusFail
		result.Violations = append(result.Violations,
			fmt.Sprintf("found %d hosts, expected max %d", hostCount, *a.ExpectHostsMax))
	}
	if a.ExpectHostsMin != nil && hostCount < *a.ExpectHostsMin {
		result.Status = models.StatusFail
		result.Violations = append(result.Violations,
			fmt.Sprintf("found %d hosts, expected min %d", hostCount, *a.ExpectHostsMin))
	}

	if result.Status == "" || (len(result.Violations) == 0 &&
		result.Status != models.StatusError &&
		result.Status != models.StatusWarn) {
		result.Status = models.StatusPass
	}
	result.Summary = fmt.Sprintf("%d hosts discovered in %s", hostCount, net.CIDR)
	return result, nil
}

func (e *Engine) runIsolation(ctx context.Context, a intent.Assertion) (*models.CheckResult, error) {
	result := models.NewCheckResult("system", "isolation", "local", fmt.Sprintf("%s -> %s", a.From, a.To))

	// Find target networks by zone name
	toNets := e.Spec.NetworkByZone(a.To)
	if len(toNets) == 0 {
		// Try treating it as a network name
		if net := e.Spec.NetworkByName(a.To); net != nil {
			toNets = []intent.Network{*net}
		}
	}

	if len(toNets) == 0 {
		result.Status = models.StatusError
		result.Summary = fmt.Sprintf("could not resolve target %q to any network", a.To)
		result.Finish()
		return result, nil
	}

	// For each target network, ping the gateway to check reachability
	allBlocked := true
	anyTested := false
	for _, targetNet := range toNets {
		if targetNet.Gateway == "" {
			continue
		}
		pingResult, err := system.Ping(ctx, targetNet.Gateway)
		if err != nil {
			result.Evidence = append(result.Evidence, fmt.Sprintf("ping to %s failed: %v", targetNet.Gateway, err))
			continue
		}
		anyTested = true
		if pingResult.Reachable {
			allBlocked = false
			result.Evidence = append(result.Evidence, fmt.Sprintf("gateway %s is reachable", targetNet.Gateway))
		} else {
			result.Evidence = append(result.Evidence, fmt.Sprintf("gateway %s is not reachable", targetNet.Gateway))
		}
	}

	// Check if nyx is running from within the source zone. Isolation checks are
	// only definitive when the runner is actually in the "from" network.
	runnerInFromZone := false
	for _, netName := range e.runnerCtx.Networks {
		n := e.Spec.NetworkByName(netName)
		if n != nil && (n.Zone == a.From || n.Name == a.From) {
			runnerInFromZone = true
			break
		}
	}

	expectDeny := a.ExpectDeny == "deny"
	if expectDeny {
		if !anyTested {
			result.Status = models.StatusWarn
			result.Summary = fmt.Sprintf(
				"isolation unverifiable: %s → %s (target zone not routable from this host; use runner: <probe> from inside the %s zone)",
				a.From, a.To, a.From,
			)
		} else if allBlocked && !runnerInFromZone {
			// Unreachable could mean isolation OR just no route from this host.
			result.Status = models.StatusWarn
			result.Summary = fmt.Sprintf(
				"isolation unconfirmed: %s → %s gateways unreachable, but nyx is not running from inside the %s zone — use runner: <probe> for a definitive check",
				a.From, a.To, a.From,
			)
		} else if allBlocked {
			result.Status = models.StatusPass
			result.Summary = fmt.Sprintf("isolation confirmed: %s cannot reach %s", a.From, a.To)
		} else {
			result.Status = models.StatusFail
			result.Summary = fmt.Sprintf("isolation violation: %s can reach %s", a.From, a.To)
			result.Violations = append(result.Violations, "expected deny but traffic is reachable")
		}
	} else {
		if !anyTested {
			result.Status = models.StatusWarn
			result.Summary = fmt.Sprintf(
				"connectivity unverifiable: %s → %s (target zone not routable from this host)",
				a.From, a.To,
			)
		} else if !allBlocked {
			result.Status = models.StatusPass
			result.Summary = fmt.Sprintf("connectivity confirmed: %s can reach %s", a.From, a.To)
		} else {
			result.Status = models.StatusFail
			result.Summary = fmt.Sprintf("connectivity failure: %s cannot reach %s", a.From, a.To)
		}
	}

	result.Finish()
	return result, nil
}

func (e *Engine) runVPNRoute(ctx context.Context, a intent.Assertion) (*models.CheckResult, error) {
	vpn := e.Spec.VPNByName(a.VPN)
	if vpn == nil {
		return nil, fmt.Errorf("vpn %q not found in spec", a.VPN)
	}

	result := models.NewCheckResult("system", "vpn_route", "local", a.Target)
	result.Expected["vpn"] = vpn.Name
	result.Expected["target"] = a.Target

	// Check route to target
	route, err := system.GetRouteToTarget(ctx, a.Target)
	if err != nil {
		result.Status = models.StatusError
		result.Summary = fmt.Sprintf("failed to get route to %s: %v", a.Target, err)
		result.Finish()
		return result, nil
	}

	result.Observed["device"] = route.Device
	result.Observed["gateway"] = route.Gateway

	// Determine expected interface name from vpn config
	expectedIface := vpn.Interface
	if expectedIface == "" {
		// Default WireGuard interface naming
		if vpn.Type == "wireguard" {
			expectedIface = "wg0"
		}
	}

	viaTunnel := false
	if expectedIface != "" && route.Device == expectedIface {
		viaTunnel = true
	}
	// Also check if the device looks like a VPN interface
	if !viaTunnel {
		isVPN, _ := system.CheckVPNInterface(ctx, route.Device)
		viaTunnel = isVPN
	}

	if a.ExpectTunnel != nil && *a.ExpectTunnel {
		if viaTunnel {
			result.Status = models.StatusPass
			result.Summary = fmt.Sprintf("%s routed via %s (tunnel)", a.Target, route.Device)
		} else {
			result.Status = models.StatusFail
			result.Summary = fmt.Sprintf("%s routed via %s (not tunnel)", a.Target, route.Device)
			result.Violations = append(result.Violations,
				fmt.Sprintf("expected tunnel route, got device %s", route.Device))
		}
	} else {
		result.Status = models.StatusPass
		result.Summary = fmt.Sprintf("%s routed via %s", a.Target, route.Device)
	}

	result.Finish()
	return result, nil
}

func (e *Engine) runRouteCheck(ctx context.Context, a intent.Assertion) (*models.CheckResult, error) {
	result := models.NewCheckResult("system", "route_check", "local", a.Target)

	route, err := system.GetRouteToTarget(ctx, a.Target)
	if err != nil {
		result.Status = models.StatusError
		result.Summary = fmt.Sprintf("failed to get route: %v", err)
		result.Finish()
		return result, nil
	}

	result.Observed["gateway"] = route.Gateway
	result.Observed["device"] = route.Device
	result.Status = models.StatusPass
	result.Summary = fmt.Sprintf("route to %s via %s dev %s", a.Target, route.Gateway, route.Device)
	result.Finish()
	return result, nil
}

func (e *Engine) runPortCheck(ctx context.Context, a intent.Assertion) (*models.CheckResult, error) {
	protocol := a.Protocol
	if protocol == "" {
		protocol = "tcp"
	}
	scanMode := nmap.ScanMode(a.ScanMode)
	if a.ScanMode == "" {
		scanMode = nmap.ScanModePolite
	}
	opts := nmap.ScanOptionsForMode(scanMode)

	result, err := nmap.PortScan(ctx, a.Target, a.Ports, protocol, opts)
	if err != nil {
		return nil, fmt.Errorf("port scan failed: %w", err)
	}

	// Evaluate pass/fail: all ports must match expect
	expect := a.ExpectDeny // "open" or "closed"
	var violations []string
	if portData, ok := result.Observed["ports"]; ok {
		if ports, ok := portData.([]interface{}); ok {
			for _, p := range ports {
				if pm, ok := p.(map[string]interface{}); ok {
					state, _ := pm["state"].(string)
					port, _ := pm["port"].(float64)
					if state != expect {
						violations = append(violations, fmt.Sprintf("port %.0f: expected %s, got %s", port, expect, state))
					}
				}
			}
		}
	}
	if len(violations) > 0 {
		result.Status = models.StatusFail
		result.Violations = violations
		result.Summary = fmt.Sprintf("port check failed on %s: %s", a.Target, strings.Join(violations, "; "))
	}
	result.Expected["expect"] = expect
	return result, nil
}

func (e *Engine) runDNSCheck(ctx context.Context, a intent.Assertion) (*models.CheckResult, error) {
	var result *models.CheckResult
	var err error

	if a.ExpectIP != "" {
		result, err = dns.ResolveExpect(ctx, a.Query, a.Server, a.ExpectIP)
	} else {
		result, err = dns.Resolve(ctx, a.Query, a.Server)
	}
	if err != nil {
		return nil, fmt.Errorf("dns check failed: %w", err)
	}

	if a.DNSSEC {
		dnssecResult, dnssecErr := dns.CheckDNSSEC(ctx, a.Query, a.Server)
		if dnssecErr != nil {
			result.Evidence = append(result.Evidence, fmt.Sprintf("DNSSEC check error: %v", dnssecErr))
		} else {
			result.Evidence = append(result.Evidence, dnssecResult.Evidence...)
			if dnssecResult.Status == models.StatusFail && result.Status == models.StatusPass {
				result.Status = models.StatusFail
				result.Violations = append(result.Violations, dnssecResult.Summary)
			}
		}
	}

	return result, nil
}

func (e *Engine) runNetworkHealth(ctx context.Context, a intent.Assertion) (*models.CheckResult, error) {
	var result *models.CheckResult
	var err error

	if a.ExpectLatencyMs > 0 || a.ExpectLossPct > 0 {
		result, err = health.CheckLatencyAndLoss(ctx, a.Target, a.ExpectLatencyMs, a.ExpectLossPct)
	} else {
		result, _, err = health.PingCheck(ctx, a.Target, 10)
	}
	if err != nil {
		return nil, fmt.Errorf("network health check failed: %w", err)
	}

	if a.ExpectMTU > 0 {
		mtuResult, mtuErr := health.ProbeMTU(ctx, a.Target, a.ExpectMTU)
		if mtuErr != nil {
			result.Evidence = append(result.Evidence, fmt.Sprintf("MTU probe error: %v", mtuErr))
		} else {
			result.Evidence = append(result.Evidence, mtuResult.Evidence...)
			if mtuResult.Status == models.StatusFail && result.Status == models.StatusPass {
				result.Status = models.StatusFail
				result.Violations = append(result.Violations, mtuResult.Summary)
			} else if mtuResult.Status == models.StatusWarn && result.Status == models.StatusPass {
				result.Status = models.StatusWarn
			}
			if mtu, ok := mtuResult.Observed["mtu"]; ok {
				result.Observed["mtu"] = mtu
			}
		}
	}

	return result, nil
}

func (e *Engine) runACLCheck(ctx context.Context, a intent.Assertion) (*models.CheckResult, error) {
	result := models.NewCheckResult("omada", "acl_check", "omada", a.Policy)

	// Get Omada credentials from environment
	host := os.Getenv("OMADA_HOST")
	username := os.Getenv("OMADA_USERNAME")
	password := os.Getenv("OMADA_PASSWORD")
	siteID := os.Getenv("OMADA_SITE")
	if host == "" || username == "" || password == "" {
		result.Status = models.StatusError
		result.Summary = "acl_check requires OMADA_HOST, OMADA_USERNAME, OMADA_PASSWORD environment variables"
		result.Finish()
		return result, nil
	}

	client, err := omada.NewClient(ctx, host)
	if err != nil {
		result.Status = models.StatusError
		result.Summary = fmt.Sprintf("failed to connect to Omada: %v", err)
		result.Finish()
		return result, nil
	}
	if err := client.Login(ctx, username, password); err != nil {
		result.Status = models.StatusError
		result.Summary = fmt.Sprintf("Omada login failed: %v", err)
		result.Finish()
		return result, nil
	}
	defer client.Logout(ctx)

	rules, err := client.GetACLRules(ctx, siteID)
	if err != nil {
		result.Status = models.StatusError
		result.Summary = fmt.Sprintf("failed to fetch ACL rules: %v", err)
		result.Finish()
		return result, nil
	}
	gwRules, _ := client.GetGatewayACLRules(ctx, siteID)
	allRules := append(rules, gwRules...)

	// Find the declared policy
	var policy *intent.Policy
	for i := range e.Spec.Policies {
		if e.Spec.Policies[i].Name == a.Policy {
			policy = &e.Spec.Policies[i]
			break
		}
	}
	if policy == nil {
		result.Status = models.StatusError
		result.Summary = fmt.Sprintf("policy %q not found in spec", a.Policy)
		result.Finish()
		return result, nil
	}

	// Check if a matching ACL rule exists
	found := false
	for _, rule := range allRules {
		if !rule.Status {
			continue // skip disabled rules
		}
		fromMatch := rule.SourceName == policy.From || strings.EqualFold(rule.SourceName, policy.From)
		toMatch := rule.DestName == policy.To || strings.EqualFold(rule.DestName, policy.To)
		actionMatch := (policy.Action == "deny" && rule.Policy == "drop") ||
			(policy.Action == "allow" && rule.Policy == "accept")
		if fromMatch && toMatch && actionMatch {
			found = true
			break
		}
	}

	expect := a.ExpectDeny // "enforced" or "not_enforced"
	wantEnforced := expect == "enforced"

	// Serialize rules as evidence
	rulesJSON, _ := json.Marshal(allRules)
	result.Evidence = append(result.Evidence, string(rulesJSON))
	result.Observed["rule_count"] = len(allRules)
	result.Expected["policy"] = a.Policy
	result.Expected["expect"] = expect

	if wantEnforced && found {
		result.Status = models.StatusPass
		result.Summary = fmt.Sprintf("ACL policy %q is enforced in Omada", a.Policy)
	} else if wantEnforced && !found {
		result.Status = models.StatusFail
		result.Summary = fmt.Sprintf("ACL policy %q is NOT enforced in Omada", a.Policy)
		result.Violations = append(result.Violations,
			fmt.Sprintf("no matching ACL rule found for policy %q (%s → %s %s)", a.Policy, policy.From, policy.To, policy.Action))
	} else if !wantEnforced && !found {
		result.Status = models.StatusPass
		result.Summary = fmt.Sprintf("ACL policy %q is correctly not enforced", a.Policy)
	} else {
		result.Status = models.StatusFail
		result.Summary = fmt.Sprintf("ACL policy %q is enforced but expected not_enforced", a.Policy)
	}

	result.Finish()
	return result, nil
}

func (e *Engine) runViaProbe(ctx context.Context, a intent.Assertion) (*models.CheckResult, error) {
	p := e.Spec.ProbeByName(a.Runner)
	if p == nil {
		return nil, fmt.Errorf("probe %q not found in spec", a.Runner)
	}

	probeP := probe.Probe{
		Name: p.Name,
		Host: p.Host,
		User: p.User,
		Key:  p.Key,
		VLAN: p.VLAN,
	}

	cmd := probeCommandFor(a)
	if cmd == nil {
		return nil, fmt.Errorf("assertion type %q does not support remote probe execution", a.Type)
	}

	output, err := probe.Run(ctx, probeP, cmd)
	result := models.NewCheckResult("probe", a.Type, a.Runner, probeTarget(a))
	result.Evidence = append(result.Evidence, fmt.Sprintf("probe: %s@%s", p.User, p.Host))
	result.Evidence = append(result.Evidence, fmt.Sprintf("command: %s", strings.Join(cmd, " ")))
	result.Evidence = append(result.Evidence, output)

	if err != nil {
		result.Status = models.StatusError
		result.Summary = fmt.Sprintf("probe %q: command failed: %v", a.Runner, err)
		result.Finish()
		return result, nil
	}

	return parseProbeOutput(result, a, output), nil
}

// probeCommandFor returns the shell command to run on a remote probe for the assertion.
// Returns nil if the assertion type doesn't support remote execution.
func probeCommandFor(a intent.Assertion) []string {
	switch a.Type {
	case "isolation", "network_health":
		// ping -c 3 <target>
		target := a.Target
		if target == "" {
			// For isolation, we probe the destination gateway
			target = a.To
		}
		return []string{"ping", "-c", "3", "-W", "3", target}
	case "port_check":
		// Use nc -z (netcat) to check port openness
		if len(a.Ports) == 0 {
			return nil
		}
		port := fmt.Sprintf("%d", a.Ports[0])
		return []string{"nc", "-z", "-w", "3", a.Target, port}
	case "dns_check":
		args := []string{"nslookup", a.Query}
		if a.Server != "" {
			args = append(args, a.Server)
		}
		return args
	default:
		return nil
	}
}

// probeTarget returns a human-readable target string for the assertion.
func probeTarget(a intent.Assertion) string {
	if a.Target != "" {
		return a.Target
	}
	if a.Query != "" {
		return a.Query
	}
	return fmt.Sprintf("%s→%s", a.From, a.To)
}

// parseProbeOutput interprets raw probe command output and updates result status.
func parseProbeOutput(result *models.CheckResult, a intent.Assertion, output string) *models.CheckResult {
	switch a.Type {
	case "isolation":
		// ping output — if contains "0 received" or "100% packet loss" → isolated (pass for deny)
		isBlocked := strings.Contains(output, "100% packet loss") ||
			strings.Contains(output, "0 received") ||
			strings.Contains(output, "100.0% packet loss")
		expectDeny := a.ExpectDeny == "deny"
		if expectDeny && isBlocked {
			result.Status = models.StatusPass
			result.Summary = fmt.Sprintf("isolation confirmed from probe %q: %s cannot reach %s", a.Runner, a.From, a.To)
		} else if expectDeny && !isBlocked {
			result.Status = models.StatusFail
			result.Summary = fmt.Sprintf("isolation violation from probe %q: %s can reach %s", a.Runner, a.From, a.To)
			result.Violations = append(result.Violations, "expected deny but traffic is reachable from probe VLAN")
		} else if !expectDeny && !isBlocked {
			result.Status = models.StatusPass
			result.Summary = fmt.Sprintf("connectivity confirmed from probe %q: %s can reach %s", a.Runner, a.From, a.To)
		} else {
			result.Status = models.StatusFail
			result.Summary = fmt.Sprintf("connectivity failure from probe %q: %s cannot reach %s", a.Runner, a.From, a.To)
		}
	case "port_check":
		// nc -z exits 0 if open, non-zero if closed/filtered
		// Since probe.Run returns err on non-zero exit, we handle this differently:
		// If we got here (no error), port is open
		expect := a.ExpectDeny
		if expect == "open" {
			result.Status = models.StatusPass
			result.Summary = fmt.Sprintf("port %d is open on %s (from probe %q)", a.Ports[0], a.Target, a.Runner)
		} else {
			result.Status = models.StatusFail
			result.Summary = fmt.Sprintf("port %d is open on %s but expected closed (from probe %q)", a.Ports[0], a.Target, a.Runner)
			result.Violations = append(result.Violations, fmt.Sprintf("expected closed but port %d is open", a.Ports[0]))
		}
	case "network_health":
		// ping output — parse loss
		isBlocked := strings.Contains(output, "100% packet loss") ||
			strings.Contains(output, "0 received") ||
			strings.Contains(output, "100.0% packet loss")
		if isBlocked {
			result.Status = models.StatusFail
			result.Summary = fmt.Sprintf("100%% packet loss to %s from probe %q", a.Target, a.Runner)
			result.Violations = append(result.Violations, "100% packet loss")
		} else {
			result.Status = models.StatusPass
			result.Summary = fmt.Sprintf("host %s is reachable from probe %q", a.Target, a.Runner)
		}
	case "dns_check":
		// nslookup output — check for expected IP
		if a.ExpectIP != "" && !strings.Contains(output, a.ExpectIP) {
			result.Status = models.StatusFail
			result.Summary = fmt.Sprintf("dns_check from probe %q: %s not resolved to %s", a.Runner, a.Query, a.ExpectIP)
			result.Violations = append(result.Violations, fmt.Sprintf("expected IP %s not in probe DNS response", a.ExpectIP))
		} else {
			result.Status = models.StatusPass
			result.Summary = fmt.Sprintf("dns_check from probe %q: resolved %s", a.Runner, a.Query)
		}
	default:
		result.Status = models.StatusWarn
		result.Summary = fmt.Sprintf("probe output not parsed for type %q", a.Type)
	}
	result.Finish()
	return result
}

// explainAssertionError turns raw errors into clearer, actionable messages for users.
// It returns a human-friendly Summary and a list of detail lines (each rendered as a ↳ bullet).
func explainAssertionError(a intent.Assertion, err error) (summary string, details []string) {
	errStr := err.Error()

	// Common case: nmap / discovery timeout
	if strings.Contains(errStr, "context deadline exceeded") || strings.Contains(errStr, "deadline exceeded") {
		summary = fmt.Sprintf("%s timed out", a.Type)
		details = []string{
			"This check took too long and was cancelled.",
			"Most likely causes:",
			"  - The target network isn't reachable from your current adapter (or runner).",
			"  - The subnet is large and the scan is slow.",
			"  - Hosts are filtering or rate-limiting discovery traffic.",
			"  - You're on the wrong VLAN for this check.",
			"Try: --interface <name> to force a specific adapter, or add a probe inside the target segment.",
		}
		return summary, details
	}

	// Probe-related errors
	if strings.Contains(errStr, "probe") && strings.Contains(errStr, "unreachable") {
		summary = fmt.Sprintf("probe %q is unreachable", a.Runner)
		details = []string{errStr}
		return summary, details
	}

	// DNS resolution failure
	if strings.Contains(errStr, "resolve") || strings.Contains(errStr, "no such host") {
		summary = fmt.Sprintf("%s failed — DNS resolution failed", a.Type)
		details = []string{
			"The DNS server couldn't resolve the query.",
			"Most likely causes:",
			"  - The DNS server address in the spec is wrong.",
			"  - The domain doesn't exist in DNS.",
			"  - The DNS server isn't reachable from your adapter.",
			"Try: verify the query and server in your spec, or use --interface to try from a different adapter.",
		}
		return summary, details
	}

	// Port scan failure
	if strings.Contains(errStr, "port scan failed") {
		summary = fmt.Sprintf("%s failed — port scan didn't complete", a.Type)
		details = []string{
			"The port scan couldn't reach the target.",
			"Most likely causes:",
			"  - The target host is down or unreachable from your adapter.",
			"  - A firewall is blocking scan traffic.",
			"  - The target IP in the spec is wrong.",
			"Try: verify the target IP, or use --interface to try from a different adapter.",
		}
		return summary, details
	}

	// Network health failure
	if strings.Contains(errStr, "network health check failed") {
		summary = fmt.Sprintf("%s failed — ping didn't complete", a.Type)
		details = []string{
			"The health check (ping) couldn't reach the target.",
			"Most likely causes:",
			"  - The target host is down or unreachable from your adapter.",
			"  - A firewall is blocking ICMP traffic.",
			"  - The target IP in the spec is wrong.",
			"Try: verify the target IP, or use --interface to try from a different adapter.",
		}
		return summary, details
	}

	// Network unreachable / connection refused
	if strings.Contains(errStr, "network is unreachable") {
		summary = fmt.Sprintf("%s failed — network unreachable", a.Type)
		details = []string{
			"The target network isn't reachable from where you're running.",
			"Check your routing, or use --interface to try from a different adapter.",
		}
		return summary, details
	}

	// Generic fallback — still better than the old raw "error running assertion: ..."
	summary = fmt.Sprintf("%s failed: %v", a.Type, err)
	details = []string{"Raw error: " + errStr}
	return summary, details
}
