// Package audit contains the concurrent assertion engine that executes a Spec's assertions using the appropriate backends and produces an AuditReport.
package audit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jpvelasco/nyx/internal/backends"
	"github.com/jpvelasco/nyx/internal/backends/nmap"
	"github.com/jpvelasco/nyx/internal/backends/system"
	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/models"
	"github.com/jpvelasco/nyx/internal/probe"
	providers "github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/seendb"
)

const (
	// assertionTimeoutDiscovery is the per-assertion timeout for nmap subnet scans.
	assertionTimeoutDiscovery = 90 * time.Second
	// assertionTimeoutDefault is the per-assertion timeout for all other checks.
	assertionTimeoutDefault = 30 * time.Second
)

// Engine runs audit assertions. It is NOT safe for concurrent use —
// Run() mutates runnerCtx and seenDB, and callers should create a new
// Engine via NewEngine for each audit.
type Engine struct {
	Spec              *intent.Spec
	Interface         string
	WarnVirtual       bool
	SkipTLSVerify     bool                 // allow self-signed TLS certs (like curl -k)
	CACertPath        string               // path to custom CA cert PEM file
	SkipHostKeyVerify bool                 // skip SSH host key verification for probes
	SeenDBPath        string               // if non-empty, overrides ~/.nyx/seen.json (used in tests)
	Backend           backends.Backend     // backend abstraction; nil means use default
	Logger            *slog.Logger         // structured logger; nil means use default stderr logger
	runnerCtx         models.RunnerContext // populated once at Run() time
	seenDB            *seendb.SeenDB       // populated once at Run() time
}

// NewEngine creates an audit engine for a spec
func NewEngine(spec *intent.Spec) *Engine {
	return &Engine{
		Spec:    spec,
		Backend: backends.NewDefaultBackend(),
		Logger:  slog.New(slog.NewTextHandler(os.Stderr, nil)),
	}
}

// Run executes all assertions concurrently and returns a report.
// Results are returned in the same order as the assertions in the spec.
// Engine is designed for single-use; Run resets internal state for safety
// but callers should create a new Engine via NewEngine for each audit.
func (e *Engine) Run(ctx context.Context) (*models.AuditReport, error) {
	e.runnerCtx = localRunnerContext(e.Spec, e.Interface)

	// Load SeenDB once for the entire run so concurrent subnet_discovery
	// assertions share the same in-memory state and avoid redundant file I/O.
	if e.SeenDBPath != "" {
		if loaded, err := seendb.LoadFrom(e.SeenDBPath); err == nil {
			e.seenDB = loaded
		} else {
			e.seenDB = seendb.New()
		}
	} else {
		e.seenDB = seendb.Load()
	}

	// Warn the user if we can't place them in any spec network (noob-friendly)
	if e.Interface == "" && len(e.runnerCtx.Networks) == 0 && len(e.Spec.Networks) > 0 {
		e.Logger.Warn("couldn't place your current network inside any spec network; you're likely multi-homed. Use --interface to pick which adapter to scan from. (Run 'nyx interfaces' to see the list.)")
	}

	assertions := e.Spec.Assertions
	findings := make([]models.CheckResult, len(assertions))

	var wg sync.WaitGroup
	wg.Add(len(assertions))

	for i, assertion := range assertions {
		i, assertion := i, assertion // capture loop vars
		go func() {
			defer wg.Done()

			// Recover from panics so a single assertion failure doesn't
			// leave findings[i] as a zero-value (which ComputeOverallStatus
			// treats as pass).
			defer func() {
				if r := recover(); r != nil {
					target := assertion.Target
					if target == "" {
						target = assertion.Network
					}
					if target == "" {
						target = assertion.From
					}
					errResult := models.NewCheckResult("audit", assertion.Type, "local", target)
					errResult.Status = models.StatusError
					errResult.Summary = fmt.Sprintf("%s panicked: %v", assertion.Type, r)
					errResult.Finish()
					findings[i] = *errResult
				}
			}()

			// Check if context is already cancelled before starting work
			select {
			case <-ctx.Done():
				target := assertion.Target
				if target == "" {
					target = assertion.Network
				}
				errResult := models.NewCheckResult("audit", assertion.Type, "local", target)
				errResult.Status = models.StatusError
				errResult.Summary = fmt.Sprintf("%s cancelled: %v", assertion.Type, ctx.Err())
				errResult.Finish()
				findings[i] = *errResult
				return
			default:
			}

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
				errResult.Violations = append(errResult.Violations, details...)
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

// matchNetworks returns the names of spec networks whose CIDRs contain at least
// one of the given IPs. This helper consolidates the CIDR-matching loop shared by
// localRunnerContext and pickBestInterface.
func matchNetworks(ips []net.IP, spec *intent.Spec) []string {
	var matched []string
	for _, n := range spec.Networks {
		_, cidr, err := net.ParseCIDR(n.CIDR)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			if cidr.Contains(ip) {
				matched = append(matched, n.Name)
				break
			}
		}
	}
	return matched
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

	matchedNetworks := matchNetworks(localIPs, spec)

	// Smart default for multi-homed machines (noob-friendly)
	// When no interface was forced, try to pick the "best" one (the one that matches the most spec networks).
	if interfaceName == "" && len(ifaces) > 1 && len(spec.Networks) > 0 {
		bestIface := pickBestInterface(ifaces, spec)
		if bestIface != "" {
			// Recompute using only the best interface
			return localRunnerContext(spec, bestIface)
		}
		// Still ambiguous → warn the user
		fmt.Fprintf(os.Stderr, "warning: multiple network interfaces, no clear winner for your spec. Use --interface to pick one. (Run 'nyx interfaces' to see the list.)\n")
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

		matched := matchNetworks(ifaceIPs, spec)
		if len(matched) > 0 {
			scores = append(scores, score{name: iface.Name, count: len(matched)})
		}
	}

	if len(scores) == 0 {
		return ""
	}

	// Find the highest score
	maxCount := 0
	for _, s := range scores {
		if s.count > maxCount {
			maxCount = s.count
		}
	}

	// Count how many have the max score
	winners := 0
	var winnerName string
	for _, s := range scores {
		if s.count == maxCount {
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
	// Give each assertion its own deadline so a single slow check
	// (e.g. a large nmap sweep) cannot starve the rest of the audit.
	// Probe assertions get the same budget — remote commands can hang
	// (black-holed DNS server, stalled shell) unless the deadline is
	// enforced on the SSH session as well.
	timeout := assertionTimeoutDefault
	if a.Type == "subnet_discovery" {
		timeout = assertionTimeoutDiscovery
	}
	assertCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Dispatch to probe if runner is set
	if a.Runner != "" && a.Runner != "local" {
		return e.runViaProbe(assertCtx, a)
	}

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

	result, err := e.Backend.Discover(ctx, net.CIDR, opts)
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
	// The nmap backend puts the host count under "total" in Observed.
	hostCount := 0
	if v, ok := result.Observed["total"]; ok {
		switch n := v.(type) {
		case int:
			hostCount = n
		case float64:
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

	// Host count violations take precedence over virtual network detection —
	// a real host-count failure should not be silently downgraded to a virtual
	// network warning.
	if len(result.Violations) > 0 {
		result.Summary = fmt.Sprintf("%d hosts discovered in %s", hostCount, net.CIDR)
		result.Finish()
		return result, nil
	}

	// Virtual network suppression: if 0 hosts and nmap evidence suggests a VM
	// hypervisor MAC, check seendb. First occurrence → WARN + ack. Subsequent
	// occurrences → SKIP (unless WarnVirtual override is set).
	// Check this BEFORE setting default pass status so the flow is clearer.
	if hostCount == 0 && (looksVirtual(result.Evidence) || looksVirtualByCIDR(net.CIDR)) {
		cidr := net.CIDR
		if e.WarnVirtual || !e.seenDB.IsVirtualAcked(cidr) {
			result.Status = models.StatusWarn
			if e.WarnVirtual {
				result.Summary = fmt.Sprintf("0 hosts discovered in %s (virtual adapter detected; --warn-virtual is set)", cidr)
			} else {
				result.Summary = fmt.Sprintf("0 hosts discovered in %s (virtual adapter detected — future scans will suppress this warning; use --warn-virtual to always show it)", cidr)
			}
			if err := e.seenDB.AckVirtual(cidr); err != nil {
				e.Logger.Warn("failed to ack virtual network; warning will reappear on next run", slog.String("cidr", cidr), slog.String("error", err.Error()))
				result.Evidence = append(result.Evidence, fmt.Sprintf("warning: failed to persist virtual network ack for %s: %v", cidr, err))
			}
		} else {
			result.Status = models.StatusSkip
			result.Summary = fmt.Sprintf("skipped: %s is a virtual network (acknowledged)", cidr)
		}
		result.Finish()
		return result, nil
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
	result.Expected["expect"] = a.Expect

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
		pingResult, err := e.Backend.Ping(ctx, targetNet.Gateway)
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

	expectDeny := a.Expect == "deny"

	// Determine isolation status with structured branching.
	// The runnerInFromZone check is unique to the direct (non-probe) case —
	// when the runner isn't in the source zone, allBlocked could mean
	// isolation OR just no route from this host.
	if !anyTested {
		result.Status = models.StatusWarn
		if expectDeny {
			result.Summary = fmt.Sprintf(
				"isolation unverifiable: %s → %s (target zone not routable from this host; use runner: <probe> from inside the %s zone)",
				a.From, a.To, a.From,
			)
		} else {
			result.Summary = fmt.Sprintf(
				"connectivity unverifiable: %s → %s (target zone not routable from this host)",
				a.From, a.To,
			)
		}
	} else if !runnerInFromZone {
		// None of the four outcomes is definitive when the runner is outside
		// the source zone: reachable gateways may be the runner's own network
		// (e.g. a runner inside the destination zone pings its own gateway),
		// and unreachable gateways may simply mean this host has no route.
		// Report what was observed without a hard verdict.
		result.Status = models.StatusWarn
		prefix := "isolation"
		if !expectDeny {
			prefix = "connectivity"
		}
		state := "unreachable"
		if !allBlocked {
			state = "reachable"
		}
		result.Summary = fmt.Sprintf(
			"%s unconfirmed: %s → %s gateways %s, but nyx is not running from inside the %s zone — use runner: <probe> for a definitive check",
			prefix, a.From, a.To, state, a.From,
		)
	} else if expectDeny && allBlocked {
		result.Status = models.StatusPass
		result.Summary = fmt.Sprintf("isolation confirmed: %s cannot reach %s", a.From, a.To)
	} else if expectDeny && !allBlocked {
		result.Status = models.StatusFail
		result.Summary = fmt.Sprintf("isolation violation: %s can reach %s", a.From, a.To)
		result.Violations = append(result.Violations, "expected deny but traffic is reachable")
	} else if !expectDeny && !allBlocked {
		result.Status = models.StatusPass
		result.Summary = fmt.Sprintf("connectivity confirmed: %s can reach %s", a.From, a.To)
	} else {
		result.Status = models.StatusFail
		result.Summary = fmt.Sprintf("connectivity failure: %s cannot reach %s", a.From, a.To)
	}

	result.Finish()
	return result, nil
}

// resolveRoute creates a CheckResult for the given assertion type, resolves the
// target route, and returns an early-error result if the route lookup fails.
// On success, the caller should populate result.Observed and continue.
func (e *Engine) resolveRoute(ctx context.Context, aType string, target string) (*models.CheckResult, *system.Route, error) {
	result := models.NewCheckResult("system", aType, "local", target)

	route, err := e.Backend.GetRouteToTarget(ctx, target)
	if err != nil {
		result.Status = models.StatusError
		result.Summary = fmt.Sprintf("failed to get route to %s: %v", target, err)
		result.Finish()
		return result, nil, nil
	}
	return result, route, nil
}

func (e *Engine) runVPNRoute(ctx context.Context, a intent.Assertion) (*models.CheckResult, error) {
	vpn := e.Spec.VPNByName(a.VPN)
	if vpn == nil {
		return nil, fmt.Errorf("vpn %q not found in spec", a.VPN)
	}

	result, route, _ := e.resolveRoute(ctx, "vpn_route", a.Target)
	if route == nil {
		return result, nil
	}
	result.Expected["vpn"] = vpn.Name
	result.Expected["target"] = a.Target

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

	viaTunnel := expectedIface != "" && route.Device == expectedIface
	// Also check if the device looks like a VPN interface
	if !viaTunnel {
		isVPN, _ := e.Backend.CheckVPNInterface(ctx, route.Device)
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
	} else if a.ExpectTunnel != nil {
		// expect_tunnel: false — the route must NOT go through the tunnel.
		if viaTunnel {
			result.Status = models.StatusFail
			result.Summary = fmt.Sprintf("%s routed via %s (tunnel)", a.Target, route.Device)
			result.Violations = append(result.Violations,
				fmt.Sprintf("expected direct route, got tunnel device %s", route.Device))
		} else {
			result.Status = models.StatusPass
			result.Summary = fmt.Sprintf("%s routed via %s (not tunnel)", a.Target, route.Device)
		}
	} else {
		result.Status = models.StatusPass
		result.Summary = fmt.Sprintf("%s routed via %s", a.Target, route.Device)
	}

	result.Finish()
	return result, nil
}

func (e *Engine) runRouteCheck(ctx context.Context, a intent.Assertion) (*models.CheckResult, error) {
	result, route, _ := e.resolveRoute(ctx, "route_check", a.Target)
	if route == nil {
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

	result, err := e.Backend.PortScan(ctx, a.Target, a.Ports, protocol, opts)
	if err != nil {
		return nil, fmt.Errorf("port scan failed: %w", err)
	}

	// Evaluate pass/fail: all ports must match expect.
	// The nmap backend scans with --open, so ports absent from the output
	// are reported as "filtered" — nmap cannot distinguish closed from
	// filtered there. The meaningful verdict is therefore open vs not-open:
	// expect "closed" passes whenever the port is NOT open.
	expectOpen := a.Expect == "open"
	var violations []string
	if portData, ok := result.Observed["ports"]; ok {
		if ports, ok := portData.([]interface{}); ok {
			for _, p := range ports {
				if pm, ok := p.(map[string]interface{}); ok {
					state, _ := pm["state"].(string)
					port, _ := pm["port"].(float64)
					isOpen := state == "open"
					if expectOpen && !isOpen {
						violations = append(violations, fmt.Sprintf("port %.0f: expected open, got %s", port, state))
					} else if !expectOpen && isOpen {
						violations = append(violations, fmt.Sprintf("port %.0f: expected closed, got open", port))
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
	result.Expected["expect"] = a.Expect
	result.Expected["ports"] = a.Ports
	return result, nil
}

func (e *Engine) runDNSCheck(ctx context.Context, a intent.Assertion) (*models.CheckResult, error) {
	var result *models.CheckResult
	var err error

	if a.ExpectIP != "" {
		result, err = e.Backend.ResolveExpect(ctx, a.Query, a.Server, a.ExpectIP)
	} else {
		result, err = e.Backend.Resolve(ctx, a.Query, a.Server)
	}
	if err != nil {
		return nil, fmt.Errorf("dns check failed: %w", err)
	}

	if result.Expected == nil {
		result.Expected = map[string]interface{}{}
	}
	result.Expected["query"] = a.Query

	if a.DNSSEC {
		dnssecResult, dnssecErr := e.Backend.CheckDNSSEC(ctx, a.Query, a.Server)
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
		result, err = e.Backend.CheckLatencyAndLoss(ctx, a.Target, a.ExpectLatencyMs, a.ExpectLossPct)
	} else {
		result, _, err = e.Backend.PingCheck(ctx, a.Target, 10)
	}
	if err != nil {
		return nil, fmt.Errorf("network health check failed: %w", err)
	}

	if a.ExpectMTU > 0 {
		mtuResult, mtuErr := e.Backend.ProbeMTU(ctx, a.Target, a.ExpectMTU)
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

// aclCheckErrorResult creates a finished CheckResult with StatusError for acl_check failures.
func aclCheckErrorResult(provider, policy string, summary string) *models.CheckResult {
	result := models.NewCheckResult(provider, "acl_check", provider, policy)
	result.Status = models.StatusError
	result.Summary = summary
	result.Finish()
	return result
}

func (e *Engine) runACLCheck(ctx context.Context, a intent.Assertion) (*models.CheckResult, error) {
	providerName := a.Provider
	if providerName == "" {
		providerName = "omada"
	}

	// Find the declared policy in the spec
	var policy *intent.Policy
	for i := range e.Spec.Policies {
		if e.Spec.Policies[i].Name == a.Policy {
			policy = &e.Spec.Policies[i]
			break
		}
	}
	if policy == nil {
		return aclCheckErrorResult(providerName, a.Policy,
			fmt.Sprintf("policy %q not found in spec", a.Policy)), nil
	}

	// Look up provider from registry
	p := providers.Get(providerName)
	if p == nil {
		return aclCheckErrorResult(providerName, a.Policy,
			fmt.Sprintf("provider %q not found in registry", providerName)), nil
	}

	// Build import options from environment (backward-compatible with existing env var pattern)
	opts := providers.ImportOptions{
		Host:          os.Getenv("OMADA_HOST"),
		Username:      os.Getenv("OMADA_USERNAME"),
		Password:      os.Getenv("OMADA_PASSWORD"),
		Site:          os.Getenv("OMADA_SITE"),
		SkipTLSVerify: e.SkipTLSVerify,
		CACertPath:    e.CACertPath,
	}
	if opts.Host == "" || opts.Username == "" || opts.Password == "" {
		return aclCheckErrorResult(providerName, a.Policy,
			"acl_check requires OMADA_HOST, OMADA_USERNAME, OMADA_PASSWORD environment variables"), nil
	}

	expect := a.Expect // "enforced" or "not_enforced"
	wantEnforced := expect == "enforced"

	req := providers.ACLCheckRequest{
		PolicyName:     a.Policy,
		From:           policy.From,
		To:             policy.To,
		Action:         policy.Action,
		ExpectEnforced: wantEnforced,
	}

	return p.CheckACL(ctx, req, opts)
}

func (e *Engine) runViaProbe(ctx context.Context, a intent.Assertion) (*models.CheckResult, error) {
	p := e.Spec.ProbeByName(a.Runner)
	if p == nil {
		return nil, fmt.Errorf("probe %q not found in spec", a.Runner)
	}

	probeP := probe.FromSpec(*p)

	// For isolation assertions, check all gateways in the destination zone
	if a.Type == "isolation" {
		return e.runIsolationViaProbe(ctx, a, probeP)
	}

	cmd := probeCommandFor(a, e.Spec)
	if cmd == nil {
		return nil, fmt.Errorf("assertion type %q does not support remote probe execution", a.Type)
	}

	output, err := probe.Run(ctx, probeP, cmd, e.SkipHostKeyVerify)
	result := models.NewCheckResult("probe", a.Type, a.Runner, probeTarget(a))
	result.Evidence = append(result.Evidence, fmt.Sprintf("probe: %s@%s", p.User, p.Host))
	result.Evidence = append(result.Evidence, fmt.Sprintf("command: %s", strings.Join(cmd, " ")))
	result.Evidence = append(result.Evidence, output)

	if err != nil {
		var remoteErr *probe.RemoteError
		switch {
		case errors.As(err, &remoteErr):
			// The remote command ran but exited non-zero (e.g. nc -z on a
			// closed port). That is a value signal — evaluate it against
			// the assertion, not as an execution failure.
			result.Finish()
			return parseProbeOutput(result, a, output, true), nil
		case ctx.Err() != nil:
			result.Status = models.StatusError
			result.Summary = fmt.Sprintf("probe %q: command timed out: %v", a.Runner, ctx.Err())
		default:
			// Transport failures (dial/auth/host-key/session) or any other
			// error — the remote command never produced a usable result.
			result.Status = models.StatusError
			result.Summary = fmt.Sprintf("probe %q: command failed: %v", a.Runner, err)
		}
		result.Finish()
		return result, nil
	}

	return parseProbeOutput(result, a, output, false), nil
}

// runIsolationViaProbe runs isolation checks against all gateways in the destination zone.
func (e *Engine) runIsolationViaProbe(ctx context.Context, a intent.Assertion, probeP probe.Probe) (*models.CheckResult, error) {
	gateways := resolveZoneToGateways(a.To, e.Spec)
	if len(gateways) == 0 {
		result := models.NewCheckResult("probe", "isolation", a.Runner, fmt.Sprintf("%s -> %s", a.From, a.To))
		result.Status = models.StatusError
		result.Summary = fmt.Sprintf("could not resolve target %q to any network", a.To)
		result.Finish()
		return result, nil
	}

	result := models.NewCheckResult("probe", "isolation", a.Runner, fmt.Sprintf("%s -> %s", a.From, a.To))
	result.Evidence = append(result.Evidence, fmt.Sprintf("probe: %s@%s", probeP.User, probeP.Host))

	allBlocked := true
	anyTested := false
	unreached := 0

	for _, gw := range gateways {
		cmd := []string{"ping", "-c", "3", "-W", "3", gw}
		result.Evidence = append(result.Evidence, fmt.Sprintf("command: %s", strings.Join(cmd, " ")))

		output, err := probe.Run(ctx, probeP, cmd, e.SkipHostKeyVerify)
		result.Evidence = append(result.Evidence, output)

		if probe.IsUnreachable(err) || ctx.Err() != nil {
			// The probe never executed the ping — SSH, auth, or session
			// failure. This must NOT count as evidence that the gateway
			// is blocked.
			unreached++
			result.Evidence = append(result.Evidence, fmt.Sprintf("gateway %s: probe unreachable (%v)", gw, err))
			continue
		}

		anyTested = true
		if err != nil || isPingBlocked(output) {
			// Remote exit non-zero (e.g. 100% loss) or output confirms loss.
			result.Evidence = append(result.Evidence, fmt.Sprintf("gateway %s: blocked", gw))
		} else {
			allBlocked = false
			result.Evidence = append(result.Evidence, fmt.Sprintf("gateway %s: reachable", gw))
		}
	}

	expectDeny := a.Expect == "deny"

	// If the probe was unreachable for every gateway, no verdict is possible —
	// a probe outage must never be reported as confirmed isolation.
	if !anyTested {
		result.Status = models.StatusWarn
		result.Summary = fmt.Sprintf("isolation unverifiable: probe %q was unreachable (%s → %s, %d gateway(s) untested)", a.Runner, a.From, a.To, len(gateways))
		result.Finish()
		return result, nil
	}

	status, summary, violations := EvalIsolationStatus(a.Runner, a.From, a.To, expectDeny, anyTested, allBlocked)
	if status == models.StatusPass && unreached > 0 {
		// "All gateways blocked" is only conclusive when every gateway was
		// actually tested — partial coverage degrades the verdict.
		result.Status = models.StatusWarn
		result.Summary = fmt.Sprintf("isolation partially verified: %d gateway(s) could not be tested from probe %q (%s → %s)", unreached, a.Runner, a.From, a.To)
	} else {
		result.Status = status
		result.Summary = summary
		result.Violations = append(result.Violations, violations...)
	}

	result.Finish()
	return result, nil
}

// probeCommandFor returns the shell command to run on a remote probe for the assertion.
// For isolation assertions, the spec is used to resolve zone names to gateway IPs.
// Returns nil if the assertion type doesn't support remote execution.
func probeCommandFor(a intent.Assertion, spec *intent.Spec) []string {
	switch a.Type {
	case "isolation", "network_health":
		// ping -c 3 <target>
		target := a.Target
		if target == "" && a.Type == "isolation" {
			// For isolation, resolve the destination zone to gateway IPs
			target = resolveZoneToGateway(a.To, spec)
		}
		if target == "" {
			return nil
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

// resolveZoneToGateway resolves a zone name to a gateway IP using the spec.
// It first tries to find networks by zone name, then by network name.
// Returns the first gateway IP found, or the original name if no gateway is available.
func resolveZoneToGateway(zone string, spec *intent.Spec) string {
	gateways := resolveZoneToGateways(zone, spec)
	if len(gateways) > 0 {
		return gateways[0]
	}
	return zone
}

// resolveZoneToGateways resolves a zone name to all gateway IPs using the spec.
// It checks networks by zone name first, then by network name.
func resolveZoneToGateways(zone string, spec *intent.Spec) []string {
	if spec == nil {
		return nil
	}

	var gateways []string

	// Try zone name first
	for _, n := range spec.NetworkByZone(zone) {
		if n.Gateway != "" {
			gateways = append(gateways, n.Gateway)
		}
	}

	// Try network name if no zone match
	if len(gateways) == 0 {
		if net := spec.NetworkByName(zone); net != nil && net.Gateway != "" {
			gateways = append(gateways, net.Gateway)
		}
	}

	return gateways
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

// EvalIsolationStatus determines the status, summary, and violations for an isolation
// check based on the probe context and connectivity results. This helper consolidates
// the branching logic shared by runIsolationViaProbe and parseProbeOutput.
func EvalIsolationStatus(runner, from, to string, expectDeny, anyTested, allBlocked bool) (models.Status, string, []string) {
	if !anyTested {
		return models.StatusWarn,
			fmt.Sprintf("isolation unverifiable from probe %q: %s → %s (no gateways reachable)", runner, from, to), nil
	}
	if expectDeny && allBlocked {
		return models.StatusPass,
			fmt.Sprintf("isolation confirmed from probe %q: %s cannot reach %s", runner, from, to), nil
	}
	if expectDeny && !allBlocked {
		return models.StatusFail,
			fmt.Sprintf("isolation violation from probe %q: %s can reach %s", runner, from, to),
			[]string{"expected deny but traffic is reachable from probe VLAN"}
	}
	if !expectDeny && !allBlocked {
		return models.StatusPass,
			fmt.Sprintf("connectivity confirmed from probe %q: %s can reach %s", runner, from, to), nil
	}
	return models.StatusFail,
		fmt.Sprintf("connectivity failure from probe %q: %s cannot reach %s", runner, from, to), nil
}

// parseProbeOutput interprets raw probe command output and updates result status.
// remoteFailed reports that the remote command executed but exited non-zero
// (e.g. nc -z on a closed port, nslookup on NXDOMAIN) — a value signal that
// must be evaluated against the assertion rather than treated as an error.
func parseProbeOutput(result *models.CheckResult, a intent.Assertion, output string, remoteFailed bool) *models.CheckResult {
	switch a.Type {
	case "isolation":
		// ping output — if contains "0 received" or "100% packet loss" → isolated (pass for deny)
		isBlocked := isPingBlocked(output)
		expectDeny := a.Expect == "deny"
		status, summary, violations := EvalIsolationStatus(a.Runner, a.From, a.To, expectDeny, true, isBlocked)
		result.Status = status
		result.Summary = summary
		result.Violations = append(result.Violations, violations...)
	case "port_check":
		// nc -z exits 0 when the port is open; a non-zero exit means closed
		// or filtered. The verdict is the inverse of the expectation — a
		// closed port is a value signal, never an execution error.
		portOpen := !remoteFailed
		switch {
		case a.Expect == "open" && portOpen:
			result.Status = models.StatusPass
			result.Summary = fmt.Sprintf("port %d is open on %s (from probe %q)", a.Ports[0], a.Target, a.Runner)
		case a.Expect == "open" && !portOpen:
			result.Status = models.StatusFail
			result.Summary = fmt.Sprintf("port %d is closed on %s but expected open (from probe %q)", a.Ports[0], a.Target, a.Runner)
			result.Violations = append(result.Violations, fmt.Sprintf("expected open but port %d is closed", a.Ports[0]))
		case portOpen:
			result.Status = models.StatusFail
			result.Summary = fmt.Sprintf("port %d is open on %s but expected closed (from probe %q)", a.Ports[0], a.Target, a.Runner)
			result.Violations = append(result.Violations, fmt.Sprintf("expected closed but port %d is open", a.Ports[0]))
		default:
			result.Status = models.StatusPass
			result.Summary = fmt.Sprintf("port %d is closed on %s (from probe %q)", a.Ports[0], a.Target, a.Runner)
		}
	case "network_health":
		// ping output — non-zero exit means no replies (100% loss)
		if remoteFailed || isPingBlocked(output) {
			result.Status = models.StatusFail
			result.Summary = fmt.Sprintf("100%% packet loss to %s from probe %q", a.Target, a.Runner)
			result.Violations = append(result.Violations, "100% packet loss")
		} else {
			result.Status = models.StatusPass
			result.Summary = fmt.Sprintf("host %s is reachable from probe %q", a.Target, a.Runner)
		}
	case "dns_check":
		// nslookup exits non-zero on NXDOMAIN / server failure — the query
		// did not resolve, which is itself the answer to evaluate.
		if remoteFailed {
			result.Status = models.StatusFail
			result.Summary = fmt.Sprintf("dns_check from probe %q: %s did not resolve", a.Runner, a.Query)
			result.Violations = append(result.Violations, "query did not resolve on the probe")
			break
		}
		if a.ExpectIP != "" {
			resolved := probeDNSAnswers(output, a.Server)
			if len(resolved) == 0 || !slices.Contains(resolved, a.ExpectIP) {
				result.Status = models.StatusFail
				result.Summary = fmt.Sprintf("dns_check from probe %q: %s not resolved to %s (got %v)", a.Runner, a.Query, a.ExpectIP, resolved)
				result.Violations = append(result.Violations, fmt.Sprintf("expected IP %s not in probe DNS response", a.ExpectIP))
			} else {
				result.Status = models.StatusPass
				result.Summary = fmt.Sprintf("dns_check from probe %q: resolved %s", a.Runner, a.Query)
			}
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

// probeDNSAnswers extracts the answer addresses from nslookup output
// without tripping on the resolver's own preamble lines ("Server:" —
// "Address:"), which list the configured resolver, not the answer.
// Only real IP tokens are kept, and a token equal to the resolver
// address itself is discarded.
func probeDNSAnswers(output, server string) []string {
	var addrs []string
	seen := make(map[string]struct{})
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(trimmed), "server:") {
			continue
		}
		for _, tok := range strings.Fields(nonIPChars.ReplaceAllString(trimmed, " ")) {
			if net.ParseIP(tok) == nil || tok == server {
				continue
			}
			if _, ok := seen[tok]; ok {
				continue
			}
			seen[tok] = struct{}{}
			addrs = append(addrs, tok)
		}
	}
	return addrs
}

// nonIPChars matches anything that is not an IPv4/IPv6 character; used to
// split nslookup lines into candidate address tokens.
var nonIPChars = regexp.MustCompile(`[^0-9a-fA-F:.%]+`)

// isPingBlocked returns true if ping output indicates 100% packet loss.
func isPingBlocked(output string) bool {
	return strings.Contains(output, "100% packet loss") ||
		strings.Contains(output, "0 received") ||
		strings.Contains(output, "100.0% packet loss")
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
