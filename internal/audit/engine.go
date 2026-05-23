package audit

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/velasco-jp/nyx/internal/backends/nmap"
	"github.com/velasco-jp/nyx/internal/backends/system"
	"github.com/velasco-jp/nyx/internal/intent"
	"github.com/velasco-jp/nyx/internal/models"
)

const (
	// assertionTimeoutDiscovery is the per-assertion timeout for nmap subnet scans.
	assertionTimeoutDiscovery = 90 * time.Second
	// assertionTimeoutDefault is the per-assertion timeout for all other checks.
	assertionTimeoutDefault = 30 * time.Second
)

// Engine runs audit assertions
type Engine struct {
	Spec *intent.Spec
}

// NewEngine creates an audit engine for a spec
func NewEngine(spec *intent.Spec) *Engine {
	return &Engine{Spec: spec}
}

// Run executes all assertions concurrently and returns a report.
// Results are returned in the same order as the assertions in the spec.
func (e *Engine) Run(ctx context.Context) (*models.AuditReport, error) {
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
				errResult.Summary = fmt.Sprintf("error running assertion: %v", err)
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
		Findings: findings,
	}
	return report, nil
}

func (e *Engine) runAssertion(ctx context.Context, a intent.Assertion) (*models.CheckResult, error) {
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
	default:
		return nil, fmt.Errorf("unknown assertion type: %s", a.Type)
	}
}

func (e *Engine) runDiscovery(ctx context.Context, a intent.Assertion) (*models.CheckResult, error) {
	net := e.Spec.NetworkByName(a.Network)
	if net == nil {
		return nil, fmt.Errorf("network %q not found in spec", a.Network)
	}

	// Build scan options — use assertion overrides if set, otherwise defaults.
	opts := nmap.DefaultScanOptions
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

	if result.Status == "" || (len(result.Violations) == 0 && result.Status != models.StatusError) {
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

	expectDeny := a.ExpectDeny == "deny"
	if expectDeny {
		if !anyTested {
			// Could not reach any gateway — but that may just mean the target
			// zone has no route from this machine, not that isolation is working.
			result.Status = models.StatusWarn
			result.Summary = fmt.Sprintf(
				"isolation unverifiable: %s → %s (target zone not routable from this host; run from a host inside the %s zone for accurate results)",
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
