package audit

import (
	"context"
	"fmt"
	"strings"

	"github.com/jpvelasco/nyx/internal/backends/system"
	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/models"
)

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
	// Fall back to a comma-separated list of network names (one-to-many
	// isolation, e.g. from post-mutation audits). Duplicates are dropped.
	if len(toNets) == 0 && strings.Contains(a.To, ",") {
		seen := make(map[string]bool, len(a.To))
		for _, name := range strings.Split(a.To, ",") {
			name = strings.TrimSpace(name)
			if name == "" || seen[name] {
				continue
			}
			if net := e.Spec.NetworkByName(name); net != nil {
				toNets = append(toNets, *net)
				seen[name] = true
			}
		}
	}

	if len(toNets) == 0 {
		result.Status = models.StatusError
		result.Summary = fmt.Sprintf("could not resolve target %q to any network", a.To)
		result.Finish()
		return result, nil
	}

	// Only a ping bound to an address on the requested network measures
	// isolation from that network on a multihomed runner.
	var source *system.PingSource
	var sourceNetwork string
	for _, n := range e.Spec.Networks {
		if addr, ok := e.runnerCtx.sources[n.Name]; ok && (n.Zone == a.From || n.Name == a.From) {
			source = &addr
			sourceNetwork = n.Name
			break
		}
	}
	// For each target network, ping the gateway to check reachability
	var unreachable []string
	allBlocked := true
	tested := 0
	for _, targetNet := range toNets {
		if targetNet.Gateway == "" {
			continue
		}
		pingResult, err := e.Backend.Ping(ctx, targetNet.Gateway, source)
		if err != nil {
			result.Evidence = append(result.Evidence, fmt.Sprintf("ping to %s failed: %v", targetNet.Gateway, err))
			continue
		}
		tested++
		if pingResult.Reachable {
			allBlocked = false
			result.Evidence = append(result.Evidence, fmt.Sprintf("gateway %s is reachable", targetNet.Gateway))
		} else {
			if source != nil {
				unreachable = append(unreachable, targetNet.Gateway)
			}
			result.Evidence = append(result.Evidence, fmt.Sprintf("gateway %s is not reachable", targetNet.Gateway))
		}
	}

	if len(unreachable) > 0 {
		result.Observed["unreachable_gateways"] = unreachable
		result.Observed["source_network"] = sourceNetwork
	}
	expectDeny := a.Expect == "deny"
	kind := "isolation"
	if !expectDeny {
		kind = "connectivity"
	}

	// Determine isolation status with structured branching.
	// The source zone check is unique to the direct (non-probe) case —
	// when the runner isn't in the source zone, allBlocked could mean
	// isolation OR just no route from this host.
	if tested == 0 {
		result.Status = models.StatusWarn
		result.Summary = fmt.Sprintf("%s unverifiable: %s → %s (no gateway could be tested; use runner: <probe> from inside the %s zone)", kind, a.From, a.To, a.From)
	} else if source == nil {
		// None of the four outcomes is definitive when the runner is outside
		// the source zone: reachable gateways may be the runner's own network
		// (e.g. a runner inside the destination zone pings its own gateway),
		// and unreachable gateways may simply mean this host has no route.
		// Report what was observed without a hard verdict.
		result.Status = models.StatusWarn
		state := "unreachable"
		if !allBlocked {
			state = "reachable"
		}
		result.Summary = fmt.Sprintf(
			"%s unconfirmed: %s → %s gateways %s, but nyx is not running from inside the %s zone — use runner: <probe> for a definitive check",
			kind, a.From, a.To, state, a.From,
		)
	} else if allBlocked == expectDeny && tested < len(toNets) {
		// As with a remote probe, incomplete coverage can only establish a
		// failure. A passing observation must cover the remaining gateways.
		result.Status = models.StatusWarn
		result.Summary = fmt.Sprintf("%s partially verified: %d gateway(s) could not be tested from %s", kind, len(toNets)-tested, a.From)
	} else if allBlocked == expectDeny {
		result.Status = models.StatusPass
		if expectDeny {
			result.Summary = fmt.Sprintf("isolation confirmed: %s cannot reach %s", a.From, a.To)
		} else {
			result.Summary = fmt.Sprintf("connectivity confirmed: %s can reach %s", a.From, a.To)
		}
	} else if expectDeny {
		result.Status = models.StatusFail
		result.Summary = fmt.Sprintf("isolation violation: %s can reach %s", a.From, a.To)
		result.Violations = append(result.Violations, "expected deny but traffic is reachable")
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
