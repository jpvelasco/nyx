package audit

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"slices"
	"strings"

	"github.com/jpvelasco/nyx/internal/backends/health"
	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/models"
	"github.com/jpvelasco/nyx/internal/probe"
)

func (e *Engine) runViaProbe(ctx context.Context, a intent.Assertion) (*models.CheckResult, error) {
	p := e.Spec.ProbeByName(a.Runner)
	if p == nil {
		return nil, fmt.Errorf("probe %q not found in spec", a.Runner)
	}

	probeP := probe.FromSpec(*p)

	// Assertion types that need more than one remote command (or a
	// per-port protocol gate) have a dedicated path; the rest share the
	// single command below.
	switch a.Type {
	case "isolation":
		return e.runIsolationViaProbe(ctx, a, probeP)
	case "port_check":
		return e.runPortCheckViaProbe(ctx, a, probeP)
	}

	// Defense in depth: the spec validator rejects dnssec with a probe
	// runner, but a programmatically constructed spec must not obtain a
	// DNSSEC PASS from nslookup, which never validates (#269).
	if a.Type == "dns_check" && a.DNSSEC {
		return nil, intent.ProbeDNSSECUnsupportedError(a.Runner)
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
		cmd := []string{"ping", "-c", fmt.Sprint(probeHealthPingCount), "-W", "3", gw}
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

// runPortCheckViaProbe runs one netcat check per requested port from the
// probe and evaluates every measured port against the expectation. A port
// that could not be measured (netcat missing, transport failure,
// cancellation) never produces a passing assertion: the verdict degrades to
// WARN instead. A probe-wide failure (transport/auth/host-key/cancellation)
// marks the remaining ports unmeasured without redialing the failed probe.
func (e *Engine) runPortCheckViaProbe(ctx context.Context, a intent.Assertion, probeP probe.Probe) (*models.CheckResult, error) {
	protocol := a.Protocol
	if protocol == "" {
		protocol = "tcp"
	}
	result := models.NewCheckResult("probe", "port_check", a.Runner, probeTarget(a))
	result.Evidence = append(result.Evidence, fmt.Sprintf("probe: %s@%s", probeP.User, probeP.Host))
	result.Expected["expect"] = a.Expect
	result.Expected["ports"] = a.Ports
	if !strings.EqualFold(protocol, "tcp") {
		result.Status = models.StatusError
		result.Summary = fmt.Sprintf("remote port_check supports tcp only (got %s); remove runner to check %s locally, or drop protocol to check tcp from the probe", strings.ToUpper(protocol), a.Target)
		result.Finish()
		return result, nil
	}

	states := make([]string, 0, len(a.Ports))
	portsObserved := make([]interface{}, 0, len(a.Ports))
	record := func(port int, state string, note error) {
		if state == "unmeasured" {
			result.Evidence = append(result.Evidence, fmt.Sprintf("port %d: unmeasured (%v)", port, note))
		} else {
			result.Evidence = append(result.Evidence, fmt.Sprintf("port %d: %s", port, state))
		}
		states = append(states, state)
		portsObserved = append(portsObserved, map[string]interface{}{"port": float64(port), "state": state, "protocol": "tcp"})
	}
	for i, port := range a.Ports {
		cmd := []string{"nc", "-z", "-w", "3", a.Target, fmt.Sprintf("%d", port)}
		result.Evidence = append(result.Evidence, fmt.Sprintf("command: %s", strings.Join(cmd, " ")))

		output, err := probe.Run(ctx, probeP, cmd, e.SkipHostKeyVerify)
		if output != "" {
			// Record only the size of the remote output: the text itself is
			// attacker-controlled, and audit results feed agent surfaces
			// (MCP) where labeling or quoting cannot neutralize it
			// deterministically.
			result.Evidence = append(result.Evidence, fmt.Sprintf("remote output: %d bytes (content withheld)", len(output)))
		}

		state := classifyPortProbeResult(err)
		record(port, state, err)

		var remoteErr *probe.RemoteError
		if state == "unmeasured" && !errors.As(err, &remoteErr) {
			// The remote command never executed (dial/auth/host-key failure or
			// cancellation): a probe-wide failure that redialing cannot fix,
			// so the remaining ports are marked unmeasured without redialing.
			for _, rest := range a.Ports[i+1:] {
				record(rest, "unmeasured", errors.New("skipped after probe failure"))
			}
			break
		}
	}
	result.Observed["ports"] = portsObserved

	status, summary, violations := evalPortCheckVerdict(a.Target, a.Runner, a.Expect == "open", a.Ports, states)
	result.Status = status
	result.Summary = summary
	result.Violations = append(result.Violations, violations...)
	result.Finish()
	return result, nil
}

// classifyPortProbeResult maps one probe.Run outcome to the port's measured
// state: "open" (netcat exit 0), "closed" (netcat ran and exited non-zero,
// i.e. closed or filtered), or "unmeasured" (netcat missing — shell exit
// 126/127 — or a transport/auth/host-key/context error).
func classifyPortProbeResult(err error) string {
	if err == nil {
		return "open"
	}
	var remoteErr *probe.RemoteError
	if errors.As(err, &remoteErr) {
		if remoteErr.Status() == 126 || remoteErr.Status() == 127 {
			// Command not executable / not found: netcat is missing on the
			// probe, so the port was never actually checked.
			return "unmeasured"
		}
		return "closed"
	}
	// The remote command never produced a usable result.
	return "unmeasured"
}

// probeCommandFor returns the shell command to run on a remote probe for the assertion.
// For isolation assertions, the spec is used to resolve zone names to gateway IPs.
// port_check runs one command per requested port through
// runPortCheckViaProbe and never reaches this path. Returns nil if the
// assertion type doesn't support remote execution.
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
		return []string{"ping", "-c", fmt.Sprint(probeHealthPingCount), "-W", "3", target}
	case "dns_check":
		// nslookup performs plain resolution only. dnssec expectations are
		// rejected before remote execution (intent.ProbeDNSSECUnsupportedError).
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

// evalPortCheckVerdict consolidates the verdict for a remote port check:
// any measured violation fails the assertion, an assertion with no measured
// ports is unverifiable (WARN), and a mix of measured and unmeasured ports
// is only partially verified (WARN).
func evalPortCheckVerdict(target, runner string, expectOpen bool, ports []int, states []string) (models.Status, string, []string) {
	expect := "open"
	observed := "open"
	if !expectOpen {
		expect = "closed"
		observed = "closed"
	}
	var violations []string
	unmeasured := 0
	for i, port := range ports {
		switch states[i] {
		case "unmeasured":
			unmeasured++
		case "open":
			if !expectOpen {
				violations = append(violations, fmt.Sprintf("port %d: expected closed, got open", port))
			}
		default: // measured closed/filtered
			if expectOpen {
				violations = append(violations, fmt.Sprintf("port %d: expected open, got %s", port, states[i]))
			}
		}
	}
	if len(violations) > 0 {
		return models.StatusFail, fmt.Sprintf("port check failed on %s from probe %q: %s", target, runner, strings.Join(violations, "; ")), violations
	}
	if unmeasured == len(ports) {
		return models.StatusWarn, fmt.Sprintf("port check unverifiable on %s from probe %q: all %d port(s) unmeasured (expected %s)", target, runner, len(ports), expect), nil
	}
	if unmeasured > 0 {
		return models.StatusWarn, fmt.Sprintf("port check partially verified on %s from probe %q: %d of %d port(s) unmeasured (expected %s)", target, runner, unmeasured, len(ports), expect), nil
	}
	return models.StatusPass, fmt.Sprintf("all %d port(s) %s on %s (from probe %q)", len(ports), observed, target, runner), nil
}

// parseProbeOutput interprets raw probe command output and updates result status.
// remoteFailed reports that the remote command executed but exited non-zero
// (e.g. ping with 100% packet loss, nslookup on NXDOMAIN) — a value signal
// that must be evaluated against the assertion rather than treated as an error.
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
	case "network_health":
		// ping output — non-zero exit means no replies (100% loss)
		if remoteFailed || isPingBlocked(output) {
			result.Status = models.StatusFail
			result.Summary = fmt.Sprintf("100%% packet loss to %s from probe %q", a.Target, a.Runner)
			result.Violations = append(result.Violations, "100% packet loss")
		} else if a.ExpectLatencyMs > 0 || a.ExpectLossPct > 0 {
			// Declared thresholds apply to the remote measurement too,
			// evaluated with the canonical health classification so the
			// same assertion cannot pass remotely and fail locally on
			// identical health.
			status, violations, summary := health.EvaluatePingOutput(output, a.Target, probeHealthPingCount, a.ExpectLatencyMs, a.ExpectLossPct)
			result.Status = status
			result.Violations = append(result.Violations, violations...)
			if summary != "" {
				result.Summary = fmt.Sprintf("network health from probe %q: %s", a.Runner, summary)
			} else {
				result.Summary = fmt.Sprintf("host %s is reachable from probe %q (latency/loss within thresholds)", a.Target, a.Runner)
			}
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
