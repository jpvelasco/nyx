package audit

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/jpvelasco/nyx/internal/backends"
	"github.com/jpvelasco/nyx/internal/backends/system"
	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/models"
	"github.com/jpvelasco/nyx/internal/seendb"
)

const (
	// assertionTimeoutDiscovery is the per-assertion timeout for nmap subnet scans.
	assertionTimeoutDiscovery = 90 * time.Second
	// assertionTimeoutDefault is the per-assertion timeout for all other checks.
	assertionTimeoutDefault = 30 * time.Second
	// probeHealthPingCount is the number of pings the remote probe command
	// sends for isolation and network_health assertions (ping -c N).
	probeHealthPingCount = 3
)

// Telemetry (#137): spans and metrics flow through the process-wide OTel
// globals — no-op unless OTLP is configured (logger.InitTelemetry). All
// attributes are PII-safe by construction (types and statuses, never
// CIDRs, hostnames, or targets; docs/naming.md).
var (
	// auditTracerName/auditMeterName are resolved against the process-wide
	// OTel globals at call time (not init), so a provider configured later
	// — including by tests — is honored.
	auditTracerName = "nyx/audit"
	auditMeterName  = "nyx/audit"

	assertionsTotal metric.Int64Counter
	runDuration     metric.Float64Histogram
	telemetryOnce   sync.Once
)

// initTelemetryInstruments creates the run's metric instruments once per
// process. With no configured provider the no-op meter returns no-op
// instruments, so the instrumentation is inert until OTLP is enabled.
func initTelemetryInstruments() {
	assertionsTotal, _ = otel.Meter(auditMeterName).Int64Counter(
		"nyx_audit_assertions_total",
		metric.WithDescription("Number of audit assertions by type and status"),
	)
	runDuration, _ = otel.Meter(auditMeterName).Float64Histogram(
		"nyx_audit_run_duration_ms",
		metric.WithDescription("Audit run duration in milliseconds"),
		metric.WithUnit("ms"),
	)
}

// instrumentAssertion records one finding: one counter increment carrying
// the assertion type and resulting status.
func instrumentAssertion(checkType string, status models.Status) {
	telemetryOnce.Do(initTelemetryInstruments)
	if assertionsTotal == nil {
		return
	}
	assertionsTotal.Add(context.Background(), 1,
		metric.WithAttributes(
			attribute.String("type", checkType),
			attribute.String("status", string(status)),
		))
}

// Engine runs audit assertions. It is NOT safe for concurrent use —
// Run() mutates runnerCtx and seenDB, and callers should create a new
// Engine via NewEngine for each audit.
type Engine struct {
	Spec              *intent.Spec
	Interface         string
	WarnVirtual       bool
	SkipTLSVerify     bool             // allow self-signed TLS certs (like curl -k)
	CACertPath        string           // path to custom CA cert PEM file
	SkipHostKeyVerify bool             // skip SSH host key verification for probes
	SeenDBPath        string           // if non-empty, overrides ~/.nyx/seen.json (used in tests)
	CredentialsPath   string           // if non-empty, overrides ~/.nyx/credentials.json (used in tests)
	Backend           backends.Backend // backend abstraction; nil means use default
	Logger            *slog.Logger     // structured logger; nil means use default stderr logger
	runnerCtx         runnerContext    // populated once at Run() time
	seenDB            *seendb.SeenDB   // populated once at Run() time
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
	runStart := time.Now()
	ctx, runSpan := otel.Tracer(auditTracerName).Start(ctx, "nyx.audit.run")
	defer runSpan.End()

	if e.Logger == nil {
		// Callers (MCP, tests) may pass a nil logger; keep the stderr
		// fallback so engine warnings stay visible.
		e.Logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
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

			assertCtx, assertSpan := otel.Tracer(auditTracerName).Start(ctx, "nyx.assertion."+assertion.Type)
			result, err := e.runAssertion(assertCtx, assertion)
			assertSpan.End()
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

	// Telemetry: one counter per finding (type + status) and the run
	// duration, recorded centrally after the findings settle (#137).
	telemetryOnce.Do(initTelemetryInstruments)
	if assertionsTotal != nil {
		for i := range findings {
			instrumentAssertion(findings[i].CheckType, findings[i].Status)
		}
	}
	if runDuration != nil {
		runDuration.Record(context.Background(), float64(time.Since(runStart).Milliseconds()))
	}

	report := &models.AuditReport{
		Audit:    e.Spec.Site,
		Status:   models.ComputeOverallStatus(findings),
		Summary:  models.Tally(findings),
		Runner:   e.runnerCtx.RunnerContext,
		Findings: findings,
	}
	return report, nil
}

// runnerContext keeps the source addresses used to establish network membership
// alongside the public report. Interface bindings are needed only while probing.
type runnerContext struct {
	models.RunnerContext
	sources map[string]system.PingSource
}

func matchNetworks(addresses []system.PingSource, spec *intent.Spec) runnerContext {
	r := runnerContext{sources: make(map[string]system.PingSource)}
	for _, addr := range addresses {
		r.LocalIPs = append(r.LocalIPs, addr.IP.String())
	}
	for _, n := range spec.Networks {
		_, cidr, err := net.ParseCIDR(n.CIDR)
		if err != nil {
			continue
		}
		for _, addr := range addresses {
			if cidr.Contains(addr.IP) {
				r.Networks = append(r.Networks, n.Name)
				r.sources[n.Name] = addr
				break
			}
		}
	}
	return r
}

// interfaceSources returns the IPv4 addresses eligible for local audit probes.
func interfaceSources(iface net.Interface) []system.PingSource {
	if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
		return nil
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil
	}
	var sources []system.PingSource
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip.To4() != nil && !ip.IsLoopback() {
			sources = append(sources, system.PingSource{IP: ip, Interface: iface.Name})
		}
	}
	return sources
}

// localRunnerContext detects which of the spec networks this machine is inside.
// If interfaceName is non-empty, only addresses on that specific interface are considered.
func localRunnerContext(spec *intent.Spec, interfaceName string) runnerContext {
	ifaces, err := net.Interfaces()
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not enumerate network interfaces: %v\n", err)
		return runnerContext{}
	}

	// Smart default for multi-homed machines (noob-friendly)
	// When no interface was forced, try to pick the "best" one (the one that matches the most spec networks).
	if interfaceName == "" && len(ifaces) > 1 && len(spec.Networks) > 0 {
		bestIface := pickBestInterface(ifaces, spec)
		if bestIface != "" {
			interfaceName = bestIface
		} else {
			fmt.Fprintf(os.Stderr, "warning: multiple network interfaces, no clear winner for your spec. Use --interface to pick one. (Run 'nyx interfaces' to see the list.)\n")
		}
	}

	var sources []system.PingSource
	for _, iface := range ifaces {
		if interfaceName == "" || interfaceName == iface.Name {
			sources = append(sources, interfaceSources(iface)...)
		}
	}
	return matchNetworks(sources, spec)
}

// pickBestInterface tries to find the interface that can reach the most networks in the spec.
// Returns the interface name, or empty if there's no clear winner.
func pickBestInterface(ifaces []net.Interface, spec *intent.Spec) string {
	best := 0
	winner := ""
	for _, iface := range ifaces {
		count := len(matchNetworks(interfaceSources(iface), spec).Networks)
		switch {
		case count > best:
			best, winner = count, iface.Name
		case count == best:
			winner = ""
		}
	}
	return winner
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
	case "nat_check":
		return e.runNatCheck(assertCtx, a)
	default:
		return nil, fmt.Errorf("unknown assertion type: %s", a.Type)
	}
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

// recordSubcheckError records a failed auxiliary check (DNSSEC validation,
// MTU measurement) against the base result: it appends the labeled evidence
// and, when the base result passed, escalates it to an error carrying the
// labeled cause (still non-fatal — other assertions keep running) while
// preserving the base summary. The success-path handling (status adoption,
// summary text, violation rules) differs per domain and stays in each domain
// handler.
func recordSubcheckError(result *models.CheckResult, subErr error, evidenceLabel, summaryLabel string) {
	result.Evidence = append(result.Evidence, fmt.Sprintf("%s: %v", evidenceLabel, subErr))
	if result.Status == models.StatusPass {
		result.Status = models.StatusError
		result.Summary = fmt.Sprintf("%s; %s: %v", result.Summary, summaryLabel, subErr)
	}
}
