// Package opnsense implements the providers.Provider interface for OPNsense firewalls using API key/secret auth.
package opnsense

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/jpvelasco/nyx/internal/audit"
	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/models"
	providers "github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/topology"
)

// ProviderName is the registry key for the OPNsense provider.
const ProviderName = "opnsense"

// isPermissionDenied reports whether err is the client's stable 403
// privilege error (an API user without the page privilege for the
// endpoint). It is distinct from the 401 credential error: a stable
// privilege 403 is safe to degrade on (the gateway is reachable and the
// key is valid — the user simply lacks the page privilege), while a 401
// or a transport failure means the credentials or the link itself are
// broken and must stay fatal.
func isPermissionDenied(err error) bool {
	var se *stableError
	return errors.As(err, &se) && strings.Contains(err.Error(), "permission denied")
}

// Provider implements providers.Provider for OPNsense firewalls.
type Provider struct{}

// newProviderClient builds a client from the shared import options, so the
// --debug flag reaches every provider surface (info, inventory, import,
// check, nat_check, plan/apply NAT).
func newProviderClient(opts providers.ImportOptions) *Client {
	client := NewClient(opts.Host, opts.ClientID, opts.ClientSecret, opts.SkipTLSVerify, opts.CACertPath)
	client.Debug = opts.Debug
	client.SetLogger(opts.Logger)
	return client
}

// Name returns the provider identifier "opnsense".
func (o *Provider) Name() string { return ProviderName }

// Capabilities lists the supported operations for this provider.
func (o *Provider) Capabilities() []string {
	return []string{"info", "import", "check", "inventory"}
}

// Info fetches system info from the OPNsense device (version, product,
// arch). The version read uses /diagnostics/system/system_information, which
// is covered by the Dashboard page privilege — the firmware endpoints
// require the separate System: Firmware privilege.
func (o *Provider) Info(ctx context.Context, opts providers.ImportOptions) (*providers.ProviderInfo, error) {
	if opts.Host == "" {
		return nil, fmt.Errorf("--host is required for opnsense provider")
	}
	client := newProviderClient(opts)
	sys, err := client.GetSystemInformation(ctx)
	if err != nil {
		return nil, err
	}
	return &providers.ProviderInfo{
		Provider: "opnsense",
		Host:     opts.Host,
		Version:  sys.ProductVersion(),
		Extra: map[string]string{
			"product": "OPNsense",
			"arch":    sys.Arch(),
		},
	}, nil
}

// Inventory returns the firewall's point-in-time observation: system
// metadata, its interfaces as networks, the firewall rule count, and the
// active DHCP-lease (client) count. It is read-only and never mutates.
func (o *Provider) Inventory(ctx context.Context, opts providers.ImportOptions) (*providers.ProviderInventory, error) {
	if opts.Host == "" {
		return nil, fmt.Errorf("--host is required for opnsense provider")
	}
	if opts.ClientID == "" || opts.ClientSecret == "" {
		return nil, fmt.Errorf("--client-id and --client-secret are required (API key and secret)")
	}
	client := newProviderClient(opts)
	snap, err := client.FetchInventory(ctx)
	if err != nil {
		return nil, err
	}
	return &providers.ProviderInventory{
		Site:        "opnsense-firewall",
		Human:       RenderInventory(snap, "opnsense-firewall"),
		Inventory:   BuildSpecInventory(snap),
		ClientCount: snap.LeaseCount(),
		Warnings:    snap.Warnings,
	}, nil
}

// ImportSpec builds a full intent spec by querying interfaces, firewall rules, DHCP leases, etc. from OPNsense.
func (o *Provider) ImportSpec(ctx context.Context, opts providers.ImportOptions) (*providers.ImportResult, error) {
	if opts.Host == "" {
		return nil, fmt.Errorf("--host is required for opnsense provider")
	}
	if opts.ClientID == "" || opts.ClientSecret == "" {
		return nil, fmt.Errorf("--client-id and --client-secret are required (API key and secret)")
	}

	client := newProviderClient(opts)

	// Get system info for version
	sys, err := client.GetSystemInformation(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching system info: %w", err)
	}

	// Get interfaces with IP configuration
	interfaces, err := client.GetInterfaces(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching interfaces: %w", err)
	}

	// Get firewall rules for policy detection. A stable 403 (the API user
	// lacks the Firewall: Filter page privilege) degrades to a zero-policy
	// spec with an explicit warning — the gateway is reachable and the
	// credentials are valid, so a least-privilege user must still get a
	// usable import. Every other failure (401 credential error, transport,
	// 5xx) stays fatal: a silent "0 policies" import for a broken key or an
	// unreachable controller would hide the real problem.
	var rules []FirewallRule
	var rulesErr error
	rules, rulesErr = client.GetFirewallRules(ctx)
	if rulesErr != nil && !isPermissionDenied(rulesErr) {
		return nil, fmt.Errorf("fetching firewall rules: %w", rulesErr)
	}

	// Get DHCP leases for host count estimation (best-effort on a stable
	// 403, mirroring the rules fetch above: no DHCP page privilege means a
	// zero-client estimate, not a fatal import).
	leases, leasesErr := client.GetDHCPLeases(ctx)
	if leasesErr != nil && !isPermissionDenied(leasesErr) {
		return nil, fmt.Errorf("fetching DHCP leases: %w", leasesErr)
	}

	// Degrade warnings for the stable-privilege 403s above. They ride the
	// same structured Warnings channel as the other import warnings, so the
	// CLI prints them once to stderr and `check` (which imports first)
	// surfaces them alongside the audit report — a 0-policy import never
	// reads as a clean pass.
	var warnings []string
	if rulesErr != nil {
		warnings = append(warnings,
			"firewall rules unavailable: "+rulesErr.Error()+
				" — the spec has no policies; grant the Firewall: Filter page privilege (System ‣ Access ‣ Users) to the API user to import them")
	}
	if leasesErr != nil {
		warnings = append(warnings,
			"DHCP leases unavailable: "+leasesErr.Error()+
				" — client count is estimated as 0; grant the Diagnostics: DHCP page privilege (System ‣ Access ‣ Users) to the API user to count leases")
	}

	// Build networks from interfaces
	var networks []intent.Network
	for _, iface := range interfaces {
		if iface.IP == "" {
			continue
		}
		_, _, err := net.ParseCIDR(fmt.Sprintf("%s/%d", iface.IP, iface.Subnet))
		if err != nil {
			continue
		}

		// Infer zone from interface name/description
		zone := inferZone(iface.Name, iface.Description)

		networks = append(networks, intent.Network{
			Name:    strings.ToLower(strings.TrimSpace(iface.Name)),
			CIDR:    fmt.Sprintf("%s/%d", iface.IP, iface.Subnet),
			Gateway: iface.Gateway,
			Zone:    zone,
		})
	}

	// Build assertions: subnet_discovery + network_health per network
	var assertions []intent.Assertion
	for _, n := range networks {
		assertions = append(assertions, intent.Assertion{
			Type:           "subnet_discovery",
			Network:        n.Name,
			ExpectHostsMax: ptrInt(50),
			// Polite scans (T2, 50-100 pps) by default: normal/aggressive
			// modes trigger SYN-flood alarms on SDN controllers.
			ScanMode: "polite",
		})

		assertions = append(assertions, intent.Assertion{
			Type:            "network_health",
			Target:          n.Gateway,
			ExpectLatencyMs: 20,
			ExpectLossPct:   0,
		})
	}

	// Build policies from deny firewall rules
	var policies []intent.Policy
	for _, rule := range rules {
		if rule.Action != "block" && rule.Action != "reject" {
			continue
		}
		if rule.Disabled {
			continue
		}

		from := inferZoneFromAddress(rule.Source, networks)
		to := inferZoneFromAddress(rule.Destination, networks)
		if from == "" || to == "" {
			continue
		}

		name := rule.Label
		if name == "" {
			name = fmt.Sprintf("deny-%s-to-%s", from, to)
		}

		policies = append(policies, intent.Policy{
			Name:   strings.ToLower(name),
			From:   from,
			To:     to,
			Action: "deny",
		})
	}

	// Add isolation assertions for deny policies
	for _, p := range policies {
		assertions = append(assertions, intent.Assertion{
			Type:   "isolation",
			From:   p.From,
			To:     p.To,
			Expect: "deny",
			Policy: p.Name,
		})
	}

	// Estimate host count from DHCP leases
	hostCount := len(leases)

	spec := &intent.Spec{
		Version:    1,
		Site:       "opnsense-firewall",
		Networks:   networks,
		Policies:   policies,
		Assertions: assertions,
	}

	if len(networks) == 0 {
		warnings = append(warnings, emptyTopologyWarning)
	}
	warnings = append(warnings,
		"OPNsense import uses DHCP lease count as host estimate — adjust expect_hosts_max as needed",
		"Firewall rules are imported as deny policies — review and adjust in your spec",
	)

	return &providers.ImportResult{
		Spec: spec,
		ProviderInfo: providers.ProviderInfo{
			Provider: "opnsense",
			Host:     opts.Host,
			Version:  sys.ProductVersion(),
			Extra: map[string]string{
				"product": "OPNsense",
				"arch":    sys.Arch(),
			},
		},
		NetworkCount: len(networks),
		PolicyCount:  len(policies),
		ClientCount:  hostCount,
		Warnings:     warnings,
	}, nil
}

// Check imports a spec from OPNsense and runs a full audit using the local engine.
func (o *Provider) Check(ctx context.Context, opts providers.ImportOptions) (*providers.AuditResult, error) {
	imported, err := o.ImportSpec(ctx, opts)
	if err != nil {
		return nil, err
	}
	engine := audit.NewEngine(imported.Spec)
	// Forward the TLS options so audit-engine-backed assertions that talk to
	// the controller (nat_check, acl_check) honor the same
	// --skip-tls-verify / --ca-cert the import used.
	engine.SkipTLSVerify = opts.SkipTLSVerify
	engine.CACertPath = opts.CACertPath
	report, err := engine.Run(ctx)
	if err != nil {
		return nil, fmt.Errorf("audit failed: %w", err)
	}
	return &providers.AuditResult{
		Report:   report,
		Warnings: imported.Warnings,
	}, nil
}

// CheckACL is not yet implemented for OPNsense.
func (o *Provider) CheckACL(_ context.Context, req providers.ACLCheckRequest, _ providers.ImportOptions) (*models.CheckResult, error) {
	result := models.NewCheckResult("opnsense", "acl_check", "opnsense", req.PolicyName)
	result.Status = models.StatusError
	result.Summary = "CheckACL is not yet implemented for the OPNsense provider"
	result.Finish()
	return result, nil
}

// NatCheck reads the firewall's NAT posture (outbound NAT mode plus the
// rule counts) and evaluates it against the expected value: an outbound
// mode (automatic, hybrid, advanced, disabled) is an equality check; a
// topology role (nat_router, bridge, indeterminate) is the classification
// of this device; "unknown" asserts the mode is not reported (key drift).
// A missing snat_mode key is reported as unknown — never guessed (version
// drift across releases).
func (o *Provider) NatCheck(ctx context.Context, req providers.NatCheckRequest, opts providers.ImportOptions) (*models.CheckResult, error) {
	result := models.NewCheckResult("opnsense", "nat_check", "opnsense", req.ExpectMode)
	result.Expected["nat_mode"] = req.ExpectMode

	client := newProviderClient(opts)
	mode, err := client.GetOutboundNatMode(ctx)
	if err != nil {
		return natCheckError(result, "reading outbound NAT mode: %v", err), nil
	}
	pf, err := client.GetPortForwardRules(ctx)
	if err != nil {
		return natCheckError(result, "reading port forward rules: %v", err), nil
	}
	o2o, err := client.GetOneToOneRules(ctx)
	if err != nil {
		return natCheckError(result, "reading one-to-one rules: %v", err), nil
	}
	snat, err := client.GetSourceNatRules(ctx)
	if err != nil {
		return natCheckError(result, "reading source NAT rules: %v", err), nil
	}
	result.Finish()
	result.Observed["outbound_nat_mode"] = mode
	result.Observed["source_nat_rules"] = len(snat)
	result.Observed["port_forward_rules"] = len(pf)
	result.Observed["one_to_one_rules"] = len(o2o)

	expect := req.ExpectMode
	var role topology.NatRole
	if topology.IsRole(expect) {
		report := topology.BuildReport([]topology.DeviceFacts{{
			Provider:         topology.ProviderOpnsense,
			OutboundNatMode:  mode,
			SourceNatRules:   len(snat),
			PortForwardRules: len(pf),
			OneToOneRules:    len(o2o),
		}})
		if len(report.Devices) != 1 {
			return natCheckError(result, "internal: topology classification returned no device"), nil
		}
		role = report.Devices[0].Role
		result.Evidence = append(result.Evidence, report.Devices[0].Evidence...)
	}

	switch {
	case role != "" && string(role) == expect:
		result.Status = models.StatusPass
		result.Summary = fmt.Sprintf("outbound NAT mode %q classifies as %s (source NAT rules: %d)", mode, expect, len(snat))
	case mode == expect:
		result.Status = models.StatusPass
		result.Summary = fmt.Sprintf("outbound NAT mode %q matches expect %q (source NAT rules: %d)", mode, expect, len(snat))
	case mode == "" && expect != "unknown":
		// The controller answered but not with the known snat_mode field —
		// report unknown and never guess (version key drift).
		result.Status = models.StatusWarn
		result.Observed["outbound_nat_mode"] = "unknown"
		result.Violations = append(result.Violations, fmt.Sprintf("outbound NAT mode missing from source_nat general config, cannot compare against %q", expect))
		result.Summary = fmt.Sprintf("outbound NAT mode not reported by the controller (key drift across versions?) — treat as unknown; expected %q", expect)
	case mode == "" && expect == "unknown":
		result.Status = models.StatusPass
		result.Summary = "outbound NAT mode not reported by the controller; expect unknown matches"
	default:
		result.Status = models.StatusFail
		result.Violations = append(result.Violations, fmt.Sprintf("outbound NAT mode is %q, expected %q", mode, expect))
		result.Summary = fmt.Sprintf("outbound NAT mode %q does not match expect %q", mode, expect)
	}
	return result, nil
}

// PlanNat previews a NAT mutation (BDD §3 S3.1–S3.6). It validates the
// request, runs the double-NAT guard, and reads the collection's current
// rules as Before evidence. It issues zero POSTs — the dry-run = zero
// POSTs lock.
func (o *Provider) PlanNat(ctx context.Context, req providers.NatApplyRequest, opts providers.ImportOptions) (*providers.NatPlan, error) {
	op, err := validateNatRequest(req)
	if err != nil {
		return nil, err
	}
	if err := requireNatHost(opts); err != nil {
		return nil, err
	}
	client := newProviderClient(opts)

	guardCtx, cancel := context.WithTimeout(ctx, natGuardTimeout)
	guard, err := client.natGuard(guardCtx)
	cancel()
	if err != nil {
		return nil, err
	}
	rules, err := op.list(client, ctx)
	if err != nil {
		return nil, fmt.Errorf("reading %s rules: %w", req.Operation, err)
	}
	before := marshalRules(rules)

	warnings := []string{natStagedWarning}
	outcome, ruleUUID := planOutcome(req)
	if w := guard.natGuardWarning(req.AllowDoubleNat); w != "" {
		outcome = "refused"
		ruleUUID = ""
		warnings = append(warnings, w)
	}
	endpoint := natPlanEndpoint(op, req)
	return &providers.NatPlan{
		Provider:  "opnsense",
		DryRun:    true,
		Outcome:   outcome,
		RuleUUID:  ruleUUID,
		Endpoints: []string{endpoint},
		Before:    before,
		Warnings:  warnings,
	}, nil
}

// ApplyNat performs a NAT mutation (BDD §3 S3.1–S3.6) when the guard passes
// and dry-run is not set. A dry-run or an idempotent no-op (a create whose
// 5-tuple already exists with the same spec) issues zero POSTs. Before/After
// evidence is the collection's rule list as JSON; the created rule's UUID is
// resolved from the add_rule response (preferred) or a unique 5-tuple match
// (lock 6).
func (o *Provider) ApplyNat(ctx context.Context, req providers.NatApplyRequest, opts providers.ImportOptions) (*providers.NatApplyResult, error) {
	op, err := validateNatRequest(req)
	if err != nil {
		return nil, err
	}
	if err := requireNatHost(opts); err != nil {
		return nil, err
	}
	client := newProviderClient(opts)

	guardCtx, cancel := context.WithTimeout(ctx, natGuardTimeout)
	guard, err := client.natGuard(guardCtx)
	cancel()
	if err != nil {
		return nil, err
	}
	rules, err := op.list(client, ctx)
	if err != nil {
		return nil, fmt.Errorf("reading %s rules: %w", req.Operation, err)
	}
	before := marshalRules(rules)

	warnings := []string{natStagedWarning}
	if w := guard.natGuardWarning(req.AllowDoubleNat); w != "" {
		return &providers.NatApplyResult{
			Provider:  "opnsense",
			DryRun:    req.DryRun,
			Outcome:   "refused",
			Endpoints: []string{op.create},
			Before:    before,
			After:     before,
			Warnings:  append(warnings, w),
		}, nil
	}

	spec := natSpecToWire(op.coll, req.Spec)
	outcome, ruleUUID, posted, refetched, err := o.applyNatMutation(ctx, client, op, req, spec, rules)
	if err != nil {
		return nil, err
	}
	after := before
	if refetched {
		refreshed, err := op.list(client, ctx)
		if err != nil {
			return nil, fmt.Errorf("refetching %s rules after %s: %w", req.Operation, outcome, err)
		}
		after = marshalRules(refreshed)
		if outcome == "created" && ruleUUID == "" {
			ruleUUID = matchPortForward(refreshed, spec)
		}
	}
	endpoints := posted
	if endpoints == nil {
		// Dry-run, refusal, and idempotent no-ops post nothing — the
		// planned endpoint is the evidence of what would have been hit.
		endpoints = []string{natPlanEndpoint(op, req)}
	}
	return &providers.NatApplyResult{
		Provider:  "opnsense",
		DryRun:    req.DryRun,
		Outcome:   outcome,
		RuleUUID:  ruleUUID,
		Endpoints: endpoints,
		Before:    before,
		After:     after,
		Warnings:  warnings,
	}, nil
}

// applyNatMutation executes the requested mutation against the collection.
// It returns the outcome, the resolved rule UUID, the exact API paths posted
// (empty for dry-run and no-ops), and whether the caller must refetch the
// collection for After evidence.
func (o *Provider) applyNatMutation(ctx context.Context, client *Client, op natOperation, req providers.NatApplyRequest, spec natRuleSpec, before []NatRule) (outcome, ruleUUID string, posted []string, refetched bool, err error) {
	ruleUUID = req.RuleUUID
	action := natAction(req)
	if req.DryRun {
		return "unchanged", ruleUUID, nil, false, nil
	}
	switch action {
	case "create":
		// Port forward is idempotent: a covering rule with the same spec
		// is unchanged (zero POSTs); otherwise create.
		if op.coll == "port_forward" {
			if existing := matchPortForward(before, spec); existing != "" {
				return "unchanged", existing, nil, false, nil
			}
		}
		switch op.coll {
		case "port_forward":
			ruleUUID, err = client.CreatePortForwardRule(ctx, spec)
		case "one_to_one":
			ruleUUID, err = client.CreateOneToOneRule(ctx, spec)
		default:
			ruleUUID, err = client.CreateSourceNatRule(ctx, spec)
		}
		if err != nil {
			return "", "", nil, false, fmt.Errorf("creating %s rule: %w", req.Operation, err)
		}
		return "created", ruleUUID, []string{op.create}, true, nil
	case "update":
		var setErr error
		switch op.coll {
		case "port_forward":
			setErr = client.SetPortForwardRule(ctx, req.RuleUUID, spec)
		case "one_to_one":
			setErr = client.SetOneToOneRule(ctx, req.RuleUUID, spec)
		default:
			setErr = client.SetSourceNatRule(ctx, req.RuleUUID, spec)
		}
		if setErr != nil {
			return "", "", nil, false, fmt.Errorf("setting %s rule: %w", req.Operation, setErr)
		}
		return "updated", ruleUUID, []string{fmt.Sprintf(op.set, req.RuleUUID)}, true, nil
	case "delete":
		var delErr error
		switch op.coll {
		case "port_forward":
			delErr = client.DeletePortForwardRule(ctx, req.RuleUUID)
		case "one_to_one":
			delErr = client.DeleteOneToOneRule(ctx, req.RuleUUID)
		default:
			delErr = client.DeleteSourceNatRule(ctx, req.RuleUUID)
		}
		if delErr != nil {
			return "", "", nil, false, fmt.Errorf("deleting %s rule: %w", req.Operation, delErr)
		}
		return "deleted", ruleUUID, []string{fmt.Sprintf(op.del, req.RuleUUID)}, true, nil
	default: // toggle (validated port-forward-only)
		if err := client.TogglePortForwardRule(ctx, req.RuleUUID, req.ToggleDisable); err != nil {
			return "", "", nil, false, fmt.Errorf("toggling %s rule: %w", req.Operation, err)
		}
		return "updated", ruleUUID, []string{op.toggle}, true, nil
	}
}

// requireNatHost fails fast when no controller host was given, so a
// missing host is a configuration error instead of a dial failure against
// an empty host after the guard's first GET.
func requireNatHost(opts providers.ImportOptions) error {
	if opts.Host == "" {
		return fmt.Errorf("--host is required for opnsense NAT mutation")
	}
	return nil
}

// validateNatRequest checks the operation and action, returning the
// collection descriptor on success.
func validateNatRequest(req providers.NatApplyRequest) (natOperation, error) {
	op, ok := natOperations[req.Operation]
	if !ok {
		return natOperation{}, fmt.Errorf("operation must be one of port_forward, one_to_one, source_nat; got %q", req.Operation)
	}
	action := req.Action
	if action == "" {
		action = "create"
	}
	switch action {
	case "create", "update", "delete":
	case "toggle":
		if op.coll != "port_forward" {
			return natOperation{}, fmt.Errorf("toggle is only supported for port_forward, not %q", req.Operation)
		}
	default:
		return natOperation{}, fmt.Errorf("action must be one of create, update, delete, toggle; got %q", req.Action)
	}
	if action == "update" || action == "delete" || action == "toggle" {
		if req.RuleUUID == "" {
			return natOperation{}, fmt.Errorf("rule_uuid is required for action %q", action)
		}
	}
	return op, nil
}

// natAction normalises an empty action to "create".
func natAction(req providers.NatApplyRequest) string {
	if req.Action == "" {
		return "create"
	}
	return req.Action
}

// planOutcome decides the PlanNat outcome for the requested action.
func planOutcome(req providers.NatApplyRequest) (string, string) {
	switch natAction(req) {
	case "update":
		return "would_update", req.RuleUUID
	case "delete":
		return "would_delete", req.RuleUUID
	case "toggle":
		return "would_update", req.RuleUUID
	default:
		return "would_create", ""
	}
}

// natPlanEndpoint picks the endpoint string for plan/apply evidence.
// The set/del formatters take the uuid as their single argument; the
// toggle pattern is emitted verbatim because the polarity flag is not
// encoded into the evidence.
func natPlanEndpoint(op natOperation, req providers.NatApplyRequest) string {
	switch natAction(req) {
	case "update":
		return fmt.Sprintf(op.set, req.RuleUUID)
	case "delete":
		return fmt.Sprintf(op.del, req.RuleUUID)
	case "toggle":
		return op.toggle
	default:
		return op.create
	}
}

// matchPortForward returns the UUID of the unique port forward rule matching
// the spec's 5-tuple (label, interface, protocol, destination, port), or ""
// when none or more than one match (ambiguous — the caller treats that as a
// miss, never a guess).
func matchPortForward(rules []NatRule, spec natRuleSpec) string {
	var match string
	for _, r := range rules {
		if !portForwardMatches(r, spec) {
			continue
		}
		if match != "" {
			return "" // ambiguous
		}
		match = r.RuleUUID
	}
	return match
}

// portForwardMatches reports whether a stored port forward rule matches the
// spec's 5-tuple.
func portForwardMatches(r NatRule, spec natRuleSpec) bool {
	if spec.Label != "" && r.Label != spec.Label {
		return false
	}
	if spec.Destination != "" && r.Destination != spec.Destination {
		return false
	}
	if spec.Port != "" && r.Port != spec.Port {
		return false
	}
	if spec.Protocol != "" && r.Protocol != strings.ToUpper(spec.Protocol) {
		return false
	}
	if len(spec.Interfaces) > 0 {
		if len(r.Interface) != len(spec.Interfaces) {
			return false
		}
		for i := range spec.Interfaces {
			if spec.Interfaces[i] != r.Interface[i] {
				return false
			}
		}
	}
	return true
}

// natSpecToWire maps the agent-facing NatRuleSpec to the client's natRuleSpec
// for the given collection, applying the model defaults (lock 7 field sets).
func natSpecToWire(coll string, spec providers.NatRuleSpec) natRuleSpec {
	wire := natRuleSpec{
		Interfaces:  spec.Interfaces,
		Protocol:    spec.Protocol,
		Source:      spec.Source,
		Destination: spec.Destination,
		Port:        spec.Port,
		LocalPort:   spec.LocalPort,
		Target:      spec.Target,
		Mode:        spec.Mode,
		Type:        spec.Type,
		Label:       spec.Label,
	}
	// one_to_one and source_nat carry an enabled flag (default 1); d_nat does not.
	if coll == "one_to_one" || coll == "source_nat" {
		wire.Enabled = "1"
	}
	// ipprotocol defaults to inet for the collections that model it.
	if coll == "port_forward" || coll == "source_nat" {
		wire.IPProtocol = "inet"
	}
	return wire
}

// natCheckError finishes a failed read with a StatusError result.
func natCheckError(result *models.CheckResult, format string, args ...any) *models.CheckResult {
	result.Status = models.StatusError
	result.Summary = fmt.Sprintf(format, args...)
	result.Finish()
	return result
}

// inferZone guesses a zone name from the OPNsense interface name or description.
func inferZone(name, description string) string {
	lower := strings.ToLower(name)
	switch {
	case strings.Contains(lower, "lan"):
		return "clients"
	case strings.Contains(lower, "wan"):
		return "wan"
	case strings.Contains(lower, "guest"):
		return "guest"
	case strings.Contains(lower, "iot"):
		return "iot"
	case strings.Contains(lower, "management") || strings.Contains(lower, "mgt"):
		return "management"
	case strings.Contains(lower, "server") || strings.Contains(lower, "srv"):
		return "servers"
	case strings.Contains(lower, "voice") || strings.Contains(lower, "voip"):
		return "voice"
	}
	// Check description for clues
	descLower := strings.ToLower(description)
	if strings.Contains(descLower, "vlan") {
		return "vlan"
	}
	return "segment"
}

// inferZoneFromAddress tries to match a source/dest address to a zone name.
func inferZoneFromAddress(address string, networks []intent.Network) string {
	if address == "" || address == "any" {
		return ""
	}
	ip := net.ParseIP(address)
	if ip == nil {
		return ""
	}
	for _, n := range networks {
		_, netw, err := net.ParseCIDR(n.CIDR)
		if err != nil {
			continue
		}
		if netw.Contains(ip) {
			return n.Zone
		}
	}
	return ""
}

// ptrInt returns a pointer to the given int.
func ptrInt(i int) *int {
	return &i
}

var _ providers.Provider = (*Provider)(nil)
var _ providers.NatChecker = (*Provider)(nil)
var _ providers.InventoryProvider = (*Provider)(nil)
var _ providers.NatMutationProvider = (*Provider)(nil)

func init() {
	_ = providers.Register(&Provider{})
}
