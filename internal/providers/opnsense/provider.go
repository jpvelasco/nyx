// Package opnsense implements the providers.Provider interface for OPNsense firewalls using API key/secret auth.
package opnsense

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/jpvelasco/nyx/internal/audit"
	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/models"
	providers "github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/topology"
)

// Provider implements providers.Provider for OPNsense firewalls.
// Currently only Info is implemented. ImportSpec and Check return ErrCapabilityUnsupported.
type Provider struct{}

// Name returns the provider identifier "opnsense".
func (o *Provider) Name() string { return "opnsense" }

// Capabilities lists the supported operations for this provider.
func (o *Provider) Capabilities() []string {
	return []string{"info", "import", "check"}
}

// Info fetches firmware and system info from the OPNsense device (no auth required for basic info).
func (o *Provider) Info(ctx context.Context, opts providers.ImportOptions) (*providers.ProviderInfo, error) {
	if opts.Host == "" {
		return nil, fmt.Errorf("--host is required for opnsense provider")
	}
	client := NewClient(opts.Host, opts.ClientID, opts.ClientSecret, opts.SkipTLSVerify, opts.CACertPath)
	fw, err := client.GetFirmwareInfo(ctx)
	if err != nil {
		return nil, err
	}
	return &providers.ProviderInfo{
		Provider: "opnsense",
		Host:     opts.Host,
		Version:  fw.ProductVersion,
		Extra: map[string]string{
			"product": fw.ProductName,
			"arch":    fw.ProductArch,
		},
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

	client := NewClient(opts.Host, opts.ClientID, opts.ClientSecret, opts.SkipTLSVerify, opts.CACertPath)

	// Get firmware info for version
	fw, err := client.GetFirmwareInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching firmware info: %w", err)
	}

	// Get interfaces with IP configuration
	interfaces, err := client.GetInterfaces(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching interfaces: %w", err)
	}

	// Get firewall rules for policy detection
	rules, err := client.GetFirewallRules(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching firewall rules: %w", err)
	}

	// Get DHCP leases for host count estimation
	leases, err := client.GetDHCPLeases(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching DHCP leases: %w", err)
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

	warnings := []string{
		"OPNsense import uses DHCP lease count as host estimate — adjust expect_hosts_max as needed",
		"Firewall rules are imported as deny policies — review and adjust in your spec",
	}

	return &providers.ImportResult{
		Spec: spec,
		ProviderInfo: providers.ProviderInfo{
			Provider: "opnsense",
			Host:     opts.Host,
			Version:  fw.ProductVersion,
			Extra: map[string]string{
				"product": fw.ProductName,
				"arch":    fw.ProductArch,
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

	client := NewClient(opts.Host, opts.ClientID, opts.ClientSecret, opts.SkipTLSVerify, opts.CACertPath)
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

func init() {
	_ = providers.Register(&Provider{})
}
