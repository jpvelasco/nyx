package opnsense

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/jpvelasco/nyx/internal/audit"
	"github.com/jpvelasco/nyx/internal/intent"
	providers "github.com/jpvelasco/nyx/internal/providers"
)

// OPNsenseProvider implements providers.Provider for OPNsense firewalls.
// Currently only Info is implemented. ImportSpec and Check return ErrCapabilityUnsupported.
type OPNsenseProvider struct{}

func (o *OPNsenseProvider) Name() string { return "opnsense" }

func (o *OPNsenseProvider) Capabilities() []string {
	return []string{"info", "import", "check"}
}

func (o *OPNsenseProvider) Info(ctx context.Context, opts providers.ImportOptions) (*providers.ProviderInfo, error) {
	if opts.Host == "" {
		return nil, fmt.Errorf("--host is required for opnsense provider")
	}
	client := NewClient(opts.Host, opts.Username, opts.Password)
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

func (o *OPNsenseProvider) ImportSpec(ctx context.Context, opts providers.ImportOptions) (*providers.ImportResult, error) {
	if opts.Host == "" {
		return nil, fmt.Errorf("--host is required for opnsense provider")
	}
	if opts.Username == "" || opts.Password == "" {
		return nil, fmt.Errorf("--username and --password are required (API key and secret)")
	}

	client := NewClient(opts.Host, opts.Username, opts.Password)

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
			ScanMode:       "normal",
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

		from := inferZoneFromAddress(rule.Source.Address, networks)
		to := inferZoneFromAddress(rule.Destination.Address, networks)
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
			Type:       "isolation",
			From:       p.From,
			To:         p.To,
			ExpectDeny: "deny",
			Policy:     p.Name,
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

func (o *OPNsenseProvider) Check(ctx context.Context, opts providers.ImportOptions) (*providers.AuditResult, error) {
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

var _ providers.Provider = (*OPNsenseProvider)(nil)

func init() {
	providers.Register(&OPNsenseProvider{})
}
