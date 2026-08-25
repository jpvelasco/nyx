// Package intent defines the YAML spec model (Spec, Assertion, Network, etc.) and validation logic.
package intent

import (
	"fmt"
	"net"
	"os"

	"gopkg.in/yaml.v3"
)

// Spec is the top-level intent file
type Spec struct {
	Version    int         `yaml:"version" json:"version"`
	Site       string      `yaml:"site" json:"site"`
	Networks   []Network   `yaml:"networks" json:"networks"`
	VPN        []VPNConfig `yaml:"vpn" json:"vpn"`
	Probes     []Probe     `yaml:"probes,omitempty" json:"probes,omitempty"`
	Policies   []Policy    `yaml:"policies" json:"policies"`
	Assertions []Assertion `yaml:"assertions" json:"assertions"`
	Inventory  *Inventory  `yaml:"inventory,omitempty" json:"inventory,omitempty"`
}

// Inventory is an observation snapshot of the controller's device inventory,
// populated by `nyx <provider> import`. It records what was seen at import
// time; re-import refreshes it. It is optional — hand-written specs omit it.
type Inventory struct {
	ControllerVersion  string            `yaml:"controller_version" json:"controller_version"`
	ControllerCategory string            `yaml:"controller_category,omitempty" json:"controller_category,omitempty"`
	Devices            []InventoryDevice `yaml:"devices" json:"devices"`
	NetworkGateways    map[string]string `yaml:"network_gateways,omitempty" json:"network_gateways,omitempty"`
	ACLScopes          []ACLScopeStatus  `yaml:"acl_scopes,omitempty" json:"acl_scopes,omitempty"`
}

// InventoryDevice is one managed device observed at import time.
// Name and IP are raw controller values (including hostnames), unlike the
// sanitized network names used elsewhere in the spec.
type InventoryDevice struct {
	Type     string   `yaml:"type" json:"type"` // gateway | switch | ap
	Name     string   `yaml:"name" json:"name"`
	Model    string   `yaml:"model" json:"model"`
	IP       string   `yaml:"ip,omitempty" json:"ip,omitempty"`
	Firmware string   `yaml:"firmware,omitempty" json:"firmware,omitempty"`
	Upgrade  bool     `yaml:"upgrade_available,omitempty" json:"upgrade_available,omitempty"`
	Networks []string `yaml:"networks,omitempty" json:"networks,omitempty"`
}

// ACLScopeStatus captures the rule count of a controller ACL scope. The
// Open API has no scope enable/disable flag, so a listed scope is active.
type ACLScopeStatus struct {
	Scope     string `yaml:"scope" json:"scope"` // "gateway" | "switch"
	RuleCount int    `yaml:"rule_count" json:"rule_count"`
}

// Network defines a named CIDR block
type Network struct {
	Name    string `yaml:"name" json:"name"`
	CIDR    string `yaml:"cidr" json:"cidr"`
	Gateway string `yaml:"gateway" json:"gateway"`
	Zone    string `yaml:"zone" json:"zone"`
	VLAN    int    `yaml:"vlan,omitempty" json:"vlan,omitempty"`
}

// VPNConfig defines expected VPN behavior
type VPNConfig struct {
	Name           string   `yaml:"name" json:"name"`
	Type           string   `yaml:"type" json:"type"`
	Interface      string   `yaml:"interface,omitempty" json:"interface,omitempty"`
	ExpectedRoutes []string `yaml:"expected_routes" json:"expected_routes"`
	Mode           string   `yaml:"mode" json:"mode"` // split-tunnel or full-tunnel
}

// Probe declares an SSH node that can run checks from a different VLAN.
type Probe struct {
	Name              string `yaml:"name" json:"name"`
	Host              string `yaml:"host" json:"host"`
	User              string `yaml:"user" json:"user"`
	Port              int    `yaml:"port,omitempty" json:"port,omitempty"` // SSH port; default 22
	Key               string `yaml:"key,omitempty" json:"key,omitempty"`
	VLAN              string `yaml:"vlan,omitempty" json:"vlan,omitempty"`
	SkipHostKeyVerify bool   `yaml:"skip_host_key_verify,omitempty" json:"skip_host_key_verify,omitempty"`
}

// Policy defines network access rules
type Policy struct {
	Name   string            `yaml:"name" json:"name"`
	From   string            `yaml:"from" json:"from"`
	To     string            `yaml:"to" json:"to"`
	Action string            `yaml:"action" json:"action"` // allow or deny
	Except []PolicyException `yaml:"except,omitempty" json:"except,omitempty"`
}

// PolicyException defines allowed exceptions to a deny policy
type PolicyException struct {
	Protocol string `yaml:"protocol" json:"protocol"`
	Port     int    `yaml:"port" json:"port"`
	Target   string `yaml:"target,omitempty" json:"target,omitempty"`
}

// Assertion defines a check to evaluate
type Assertion struct {
	Type            string  `yaml:"type" json:"type"`
	Network         string  `yaml:"network,omitempty" json:"network,omitempty"`
	From            string  `yaml:"from,omitempty" json:"from,omitempty"`
	To              string  `yaml:"to,omitempty" json:"to,omitempty"`
	VPN             string  `yaml:"vpn,omitempty" json:"vpn,omitempty"`
	Target          string  `yaml:"target,omitempty" json:"target,omitempty"`
	ExpectHostsMin  *int    `yaml:"expect_hosts_min,omitempty" json:"expect_hosts_min,omitempty"`
	ExpectHostsMax  *int    `yaml:"expect_hosts_max,omitempty" json:"expect_hosts_max,omitempty"`
	Expect          string  `yaml:"expect,omitempty" json:"expect,omitempty"`
	ExpectTunnel    *bool   `yaml:"expect_tunnel,omitempty" json:"expect_tunnel,omitempty"`
	Ports           []int   `yaml:"ports,omitempty" json:"ports,omitempty"`
	Protocol        string  `yaml:"protocol,omitempty" json:"protocol,omitempty"`
	ScanMode        string  `yaml:"scan_mode,omitempty" json:"scan_mode,omitempty"`
	ScanTiming      int     `yaml:"scan_timing,omitempty" json:"scan_timing,omitempty"`
	ScanMinRate     int     `yaml:"scan_min_rate,omitempty" json:"scan_min_rate,omitempty"`
	Query           string  `yaml:"query,omitempty" json:"query,omitempty"`
	ExpectIP        string  `yaml:"expect_ip,omitempty" json:"expect_ip,omitempty"`
	Server          string  `yaml:"server,omitempty" json:"server,omitempty"`
	DNSSEC          bool    `yaml:"dnssec,omitempty" json:"dnssec,omitempty"`
	ExpectLatencyMs float64 `yaml:"expect_latency_ms,omitempty" json:"expect_latency_ms,omitempty"`
	ExpectLossPct   float64 `yaml:"expect_loss_pct,omitempty" json:"expect_loss_pct,omitempty"`
	ExpectMTU       int     `yaml:"expect_mtu,omitempty" json:"expect_mtu,omitempty"`
	Provider        string  `yaml:"provider,omitempty" json:"provider,omitempty"`
	Policy          string  `yaml:"policy,omitempty" json:"policy,omitempty"`
	Runner          string  `yaml:"runner,omitempty" json:"runner,omitempty"`
}

// LoadSpec reads and parses a YAML spec file
func LoadSpec(path string) (*Spec, error) {
	// #nosec G304 — path from CLI flag, not user-controlled
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading spec file: %w", err)
	}
	return ParseSpec(data)
}

// ParseSpec parses YAML bytes into a Spec
func ParseSpec(data []byte) (*Spec, error) {
	var spec Spec
	if err := yaml.Unmarshal(data, &spec); err != nil {
		return nil, fmt.Errorf("parsing spec YAML: %w", err)
	}
	if err := ValidateSpec(&spec); err != nil {
		return nil, err
	}
	return &spec, nil
}

// ValidateSpec checks for structural validity
func ValidateSpec(spec *Spec) error {
	if spec.Version != 1 {
		return fmt.Errorf("unsupported spec version: %d (expected 1)", spec.Version)
	}
	if spec.Site == "" {
		return fmt.Errorf("spec must have a site name")
	}
	if err := validateNetworks(spec.Networks); err != nil {
		return err
	}
	if err := validateVPNs(spec.VPN); err != nil {
		return err
	}
	probeNames, err := validateProbes(spec.Probes)
	if err != nil {
		return err
	}
	if err := validatePolicies(spec.Policies); err != nil {
		return err
	}
	if err := validateInventory(spec.Inventory); err != nil {
		return err
	}
	return validateAssertions(spec.Assertions, probeNames)
}

func validateNetworks(networks []Network) error {
	names := make(map[string]bool)
	for i, n := range networks {
		if n.Name == "" {
			return fmt.Errorf("network[%d]: name is required", i)
		}
		if names[n.Name] {
			return fmt.Errorf("network[%d]: duplicate name %q", i, n.Name)
		}
		names[n.Name] = true
		if _, _, err := net.ParseCIDR(n.CIDR); err != nil {
			return fmt.Errorf("network %q: invalid CIDR %q: %w", n.Name, n.CIDR, err)
		}
		if n.Gateway != "" && net.ParseIP(n.Gateway) == nil {
			return fmt.Errorf("network %q: invalid gateway IP %q", n.Name, n.Gateway)
		}
	}
	return nil
}

func validateVPNs(vpns []VPNConfig) error {
	for i, v := range vpns {
		if v.Name == "" {
			return fmt.Errorf("vpn[%d]: name is required", i)
		}
		if v.Type == "" {
			return fmt.Errorf("vpn %q: type is required", v.Name)
		}
	}
	return nil
}

// validateProbes returns the set of declared probe names so assertion
// runner references can be checked against it.
func validateProbes(probes []Probe) (map[string]bool, error) {
	names := make(map[string]bool)
	for i, p := range probes {
		if p.Name == "" {
			return nil, fmt.Errorf("probe[%d]: 'name' is required", i)
		}
		if p.Host == "" {
			return nil, fmt.Errorf("probe[%d]: 'host' is required", i)
		}
		if p.User == "" {
			return nil, fmt.Errorf("probe[%d]: 'user' is required", i)
		}
		if p.Port != 0 && (p.Port < 1 || p.Port > 65535) {
			return nil, fmt.Errorf("probe[%d]: 'port' must be 1-65535, got %d", i, p.Port)
		}
		if names[p.Name] {
			return nil, fmt.Errorf("probe[%d]: duplicate probe name %q", i, p.Name)
		}
		names[p.Name] = true
	}
	return names, nil
}

func validatePolicies(policies []Policy) error {
	for i, p := range policies {
		if p.Name == "" {
			return fmt.Errorf("policy[%d]: name is required", i)
		}
		if p.Action != "allow" && p.Action != "deny" {
			return fmt.Errorf("policy %q: action must be 'allow' or 'deny'", p.Name)
		}
	}
	return nil
}

func validateInventory(inv *Inventory) error {
	if inv == nil {
		return nil
	}
	validDeviceTypes := map[string]bool{"gateway": true, "switch": true, "ap": true}
	for i, d := range inv.Devices {
		if d.Name == "" {
			return fmt.Errorf("inventory.devices[%d]: name is required", i)
		}
		if !validDeviceTypes[d.Type] {
			return fmt.Errorf("inventory.devices[%d]: type must be gateway, switch, or ap (got %q)", i, d.Type)
		}
	}
	for i, s := range inv.ACLScopes {
		if s.Scope != "gateway" && s.Scope != "switch" {
			return fmt.Errorf("inventory.acl_scopes[%d]: scope must be 'gateway' or 'switch' (got %q)", i, s.Scope)
		}
	}
	return nil
}

// assertionValidators maps each supported assertion type to its field
// requirements. Every entry must stay in sync with validAssertionTypes.
var assertionValidators = map[string]func(int, *Assertion) error{
	"subnet_discovery": validateSubnetDiscoveryAssertion,
	"isolation":        validateIsolationAssertion,
	"vpn_route":        validateVPNRouteAssertion,
	"route_check":      validateRouteCheckAssertion,
	"port_check":       validatePortCheckAssertion,
	"dns_check":        validateDNSCheckAssertion,
	"network_health":   validateNetworkHealthAssertion,
	"acl_check":        validateACLCheckAssertion,
}

func validateSubnetDiscoveryAssertion(i int, a *Assertion) error {
	if a.Network == "" {
		return fmt.Errorf("assertion[%d] (subnet_discovery): network is required", i)
	}
	if a.ExpectHostsMin != nil && a.ExpectHostsMax != nil && *a.ExpectHostsMin > *a.ExpectHostsMax {
		return fmt.Errorf("assertion[%d] (subnet_discovery): expect_hosts_min must not exceed expect_hosts_max", i)
	}
	return nil
}

func validateIsolationAssertion(i int, a *Assertion) error {
	if a.From == "" {
		return fmt.Errorf("assertion[%d] (isolation): from is required", i)
	}
	if a.To == "" {
		return fmt.Errorf("assertion[%d] (isolation): to is required", i)
	}
	if a.Expect == "" {
		return fmt.Errorf("assertion[%d] (isolation): expect is required (use 'deny' or 'allow')", i)
	}
	return nil
}

func validateVPNRouteAssertion(i int, a *Assertion) error {
	if a.VPN == "" {
		return fmt.Errorf("assertion[%d] (vpn_route): vpn is required", i)
	}
	if a.Target == "" {
		return fmt.Errorf("assertion[%d] (vpn_route): target is required", i)
	}
	return nil
}

func validateRouteCheckAssertion(i int, a *Assertion) error {
	if a.Target == "" {
		return fmt.Errorf("assertion[%d] (route_check): target is required", i)
	}
	return nil
}

func validatePortCheckAssertion(i int, a *Assertion) error {
	if a.Target == "" {
		return fmt.Errorf("assertion[%d]: port_check requires 'target'", i)
	}
	if len(a.Ports) == 0 {
		return fmt.Errorf("assertion[%d]: port_check requires 'ports'", i)
	}
	if a.Expect == "" {
		return fmt.Errorf("assertion[%d]: port_check requires 'expect' (open or closed)", i)
	}
	return nil
}

func validateDNSCheckAssertion(i int, a *Assertion) error {
	if a.Query == "" {
		return fmt.Errorf("assertion[%d]: dns_check requires 'query'", i)
	}
	return nil
}

func validateNetworkHealthAssertion(i int, a *Assertion) error {
	if a.Target == "" {
		return fmt.Errorf("assertion[%d]: network_health requires 'target'", i)
	}
	return nil
}

func validateACLCheckAssertion(i int, a *Assertion) error {
	if a.Provider == "" {
		return fmt.Errorf("assertion[%d]: acl_check requires 'provider'", i)
	}
	if a.Policy == "" {
		return fmt.Errorf("assertion[%d]: acl_check requires 'policy'", i)
	}
	if a.Expect == "" {
		return fmt.Errorf("assertion[%d]: acl_check requires 'expect' (enforced or not_enforced)", i)
	}
	return nil
}

func validateAssertions(assertions []Assertion, probeNames map[string]bool) error {
	for i := range assertions {
		a := &assertions[i]
		validate, known := assertionValidators[a.Type]
		if !known {
			return fmt.Errorf("assertion[%d]: unknown type %q", i, a.Type)
		}
		if err := validate(i, a); err != nil {
			return err
		}
		// Validate runner references a declared probe
		if a.Runner != "" && a.Runner != "local" && !probeNames[a.Runner] {
			return fmt.Errorf("assertion[%d]: runner %q is not declared in probes", i, a.Runner)
		}
	}
	return nil
}

// NetworkByName finds a network by name
func (s *Spec) NetworkByName(name string) *Network {
	for i := range s.Networks {
		if s.Networks[i].Name == name {
			return &s.Networks[i]
		}
	}
	return nil
}

// VPNByName finds a VPN config by name
func (s *Spec) VPNByName(name string) *VPNConfig {
	for i := range s.VPN {
		if s.VPN[i].Name == name {
			return &s.VPN[i]
		}
	}
	return nil
}

// NetworkByZone finds all networks in a zone
func (s *Spec) NetworkByZone(zone string) []Network {
	var result []Network
	for _, n := range s.Networks {
		if n.Zone == zone {
			result = append(result, n)
		}
	}
	return result
}

// ProbeByName finds a declared probe by name, or returns nil.
func (s *Spec) ProbeByName(name string) *Probe {
	for i := range s.Probes {
		if s.Probes[i].Name == name {
			return &s.Probes[i]
		}
	}
	return nil
}
