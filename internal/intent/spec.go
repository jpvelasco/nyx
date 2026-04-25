package intent

import (
	"fmt"
	"net"
	"os"

	"gopkg.in/yaml.v3"
)

// Spec is the top-level intent file
type Spec struct {
	Version    int          `yaml:"version" json:"version"`
	Site       string       `yaml:"site" json:"site"`
	Networks   []Network    `yaml:"networks" json:"networks"`
	VPN        []VPNConfig  `yaml:"vpn" json:"vpn"`
	Policies   []Policy     `yaml:"policies" json:"policies"`
	Assertions []Assertion  `yaml:"assertions" json:"assertions"`
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
	Type           string `yaml:"type" json:"type"`
	Network        string `yaml:"network,omitempty" json:"network,omitempty"`
	From           string `yaml:"from,omitempty" json:"from,omitempty"`
	To             string `yaml:"to,omitempty" json:"to,omitempty"`
	VPN            string `yaml:"vpn,omitempty" json:"vpn,omitempty"`
	Target         string `yaml:"target,omitempty" json:"target,omitempty"`
	ExpectHostsMin *int   `yaml:"expect_hosts_min,omitempty" json:"expect_hosts_min,omitempty"`
	ExpectHostsMax *int   `yaml:"expect_hosts_max,omitempty" json:"expect_hosts_max,omitempty"`
	ExpectDeny     string `yaml:"expect,omitempty" json:"expect,omitempty"`
	ExpectTunnel   *bool  `yaml:"expect_tunnel,omitempty" json:"expect_tunnel,omitempty"`
	Ports          []int  `yaml:"ports,omitempty" json:"ports,omitempty"`
	// ScanTiming sets the nmap -T flag for subnet_discovery assertions (0-5).
	// Defaults to 4 if unset.
	ScanTiming int `yaml:"scan_timing,omitempty" json:"scan_timing,omitempty"`
	// ScanMinRate sets --min-rate for subnet_discovery assertions.
	// Defaults to 500 if unset.
	ScanMinRate int `yaml:"scan_min_rate,omitempty" json:"scan_min_rate,omitempty"`
}

// LoadSpec reads and parses a YAML spec file
func LoadSpec(path string) (*Spec, error) {
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
	// Validate networks
	names := make(map[string]bool)
	for i, n := range spec.Networks {
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
	// Validate VPN configs
	for i, v := range spec.VPN {
		if v.Name == "" {
			return fmt.Errorf("vpn[%d]: name is required", i)
		}
		if v.Type == "" {
			return fmt.Errorf("vpn %q: type is required", v.Name)
		}
	}
	// Validate policies
	for i, p := range spec.Policies {
		if p.Name == "" {
			return fmt.Errorf("policy[%d]: name is required", i)
		}
		if p.Action != "allow" && p.Action != "deny" {
			return fmt.Errorf("policy %q: action must be 'allow' or 'deny'", p.Name)
		}
	}
	// Validate assertions
	validTypes := map[string]bool{
		"subnet_discovery": true,
		"isolation":        true,
		"vpn_route":        true,
		"route_check":      true,
	}
	for i, a := range spec.Assertions {
		if !validTypes[a.Type] {
			return fmt.Errorf("assertion[%d]: unknown type %q", i, a.Type)
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
