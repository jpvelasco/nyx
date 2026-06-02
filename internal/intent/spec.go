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
	Name string `yaml:"name" json:"name"`
	Host string `yaml:"host" json:"host"`
	User string `yaml:"user" json:"user"`
	Key  string `yaml:"key,omitempty" json:"key,omitempty"`
	VLAN string `yaml:"vlan,omitempty" json:"vlan,omitempty"`
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
	ExpectDeny      string  `yaml:"expect,omitempty" json:"expect,omitempty"`
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
	// Validate probes
	probeNames := make(map[string]bool)
	for i, p := range spec.Probes {
		if p.Name == "" {
			return fmt.Errorf("probe[%d]: 'name' is required", i)
		}
		if p.Host == "" {
			return fmt.Errorf("probe[%d]: 'host' is required", i)
		}
		if p.User == "" {
			return fmt.Errorf("probe[%d]: 'user' is required", i)
		}
		if p.Name != "" {
			if probeNames[p.Name] {
				return fmt.Errorf("probe[%d]: duplicate probe name %q", i, p.Name)
			}
			probeNames[p.Name] = true
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
		"port_check":       true,
		"dns_check":        true,
		"network_health":   true,
		"acl_check":        true,
	}
	for i, a := range spec.Assertions {
		if !validTypes[a.Type] {
			return fmt.Errorf("assertion[%d]: unknown type %q", i, a.Type)
		}
		switch a.Type {
		case "subnet_discovery":
			if a.Network == "" {
				return fmt.Errorf("assertion[%d] (subnet_discovery): network is required", i)
			}
			if a.ExpectHostsMin != nil && a.ExpectHostsMax != nil && *a.ExpectHostsMin > *a.ExpectHostsMax {
				return fmt.Errorf("assertion[%d] (subnet_discovery): expect_hosts_min must not exceed expect_hosts_max", i)
			}
		case "isolation":
			if a.From == "" {
				return fmt.Errorf("assertion[%d] (isolation): from is required", i)
			}
			if a.To == "" {
				return fmt.Errorf("assertion[%d] (isolation): to is required", i)
			}
			if a.ExpectDeny == "" {
				return fmt.Errorf("assertion[%d] (isolation): expect is required (use 'deny' or 'allow')", i)
			}
		case "vpn_route":
			if a.VPN == "" {
				return fmt.Errorf("assertion[%d] (vpn_route): vpn is required", i)
			}
			if a.Target == "" {
				return fmt.Errorf("assertion[%d] (vpn_route): target is required", i)
			}
		case "route_check":
			if a.Target == "" {
				return fmt.Errorf("assertion[%d] (route_check): target is required", i)
			}
		case "port_check":
			if a.Target == "" {
				return fmt.Errorf("assertion[%d]: port_check requires 'target'", i)
			}
			if len(a.Ports) == 0 {
				return fmt.Errorf("assertion[%d]: port_check requires 'ports'", i)
			}
			if a.ExpectDeny == "" {
				return fmt.Errorf("assertion[%d]: port_check requires 'expect' (open or closed)", i)
			}
		case "dns_check":
			if a.Query == "" {
				return fmt.Errorf("assertion[%d]: dns_check requires 'query'", i)
			}
		case "network_health":
			if a.Target == "" {
				return fmt.Errorf("assertion[%d]: network_health requires 'target'", i)
			}
		case "acl_check":
			if a.Provider == "" {
				return fmt.Errorf("assertion[%d]: acl_check requires 'provider'", i)
			}
			if a.Policy == "" {
				return fmt.Errorf("assertion[%d]: acl_check requires 'policy'", i)
			}
			if a.ExpectDeny == "" {
				return fmt.Errorf("assertion[%d]: acl_check requires 'expect' (enforced or not_enforced)", i)
			}
		}
		// Validate runner references a declared probe
		if a.Runner != "" && a.Runner != "local" {
			if !probeNames[a.Runner] {
				return fmt.Errorf("assertion[%d]: runner %q is not declared in probes", i, a.Runner)
			}
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
