package intent

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// ServicePolicy ties two existing assertions to the same directional policy.
// Evaluation uses their results from this audit and issues no additional probes.
type ServicePolicy struct {
	Policy          string `yaml:"policy" json:"policy"`
	Measurement     string `yaml:"measurement" json:"measurement"`
	PositiveControl string `yaml:"positive_control" json:"positive_control"`
	Discovery       string `yaml:"discovery,omitempty" json:"discovery,omitempty"`
}

// ServicePolicyBinding records the assertion indexes and validated test endpoint.
type ServicePolicyBinding struct {
	Policy          Policy
	Measurement     int
	PositiveControl int
	Discovery       *int
	Destination     netip.Addr
	Protocol        string
	Port            int
	Expected        string
}

// BindServicePolicies validates references and preserves declaration order.
func (s *Spec) BindServicePolicies() ([]ServicePolicyBinding, error) {
	indices := map[string]int{}
	for i, a := range s.Assertions {
		if a.Name == "" {
			continue
		}
		if _, found := indices[a.Name]; found {
			return nil, fmt.Errorf("duplicate assertion name %q", a.Name)
		}
		indices[a.Name] = i
	}
	var bindings []ServicePolicyBinding
	for i, decl := range s.ServicePolicies {
		b, err := s.bindServicePolicy(decl, indices)
		if err != nil {
			return nil, fmt.Errorf("service_policies[%d]: %w", i, err)
		}
		bindings = append(bindings, b)
	}
	return bindings, nil
}

func (s *Spec) bindServicePolicy(decl ServicePolicy, indices map[string]int) (ServicePolicyBinding, error) {
	var b ServicePolicyBinding
	for _, p := range s.Policies {
		if p.Name != decl.Policy {
			continue
		}
		if b.Policy.Name != "" {
			return b, fmt.Errorf("ambiguous policy %q", decl.Policy)
		}
		b.Policy = p
	}
	if b.Policy.Name == "" {
		return b, fmt.Errorf("undeclared policy %q", decl.Policy)
	}
	m, ok := indices[decl.Measurement]
	c, controlOk := indices[decl.PositiveControl]
	if !ok || !controlOk || m == c {
		return b, fmt.Errorf("measurement and positive_control must name two distinct assertions")
	}
	a, control := s.Assertions[m], s.Assertions[c]
	b.Measurement, b.PositiveControl = m, c
	source, positive := s.ProbeByName(a.Runner), s.ProbeByName(control.Runner)
	if source == nil || positive == nil || strings.EqualFold(source.Host, positive.Host) && sshPort(source.Port) == sshPort(positive.Port) {
		return b, fmt.Errorf("source and positive control require distinct declared probes")
	}
	if !s.probeInDirection(source.VLAN, b.Policy.From) || !s.probeInDirection(positive.VLAN, b.Policy.To) {
		return b, fmt.Errorf("source and positive control probes must belong to their policy source and destination zones")
	}
	endpoint, err := serviceEndpoint(a)
	if err != nil {
		return b, err
	}
	check, err := serviceEndpoint(control)
	if err != nil {
		return b, err
	}
	if endpoint != check {
		return b, fmt.Errorf("positive control must check the same destination address, service and DNS query as the source")
	}
	if !s.containsDestination(b.Policy.To, endpoint.address) {
		return b, fmt.Errorf("service destination must belong to the policy destination network")
	}
	b.Destination, b.Protocol, b.Port = endpoint.address, endpoint.protocol, endpoint.port
	b.Expected = b.Policy.Action
	for _, exception := range b.Policy.Except {
		if b.Expected != "deny" || exception.Port != b.Port {
			continue
		}
		if exception.Target != "" {
			addr, err := netip.ParseAddr(exception.Target)
			if err != nil {
				return b, fmt.Errorf("policy service exception must use a literal destination")
			}
			if addr != b.Destination {
				continue
			}
		}
		if endpoint.protocol == "dns" && !strings.EqualFold(exception.Protocol, "any") {
			return b, fmt.Errorf("DNS measurement cannot disambiguate a transport-specific firewall exception")
		}
		if strings.EqualFold(exception.Protocol, b.Protocol) || strings.EqualFold(exception.Protocol, "any") {
			b.Expected = "allow"
		}
	}
	if a.Type == "dns_check" && b.Expected != "allow" {
		return b, fmt.Errorf("DNS resolution outcomes can only verify a permitted DNS service")
	}
	if a.Type == "port_check" && (control.Expect != "open" || (a.Expect == "open") != (b.Expected == "allow")) {
		return b, fmt.Errorf("positive control must expect open and source expectation must match the policy")
	}
	if decl.Discovery != "" {
		i, found := indices[decl.Discovery]
		if !found {
			return b, fmt.Errorf("discovery must name a declared mdns_lookup assertion")
		}
		d := s.Assertions[i]
		ip, err := netip.ParseAddr(d.ExpectIP)
		if d.Type != "mdns_lookup" || s.ValidateMDNSLookup(d) != nil || d.Runner != a.Runner || !s.EndpointCovers(b.Policy.From, d.From) || !s.EndpointCovers(b.Policy.To, d.To) || err != nil || ip != b.Destination || b.Expected != "allow" || a.Type != "port_check" {
			return b, fmt.Errorf("discovery must test the allowed service address from its source probe and networks")
		}
		b.Discovery = &i
	}
	return b, nil
}

func sshPort(port int) int {
	if port == 0 {
		return 22
	}
	return port
}

// serviceTarget is comparable so a control cannot accidentally exercise a different service.
type serviceTarget struct {
	address       netip.Addr
	protocol      string
	port          int
	query, answer string
}

func serviceEndpoint(a Assertion) (serviceTarget, error) {
	var e serviceTarget
	target := a.Target
	switch a.Type {
	case "port_check":
		if len(a.Ports) != 1 || a.Ports[0] < 1 || a.Ports[0] > 65535 || (a.Protocol != "" && !strings.EqualFold(a.Protocol, "tcp")) {
			return e, fmt.Errorf("service measurement requires one TCP port")
		}
		e.port = a.Ports[0]
		e.protocol = "tcp"
	case "dns_check":
		if a.Query == "" || a.ExpectIP == "" {
			return e, fmt.Errorf("DNS service measurement requires a query and expected answer")
		}
		target = a.Server
		e.protocol = "dns"
		e.port = 53
		e.query = strings.ToLower(a.Query)
		e.answer = a.ExpectIP
	default:
		return e, fmt.Errorf("service measurement must be a port_check or dns_check")
	}
	addr, err := netip.ParseAddr(target)
	if err != nil || addr.Zone() != "" || !addr.IsGlobalUnicast() || addr.Is4In6() {
		return e, fmt.Errorf("service destination must be one unicast IP address")
	}
	e.address = addr
	return e, nil
}

func (s *Spec) probeInDirection(vlan, direction string) bool {
	if vlan == "" {
		return false
	}
	return slices.ContainsFunc(s.Networks, func(n Network) bool { return (n.Name == vlan || n.Zone == vlan) && s.EndpointCovers(direction, n.Name) })
}
func (s *Spec) containsDestination(direction string, addr netip.Addr) bool {
	return slices.ContainsFunc(s.Networks, func(n Network) bool {
		prefix, err := netip.ParsePrefix(n.CIDR)
		return err == nil && prefix.Contains(addr) && s.EndpointCovers(direction, n.Name)
	})
}
