package intent

import (
	"fmt"
	"net/netip"
	"strings"
)

// ValidateMDNSLookup binds a single hostname resolution to a declared client
// probe and a known service on the destination network.
func (s *Spec) ValidateMDNSLookup(a Assertion) error {
	host := strings.ToLower(strings.TrimSuffix(a.Query, "."))
	if !strings.HasSuffix(host, ".local") || len(host) <= len(".local") || ValidateTarget(host) != nil {
		return fmt.Errorf("mdns_lookup requires a single known .local hostname")
	}
	addr, err := netip.ParseAddr(a.ExpectIP)
	if err != nil || !addr.IsGlobalUnicast() || addr.Is4In6() {
		return fmt.Errorf("mdns_lookup requires one expected unicast service address")
	}
	src, dst := s.NetworkByName(a.From), s.NetworkByName(a.To)
	p := s.ProbeByName(a.Runner)
	if src == nil || dst == nil || src.Name == dst.Name || p == nil || !s.probeInDirection(p.VLAN, src.Name) || !s.containsDestination(dst.Name, addr) {
		return fmt.Errorf("mdns_lookup requires distinct declared client/service networks, a client-side probe, and a service address in the destination network")
	}
	return nil
}
