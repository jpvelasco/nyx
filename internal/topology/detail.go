package topology

import (
	"net/netip"
	"slices"
	"strings"

	"github.com/jpvelasco/nyx/internal/textsafe"
)

// SegmentDetail holds a segment's private addressing. It is attached only
// on operator request (--detail) and never enters the default report.
type SegmentDetail struct {
	CIDR            string           `json:"cidr"`
	GatewayAddress  string           `json:"gateway_address"`
	ProbeCandidates []ProbeCandidate `json:"probe_candidates,omitempty"`
}

// ProbeCandidate is an inventory-known host inside a segment. It is a
// candidate only: nyx does not check that it is reachable.
type ProbeCandidate struct {
	Address  string `json:"address"`
	Hostname string `json:"hostname,omitempty"`
	Source   string `json:"source"`
}

// SegmentSubnet is one provider's view of a VLAN's gateway interface in
// address/prefix form (e.g. "10.0.10.1/24").
type SegmentSubnet struct {
	VLAN     int
	Provider string
	Gateway  string
}

// HostSighting is a host address reported by a provider inventory (Omada
// clients, OPNsense DHCP leases).
type HostSighting struct {
	Address  string
	Hostname string
	Source   string
}

// AttachDetail returns segments with their CIDR, gateway address, and up to
// limit probe candidates attached. The serving provider's subnet wins over
// other views of the same VLAN. Candidates exclude the gateway itself, are
// de-duplicated by address (first sighting wins), and are sorted
// numerically. Segments with no parseable subnet keep a nil Detail.
func AttachDetail(segments []FingerprintSegment, subnets []SegmentSubnet, hosts []HostSighting, limit int) []FingerprintSegment {
	out := slices.Clone(segments)
	for i := range out {
		gateway, ok := segmentGateway(out[i], subnets)
		if !ok {
			continue
		}
		out[i].Detail = &SegmentDetail{
			CIDR:            gateway.Masked().String(),
			GatewayAddress:  gateway.Addr().String(),
			ProbeCandidates: probeCandidates(gateway, hosts, limit),
		}
	}
	return out
}

// segmentGateway picks the serving provider's gateway prefix for the
// segment, falling back to any other provider's parseable view.
func segmentGateway(segment FingerprintSegment, subnets []SegmentSubnet) (netip.Prefix, bool) {
	var fallback netip.Prefix
	for _, s := range subnets {
		if s.VLAN != segment.VLAN {
			continue
		}
		prefix, err := netip.ParsePrefix(strings.TrimSpace(s.Gateway))
		if err != nil {
			continue
		}
		if s.Provider == segment.Gateway {
			return prefix, true
		}
		if !fallback.IsValid() {
			fallback = prefix
		}
	}
	return fallback, fallback.IsValid()
}

func probeCandidates(gateway netip.Prefix, hosts []HostSighting, limit int) []ProbeCandidate {
	network := gateway.Masked()
	seen := map[netip.Addr]bool{gateway.Addr(): true}
	type sighting struct {
		addr      netip.Addr
		candidate ProbeCandidate
	}
	var found []sighting
	for _, h := range hosts {
		addr, err := netip.ParseAddr(strings.TrimSpace(h.Address))
		if err != nil || !network.Contains(addr) || seen[addr] {
			continue
		}
		seen[addr] = true
		// Hostnames are device-chosen (a DHCP client names itself), so
		// strip anything that could drive or spoof the operator's terminal.
		found = append(found, sighting{addr, ProbeCandidate{Address: addr.String(), Hostname: textsafe.Printable(h.Hostname), Source: h.Source}})
	}
	slices.SortFunc(found, func(a, b sighting) int { return a.addr.Compare(b.addr) })
	candidates := make([]ProbeCandidate, 0, min(len(found), limit))
	for _, f := range found[:min(len(found), limit)] {
		candidates = append(candidates, f.candidate)
	}
	if len(candidates) == 0 {
		return nil
	}
	return candidates
}
