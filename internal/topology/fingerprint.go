package topology

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// Fingerprint classifies the observed provider roles and the configured
// segments. Addresses are matched by the service and never enter the report.
type Fingerprint struct {
	Edge     *FingerprintEdge     `json:"edge,omitempty"`
	Devices  []FingerprintDevice  `json:"devices"`
	Segments []FingerprintSegment `json:"segments,omitempty"`
	Warnings []string             `json:"warnings,omitempty"`
}

// FingerprintDevice contains only provider roles and aggregate evidence.
type FingerprintDevice struct {
	Provider         string `json:"provider"`
	Role             string `json:"role"`
	ManagedUpstream  string `json:"managed_upstream,omitempty"`
	InterfaceCount   int    `json:"interface_count,omitempty"`
	BridgeCount      *int   `json:"bridge_count,omitempty"`
	EnforcementRules *int   `json:"enforcement_rules,omitempty"`
	WhereToLook      string `json:"where_to_look,omitempty"`
}

// FingerprintSegment identifies a VLAN by its configured VLAN ID, the
// provider serving its gateway, and every provider that observed it.
type FingerprintSegment struct {
	VLAN       int      `json:"vlan"`
	Gateway    string   `json:"gateway,omitempty"`
	ObservedBy []string `json:"observed_by,omitempty"`
	// Detail carries private addressing, attached only on operator request.
	Detail *SegmentDetail `json:"detail,omitempty"`
}

// SegmentObservation is one provider's sighting of a VLAN. Serves is true
// when that provider holds the VLAN's L3 gateway.
type SegmentObservation struct {
	VLAN     int
	Provider string
	Serves   bool
}

// FingerprintEdge names the provider where the default route leaves the
// configured providers, and what its next hop looks like.
type FingerprintEdge struct {
	Provider string `json:"provider,omitempty"`
	NextHop  string `json:"next_hop"`
}

// Next-hop classifications for the edge provider's default route.
const (
	// NextHopInternet: a public or carrier-grade NAT next hop; this
	// provider is the network edge.
	NextHopInternet = "internet"
	// NextHopUpstreamRouter: a private next hop nyx does not manage; the
	// network continues past this provider.
	NextHopUpstreamRouter = "upstream_router"
	// NextHopUnknown: no classifiable next hop was observed.
	NextHopUnknown = "unknown"
)

var carrierGradeNAT = netip.MustParsePrefix("100.64.0.0/10")

// FingerprintRole derives an architecture role without interpreting the
// absence of an observed upstream as proof that a provider is the edge.
func FingerprintRole(d DeviceReport, servingSegments bool, hasBridge bool, confirmedSourceNAT bool) (role, where string) {
	switch {
	case d.OnPath && d.Role == RoleNatRouter && servingSegments && confirmedSourceNAT:
		return "enforcer", "Inspect configured firewall rules, ACLs, and egress drops."
	case d.Role == RoleBridge && hasBridge:
		return "observer", "Inspect bridge members for a passive observation point."
	default:
		return "unknown", ""
	}
}

// MergeSegments folds per-provider observations into one segment per VLAN,
// sorted by VLAN ID, and warns where visibility ends: a VLAN no inventory
// serves, or one whose gateway two providers both claim.
func MergeSegments(observations []SegmentObservation) ([]FingerprintSegment, []string) {
	byVLAN := map[int]*segmentSighting{}
	for _, o := range observations {
		s := byVLAN[o.VLAN]
		if s == nil {
			s = &segmentSighting{}
			byVLAN[o.VLAN] = s
		}
		s.add(o)
	}
	vlans := make([]int, 0, len(byVLAN))
	for vlan := range byVLAN {
		vlans = append(vlans, vlan)
	}
	slices.Sort(vlans)

	segments := make([]FingerprintSegment, 0, len(vlans))
	var warnings []string
	for _, vlan := range vlans {
		s := byVLAN[vlan]
		segment := FingerprintSegment{VLAN: vlan, ObservedBy: s.observedBy}
		switch len(s.servedBy) {
		case 0:
			warnings = append(warnings, fmt.Sprintf("VLAN %d observed by %s; no inventory serves its gateway", vlan, strings.Join(s.observedBy, " and ")))
		case 1:
			segment.Gateway = s.servedBy[0]
		default:
			segment.Gateway = s.servedBy[0]
			warnings = append(warnings, fmt.Sprintf("VLAN %d gateway observed on both %s", vlan, strings.Join(s.servedBy, " and ")))
		}
		segments = append(segments, segment)
	}
	return segments, warnings
}

// segmentSighting accumulates the sorted, de-duplicated providers that
// observed and served one VLAN.
type segmentSighting struct {
	observedBy []string
	servedBy   []string
}

func (s *segmentSighting) add(o SegmentObservation) {
	s.observedBy = insertSorted(s.observedBy, o.Provider)
	if o.Serves {
		s.servedBy = insertSorted(s.servedBy, o.Provider)
	}
}

func insertSorted(list []string, v string) []string {
	i, found := slices.BinarySearch(list, v)
	if found {
		return list
	}
	return slices.Insert(list, i, v)
}

// ClassifyNextHop classifies default-route next hops without returning
// them: any public or carrier-grade NAT address is the internet; otherwise
// any private address is an unmanaged upstream router. Link-local IPv6
// gateways say nothing about what lies beyond them and are ignored.
func ClassifyNextHop(gateways []string) string {
	result := NextHopUnknown
	for _, g := range gateways {
		addr, err := netip.ParseAddr(strings.TrimSpace(g))
		if err != nil || !addr.IsGlobalUnicast() {
			continue
		}
		if !addr.IsPrivate() || carrierGradeNAT.Contains(addr) {
			return NextHopInternet
		}
		result = NextHopUpstreamRouter
	}
	return result
}

// SelectEdge picks the edge among providers whose default route does not
// point at another configured provider, preferring one with an observed
// next hop. nextHop maps provider to its ClassifyNextHop result; providers
// absent from it are unknown.
func SelectEdge(devices []FingerprintDevice, nextHop map[string]string) *FingerprintEdge {
	var edge *FingerprintEdge
	for _, d := range devices {
		if d.ManagedUpstream != "" {
			continue
		}
		hop := nextHop[d.Provider]
		if hop == "" {
			hop = NextHopUnknown
		}
		if edge == nil || (edge.NextHop == NextHopUnknown && hop != NextHopUnknown) {
			edge = &FingerprintEdge{Provider: d.Provider, NextHop: hop}
		}
	}
	if edge == nil {
		return &FingerprintEdge{NextHop: NextHopUnknown}
	}
	return edge
}
