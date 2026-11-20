package service

import (
	"net/netip"
	"strings"

	omadabackend "github.com/jpvelasco/nyx/internal/backends/omada"
	"github.com/jpvelasco/nyx/internal/topology"
)

// omadaMatrixRules resolves enabled Omada ACLs to segment endpoints via
// network ID -> VLAN. Gateway rules count only when they apply LAN-to-LAN;
// switch rules carry no direction and always apply between networks.
func omadaMatrixRules(networks []omadabackend.Network, gatewayRules, switchRules []omadabackend.ACLRule) []topology.ObservedRule {
	vlanByID := make(map[string]int, len(networks))
	for _, n := range networks {
		vlanByID[n.ID] = n.VLANID
	}
	var out []topology.ObservedRule
	add := func(r omadabackend.ACLRule) {
		if !r.Status {
			return
		}
		out = append(out, topology.ObservedRule{
			Provider:    topology.ProviderOmada,
			Allow:       r.Policy == omadabackend.ACLPolicyPermit,
			Source:      omadaEndpoint(r.SourceType, r.SourceIDs, vlanByID),
			Destination: omadaEndpoint(r.DestType, r.DestIDs, vlanByID),
		})
	}
	for _, r := range gatewayRules {
		if r.Direction.LANToLAN {
			add(r)
		}
	}
	for _, r := range switchRules {
		add(r)
	}
	return out
}

// omadaEndpoint maps network endpoints to VLANs. Any other endpoint kind
// (IP group, port group), an empty ID list, or an unknown network ID maps
// to no segment.
func omadaEndpoint(kind omadabackend.EndpointKind, ids []string, vlanByID map[string]int) topology.EndpointSet {
	if kind != omadabackend.EndpointNetwork || len(ids) == 0 {
		return topology.EndpointSet{Unresolved: true}
	}
	vlans := make([]int, 0, len(ids))
	for _, id := range ids {
		vlan, ok := vlanByID[id]
		if !ok {
			return topology.EndpointSet{Unresolved: true}
		}
		vlans = append(vlans, vlan)
	}
	return topology.EndpointSet{VLANs: vlans}
}

// opnsenseMatrixRules resolves enabled OPNsense filter rules to segment
// endpoints. An interface net macro maps through interface -> device ->
// VLAN; a CIDR maps when it equals a segment subnet; "any" is a wildcard,
// except as the source of a single-interface rule, where it means the
// traffic entering that interface's segment. Aliases, hosts, interface
// addresses ("opt1ip"), and untagged interfaces map to no segment.
func opnsenseMatrixRules(rules []OpnsenseFirewallRule, ifaces []OpnsenseInterface, vlans []OpnsenseVLAN, subnets []topology.SegmentSubnet) []topology.ObservedRule {
	r := newOpnsenseResolver(ifaces, vlans, subnets)
	var out []topology.ObservedRule
	for _, rule := range rules {
		if !rule.Enabled || rule.Disabled {
			continue
		}
		source := r.endpoint(rule.Source)
		if source.Any && len(rule.Interfaces) == 1 {
			if vlan, ok := r.vlanByIface[rule.Interfaces[0]]; ok {
				source = topology.EndpointSet{VLANs: []int{vlan}}
			}
		}
		out = append(out, topology.ObservedRule{
			Provider:    topology.ProviderOpnsense,
			Allow:       rule.Action == "pass",
			Source:      source,
			Destination: r.endpoint(rule.Destination),
		})
	}
	return out
}

type opnsenseResolver struct {
	vlanByIface map[string]int
	vlanByCIDR  map[netip.Prefix]int
}

func newOpnsenseResolver(ifaces []OpnsenseInterface, vlans []OpnsenseVLAN, subnets []topology.SegmentSubnet) opnsenseResolver {
	tagByDevice := make(map[string]int, len(vlans))
	for _, v := range vlans {
		if v.Device != "" {
			tagByDevice[v.Device] = v.Tag
		}
	}
	r := opnsenseResolver{vlanByIface: map[string]int{}, vlanByCIDR: map[netip.Prefix]int{}}
	for _, i := range ifaces {
		if tag, ok := tagByDevice[i.Device]; ok {
			r.vlanByIface[i.Name] = tag
		}
	}
	for _, s := range subnets {
		if prefix, err := netip.ParsePrefix(s.Gateway); err == nil {
			r.vlanByCIDR[prefix.Masked()] = s.VLAN
		}
	}
	return r
}

func (r opnsenseResolver) endpoint(value string) topology.EndpointSet {
	value = strings.TrimSpace(value)
	if value == "" || strings.EqualFold(value, "any") {
		return topology.EndpointSet{Any: true}
	}
	if vlan, ok := r.vlanByIface[value]; ok {
		return topology.EndpointSet{VLANs: []int{vlan}}
	}
	if prefix, err := netip.ParsePrefix(value); err == nil {
		if vlan, ok := r.vlanByCIDR[prefix.Masked()]; ok && prefix == prefix.Masked() {
			return topology.EndpointSet{VLANs: []int{vlan}}
		}
	}
	return topology.EndpointSet{Unresolved: true}
}
