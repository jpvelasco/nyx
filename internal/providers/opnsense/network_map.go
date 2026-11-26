package opnsense

import (
	"context"
	"net/netip"

	"github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/topology"
)

func (*Provider) ObserveNetwork(ctx context.Context, opts providers.ImportOptions) (topology.ObservationSet, error) {
	var facts topology.ObservationSet
	if err := requireAuth(opts); err != nil {
		return facts, err
	}
	client := newProviderClient(opts)
	vlans, verr := client.GetVLANs(ctx)
	ifaces, ierr := client.GetInterfaces(ctx)
	if verr != nil && ierr != nil {
		return facts, ierr
	}
	if verr != nil {
		facts.Gaps = append(facts.Gaps, "VLAN settings")
	}
	if ierr != nil {
		facts.Gaps = append(facts.Gaps, "interface inventory")
	}
	firewall := topology.ResourceRef{Kind: "gateway", Key: "firewall"}
	facts.Resources = append(facts.Resources, topology.Observation{Ref: firewall})
	tags := make(map[string]int)
	conflicted := make(map[string]bool)
	for _, v := range vlans {
		if v.Device != "" {
			if previous, ok := tags[v.Device]; ok && previous != v.Tag {
				conflicted[v.Device] = true
				facts.Gaps = append(facts.Gaps, "VLAN device identity")
			}
			tags[v.Device] = v.Tag
		}
	}
	for _, iface := range ifaces {
		ref := topology.ResourceRef{Kind: "interface", Key: iface.Name}
		r := topology.Observation{Ref: ref, Name: iface.Description, VLAN: tags[iface.Device], Device: iface.Device}
		if conflicted[iface.Device] {
			r.VLAN = 0
			r.Device = ""
		}
		if _, vlanDevice := tags[iface.Device]; !vlanDevice && (iface.LinkType == "ether" || iface.LinkType == "ethernet") {
			r.MAC = iface.MAC
		}
		if ip, err := netip.ParseAddr(iface.IP); err == nil && !ip.IsUnspecified() && iface.Subnet > 0 && iface.Enabled {
			if p := netip.PrefixFrom(ip, iface.Subnet); p.IsValid() {
				r.GatewayPrefix = p.String()
			}
		}
		facts.Resources = append(facts.Resources, r)
		facts.Links = append(facts.Links, topology.LinkObservation{From: ref, To: topology.MapTarget{Ref: firewall}, Relation: "device", Evidence: "firewall interface inventory"})
	}
	for _, v := range vlans {
		ref := topology.ResourceRef{Kind: "segment", Key: v.UUID}
		facts.Resources = append(facts.Resources, topology.Observation{Ref: ref, Name: v.Description, VLAN: v.Tag})
		facts.Links = append(facts.Links, topology.LinkObservation{From: ref, To: topology.MapTarget{AddressedDevice: v.Device}, Relation: "gateway", Evidence: "addressed VLAN interface"})
	}
	return facts, ctx.Err()
}
