package omadaprovider

import (
	"context"
	"strconv"

	backend "github.com/jpvelasco/nyx/internal/backends/omada"
	"github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/topology"
)

// mapCollection preserves successful collections if a different endpoint is
// unavailable on this controller version, model or API role.
func mapCollection[T any](facts *topology.ObservationSet, label string, rows []T, err error) []T {
	if err != nil {
		facts.Gaps = append(facts.Gaps, label)
		return nil
	}
	return rows
}
func mapPort(mac string, port int) topology.ResourceRef {
	if mac == "" || port <= 0 {
		return topology.ResourceRef{}
	}
	return topology.ResourceRef{Kind: "port", Key: backend.NormalizeMAC(mac) + "/" + strconv.Itoa(port)}
}
func mapSegment(id string) topology.ResourceRef {
	return topology.ResourceRef{Kind: "segment", Key: id}
}

func (*OmadaProvider) ObserveNetwork(ctx context.Context, opts providers.ImportOptions) (topology.ObservationSet, error) {
	var facts topology.ObservationSet
	client, site, err := openACLSite(ctx, opts)
	if err != nil {
		return facts, err
	}
	defer client.Logout(ctx) //nolint:errcheck
	facts.ControllerSite = site.Name
	siteID := site.EffectiveID()
	observeMapDevices(ctx, client, siteID, &facts)
	observeMapSegments(ctx, client, siteID, &facts)
	observeMapPorts(ctx, client, siteID, &facts)
	observeMapSSIDs(ctx, client, siteID, &facts)
	return facts, ctx.Err()
}

func observeMapDevices(ctx context.Context, client *backend.Client, siteID string, facts *topology.ObservationSet) {
	devices, err := client.GetDevices(ctx, siteID)
	devices = mapCollection(facts, "devices", devices, err)
	var aps []string
	for _, d := range devices {
		key := backend.NormalizeMAC(d.MAC)
		if key == "" {
			facts.Gaps = append(facts.Gaps, "device identity")
			continue
		}
		kind := "device"
		switch {
		case d.IsGateway():
			kind = "gateway"
		case d.IsSwitch():
			kind = "switch"
		case d.IsAP():
			kind = "ap"
			aps = append(aps, d.MAC)
		}
		ref := topology.ResourceRef{Kind: kind, Key: key}
		facts.Resources = append(facts.Resources, topology.Observation{Ref: ref, Name: d.Name, MAC: d.MAC})
		if d.IsSwitch() {
			rows, err := client.GetLLDPNeighbors(ctx, siteID, d.MAC)
			for _, n := range mapCollection(facts, "LLDP neighbors", rows, err) {
				facts.Links = append(facts.Links, topology.LinkObservation{From: mapPort(d.MAC, n.Port), Relation: "neighbor", To: topology.MapTarget{MAC: n.Chassis}, Evidence: "LLDP"})
			}
		}
	}
	if len(aps) == 0 {
		return
	}
	rows, err := client.GetUplinkInfo(ctx, siteID, aps)
	up := make(map[string]topology.ResourceRef)
	for _, r := range mapCollection(facts, "AP uplinks", rows, err) {
		port, _ := strconv.Atoi(r.UplinkDevicePort)
		up[backend.NormalizeMAC(r.MAC)] = mapPort(r.UplinkDeviceMAC, port)
	}
	for _, mac := range aps {
		id := backend.NormalizeMAC(mac)
		facts.Links = append(facts.Links, topology.LinkObservation{From: topology.ResourceRef{Kind: "ap", Key: id}, Relation: "uplink", To: topology.MapTarget{Ref: up[id]}, Evidence: "AP uplink inventory"})
	}
}

func observeMapSegments(ctx context.Context, client *backend.Client, siteID string, facts *topology.ObservationSet) {
	networks, err := client.GetNetworks(ctx, siteID)
	for _, n := range mapCollection(facts, "segments", networks, err) {
		ref := mapSegment(n.ID)
		facts.Resources = append(facts.Resources, topology.Observation{Ref: ref, Name: n.Name, VLAN: n.VLANID, GatewayPrefix: n.GatewaySubnet})
		link := topology.LinkObservation{From: ref, Relation: "gateway", Evidence: "configured VLAN and gateway prefix", Inferred: true}
		if n.DeviceMac != "" {
			link.To = topology.MapTarget{Ref: topology.ResourceRef{Kind: "gateway", Key: backend.NormalizeMAC(n.DeviceMac)}}
			link.Evidence = "LAN device binding"
			link.Inferred = false
		} else if n.GatewaySubnet != "" {
			link.To = topology.MapTarget{GatewayPrefix: n.GatewaySubnet, VLAN: n.VLANID}
		}
		facts.Links = append(facts.Links, link)
	}
}

func observeMapSSIDs(ctx context.Context, client *backend.Client, siteID string, facts *topology.ObservationSet) {
	ssids, err := client.GetSSIDs(ctx, siteID)
	for _, s := range mapCollection(facts, "SSIDs", ssids, err) {
		ref := topology.ResourceRef{Kind: "ssid", Key: s.ID}
		facts.Resources = append(facts.Resources, topology.Observation{Ref: ref, Name: s.SSID, VLAN: s.VLANID})
		facts.Links = append(facts.Links, topology.LinkObservation{From: ref, To: topology.MapTarget{VLAN: s.VLANID}, Relation: "segment", Evidence: "SSID VLAN"})
	}
}

func observeMapPorts(ctx context.Context, client *backend.Client, siteID string, facts *topology.ObservationSet) {
	profiles, err := client.GetLanProfiles(ctx, siteID)
	byID := make(map[string]backend.LanProfile, len(profiles))
	for _, p := range mapCollection(facts, "LAN profiles", profiles, err) {
		byID[p.ID] = p
	}
	ports, err := client.GetSwitchPortsOverview(ctx, siteID)
	for _, p := range mapCollection(facts, "switch ports", ports, err) {
		observeMapPort(facts, p, byID[p.ProfileID])
	}
}

func observeMapPort(facts *topology.ObservationSet, p backend.SwitchPort, profile backend.LanProfile) {
	ref := mapPort(p.SwitchMAC, p.Port)
	facts.Resources = append(facts.Resources, topology.Observation{Ref: ref, Name: p.PortName, Port: p.Port, STPDiscarding: p.PortStatus.STPDiscarding})
	sw := topology.ResourceRef{Kind: "switch", Key: backend.NormalizeMAC(p.SwitchMAC)}
	facts.Links = append(facts.Links, topology.LinkObservation{From: ref, To: topology.MapTarget{Ref: sw}, Relation: "device", Evidence: "switch port inventory"})
	native := p.NativeNetworkID
	if native == "" && !p.ProfileOverride {
		native = profile.NativeNetworkID
	}
	target := topology.MapTarget{Ref: mapSegment(native)}
	if native == "" {
		target = topology.MapTarget{VLAN: p.NativeBridgeVLAN}
	}
	facts.Links = append(facts.Links, topology.LinkObservation{From: ref, To: target, Relation: "native", Evidence: "port VLAN configuration"})
	if p.ProfileOverride || profile.ID == "" {
		facts.Gaps = append(facts.Gaps, "effective tagged VLANs")
		facts.Links = append(facts.Links, topology.LinkObservation{From: ref, Relation: "tagged", Evidence: "effective port membership unavailable"})
		return
	}
	for _, tag := range profile.TagNetworkIDs {
		facts.Links = append(facts.Links, topology.LinkObservation{From: ref, To: topology.MapTarget{Ref: mapSegment(tag)}, Relation: "tagged", Evidence: "bound port profile"})
	}
}
