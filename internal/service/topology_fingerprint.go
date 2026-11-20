package service

import (
	"context"
	"net/netip"

	omadabackend "github.com/jpvelasco/nyx/internal/backends/omada"
	"github.com/jpvelasco/nyx/internal/topology"
)

type omadaFingerprintFacts struct {
	segments         []topology.SegmentObservation
	gatewayAddresses []string
	ruleCount        *int
	warnings         []string
}

func readOmadaFingerprint(ctx context.Context, client *omadabackend.Client, siteID string, devices []omadabackend.Device) *omadaFingerprintFacts {
	facts := &omadaFingerprintFacts{}
	if networks, err := client.GetNetworks(ctx, siteID); err == nil {
		for _, network := range networks {
			segment := topology.SegmentObservation{VLAN: network.VLANID, Provider: topology.ProviderOmada}
			if network.Gateway() != "" && omadabackend.GatewayForNetwork(devices, networks, network.ID) != nil {
				segment.Serves = true
				facts.gatewayAddresses = append(facts.gatewayAddresses, network.Gateway())
			}
			facts.segments = append(facts.segments, segment)
		}
	} else {
		facts.warnings = append(facts.warnings, "Omada segment and gateway observations unavailable")
	}
	gateway, gatewayErr := client.FetchACLs(ctx, siteID, omadabackend.ACLTypeGateway)
	switchRules, switchErr := client.FetchACLs(ctx, siteID, omadabackend.ACLTypeSwitch)
	if gatewayErr == nil && switchErr == nil {
		count := len(gateway.Rules) + len(switchRules.Rules)
		facts.ruleCount = &count
	} else {
		facts.warnings = append(facts.warnings, "Omada ACL counts unavailable")
	}
	return facts
}

func (s *TopologyService) fingerprint(ctx context.Context, opts TopologyOptions, report *TopologyReport, ifaces []OpnsenseInterface) *topology.Fingerprint {
	fingerprint := &topology.Fingerprint{Devices: []topology.FingerprintDevice{}}
	var omada *omadaFingerprintFacts
	var segments []topology.SegmentObservation
	if report.Omada != nil {
		omada = report.Omada.fingerprint
		segments = append(segments, omada.segments...)
		fingerprint.Warnings = append(fingerprint.Warnings, omada.warnings...)
	}
	for _, device := range report.Devices {
		if device.Provider == topology.ProviderOmada {
			role, where := topology.FingerprintRole(device, len(omada.gatewayAddresses) > 0, false, report.Omada.HasManagedGateway)
			fingerprint.Devices = append(fingerprint.Devices, topology.FingerprintDevice{Provider: device.Provider, Role: role, WhereToLook: where, EnforcementRules: omada.ruleCount})
			continue
		}
		segments = append(segments, s.appendOpnsenseFingerprint(ctx, *opts.Opnsense, report, device, ifaces, fingerprint)...)
	}
	merged, coverage := topology.MergeSegments(segments)
	fingerprint.Segments = merged
	fingerprint.Warnings = append(fingerprint.Warnings, coverage...)
	fingerprint.Edge = topology.SelectEdge(fingerprint.Devices, map[string]string{
		topology.ProviderOpnsense: topology.ClassifyNextHop(interfaceGateways(ifaces)),
	})
	return fingerprint
}

// appendOpnsenseFingerprint adds the OPNsense device row and returns its
// VLAN observations for the cross-provider segment merge.
func (s *TopologyService) appendOpnsenseFingerprint(ctx context.Context, opts OpnsenseOptions, report *TopologyReport, device topology.DeviceReport, ifaces []OpnsenseInterface, fingerprint *topology.Fingerprint) []topology.SegmentObservation {
	row := topology.FingerprintDevice{Provider: device.Provider, InterfaceCount: len(ifaces)}
	if report.Omada != nil {
		upstream := interfaceGateways(ifaces)
		if addrsOverlap(report.Omada.gatewayIPs, upstream) || addrsOverlap(report.Omada.fingerprint.gatewayAddresses, upstream) {
			row.ManagedUpstream = topology.ProviderOmada
			device.OnPath = false
		}
	}
	if ifaces == nil {
		fingerprint.Warnings = append(fingerprint.Warnings, "OPNsense interface observations unavailable")
	}
	bridges, err := s.Opnsense.ListBridges(ctx, opts)
	if err == nil {
		count := len(bridges)
		row.BridgeCount = &count
	} else {
		fingerprint.Warnings = append(fingerprint.Warnings, "OPNsense bridge inventory unavailable")
	}
	if rules, err := s.Opnsense.ListFirewallRules(ctx, opts); err == nil {
		count := len(rules)
		row.EnforcementRules = &count
	} else {
		fingerprint.Warnings = append(fingerprint.Warnings, "OPNsense firewall rule count unavailable")
	}
	vlans, err := s.Opnsense.ListVLANs(ctx, opts)
	if err != nil {
		fingerprint.Warnings = append(fingerprint.Warnings, "OPNsense VLAN inventory unavailable")
	}
	addressed := make(map[string]bool, len(ifaces))
	for _, iface := range ifaces {
		if ip, err := netip.ParseAddr(iface.IP); err == nil && !ip.IsUnspecified() {
			addressed[iface.Device] = true
		}
	}
	serving, bridge := false, false
	segments := make([]topology.SegmentObservation, 0, len(vlans))
	for _, vlan := range vlans {
		segment := topology.SegmentObservation{VLAN: vlan.Tag, Provider: topology.ProviderOpnsense}
		if vlan.Device != "" && addressed[vlan.Device] {
			segment.Serves = true
			serving = true
		}
		segments = append(segments, segment)
	}
	for _, entry := range bridges {
		bridge = bridge || len(entry.Members) >= 2
	}
	nat := report.Opnsense
	confirmedNAT := nat.OutboundNatMode == topology.NatModeAutomatic || nat.OutboundNatMode == topology.NatModeHybrid || len(nat.SourceNatRules) > 0
	row.Role, row.WhereToLook = topology.FingerprintRole(device, serving, bridge, confirmedNAT)
	fingerprint.Devices = append(fingerprint.Devices, row)
	return segments
}
