package service

import (
	"context"
	"net/netip"
	"sort"

	omadabackend "github.com/jpvelasco/nyx/internal/backends/omada"
	"github.com/jpvelasco/nyx/internal/topology"
)

type omadaFingerprintFacts struct {
	segments         []topology.FingerprintSegment
	gatewayAddresses []string
	ruleCount        *int
	warnings         []string
}

func readOmadaFingerprint(ctx context.Context, client *omadabackend.Client, siteID string, devices []omadabackend.Device) *omadaFingerprintFacts {
	facts := &omadaFingerprintFacts{}
	if networks, err := client.GetNetworks(ctx, siteID); err == nil {
		for _, network := range networks {
			segment := topology.FingerprintSegment{VLAN: network.VLANID}
			if network.Gateway() != "" && omadabackend.GatewayForNetwork(devices, networks, network.ID) != nil {
				segment.Gateway = topology.ProviderOmada
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
	if report.Omada != nil {
		omada = report.Omada.fingerprint
		fingerprint.Segments = omada.segments
		fingerprint.Warnings = append(fingerprint.Warnings, omada.warnings...)
	}
	for _, device := range report.Devices {
		if device.Provider == topology.ProviderOmada {
			role, where := topology.FingerprintRole(device, len(omada.gatewayAddresses) > 0, false, report.Omada.HasManagedGateway)
			fingerprint.Devices = append(fingerprint.Devices, topology.FingerprintDevice{Provider: device.Provider, Role: role, WhereToLook: where, EnforcementRules: omada.ruleCount})
			continue
		}
		s.appendOpnsenseFingerprint(ctx, *opts.Opnsense, report, device, ifaces, fingerprint)
	}
	sort.Slice(fingerprint.Segments, func(i, j int) bool {
		left, right := fingerprint.Segments[i], fingerprint.Segments[j]
		if left.VLAN == right.VLAN {
			return left.Gateway < right.Gateway
		}
		return left.VLAN < right.VLAN
	})
	return fingerprint
}

func (s *TopologyService) appendOpnsenseFingerprint(ctx context.Context, opts OpnsenseOptions, report *TopologyReport, device topology.DeviceReport, ifaces []OpnsenseInterface, fingerprint *topology.Fingerprint) {
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
	for _, vlan := range vlans {
		segment := topology.FingerprintSegment{VLAN: vlan.Tag}
		if vlan.Device != "" && addressed[vlan.Device] {
			segment.Gateway = topology.ProviderOpnsense
			serving = true
		}
		fingerprint.Segments = append(fingerprint.Segments, segment)
	}
	for _, entry := range bridges {
		bridge = bridge || len(entry.Members) >= 2
	}
	nat := report.Opnsense
	confirmedNAT := nat.OutboundNatMode == topology.NatModeAutomatic || nat.OutboundNatMode == topology.NatModeHybrid || len(nat.SourceNatRules) > 0
	row.Role, row.WhereToLook = topology.FingerprintRole(device, serving, bridge, confirmedNAT)
	fingerprint.Devices = append(fingerprint.Devices, row)
}
