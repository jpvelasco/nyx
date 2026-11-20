package service

import (
	"context"
	"fmt"
	"net/netip"

	omadabackend "github.com/jpvelasco/nyx/internal/backends/omada"
	"github.com/jpvelasco/nyx/internal/topology"
)

// probeCandidateLimit caps the probe candidates listed per segment.
const probeCandidateLimit = 5

type omadaFingerprintFacts struct {
	segments         []topology.SegmentObservation
	subnets          []topology.SegmentSubnet
	hosts            []topology.HostSighting
	gatewayAddresses []string
	ruleCount        *int
	warnings         []string
}

func readOmadaFingerprint(ctx context.Context, client *omadabackend.Client, siteID string, devices []omadabackend.Device, detail bool) *omadaFingerprintFacts {
	facts := &omadaFingerprintFacts{}
	networks, err := client.GetNetworks(ctx, siteID)
	if err == nil {
		for _, network := range networks {
			if network.GatewaySubnet != "" {
				facts.subnets = append(facts.subnets, topology.SegmentSubnet{VLAN: network.VLANID, Provider: topology.ProviderOmada, Gateway: network.GatewaySubnet})
			}
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
	if detail {
		facts.readHosts(ctx, client, siteID, networks)
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

// readHosts records connected-client addresses as probe-candidate
// sightings. Network enrichment is best-effort, as in ListClients.
func (f *omadaFingerprintFacts) readHosts(ctx context.Context, client *omadabackend.Client, siteID string, networks []omadabackend.Network) {
	clients, err := client.GetClients(ctx, siteID)
	if err != nil {
		f.warnings = append(f.warnings, "Omada client inventory unavailable; probe candidates incomplete")
		return
	}
	_ = client.EnrichFromDHCP(ctx, siteID, clients, networks)
	for _, c := range clients {
		f.hosts = append(f.hosts, topology.HostSighting{Address: c.IP, Hostname: c.Name, Source: topology.ProviderOmada})
	}
}

func (s *TopologyService) fingerprint(ctx context.Context, opts TopologyOptions, report *TopologyReport, ifaces []OpnsenseInterface) *topology.Fingerprint {
	fingerprint := &topology.Fingerprint{Devices: []topology.FingerprintDevice{}}
	var omada *omadaFingerprintFacts
	var segments []topology.SegmentObservation
	var subnets []topology.SegmentSubnet
	var hosts []topology.HostSighting
	if report.Omada != nil {
		omada = report.Omada.fingerprint
		segments = append(segments, omada.segments...)
		subnets = append(subnets, omada.subnets...)
		hosts = append(hosts, omada.hosts...)
		fingerprint.Warnings = append(fingerprint.Warnings, omada.warnings...)
	}
	for _, device := range report.Devices {
		if device.Provider == topology.ProviderOmada {
			role, where := topology.FingerprintRole(device, len(omada.gatewayAddresses) > 0, false, report.Omada.HasManagedGateway)
			fingerprint.Devices = append(fingerprint.Devices, topology.FingerprintDevice{Provider: device.Provider, Role: role, WhereToLook: where, EnforcementRules: omada.ruleCount})
			continue
		}
		opnsense := s.appendOpnsenseFingerprint(ctx, *opts.Opnsense, report, device, ifaces, fingerprint)
		segments = append(segments, opnsense.segments...)
		subnets = append(subnets, opnsense.subnets...)
	}
	merged, coverage := topology.MergeSegments(segments)
	fingerprint.Segments = merged
	if opts.fingerprintScope() == fingerprintDetail {
		hosts = append(hosts, s.opnsenseHostSightings(ctx, opts.Opnsense, fingerprint)...)
		fingerprint.Segments = topology.AttachDetail(merged, subnets, hosts, probeCandidateLimit)
	}
	fingerprint.Warnings = append(fingerprint.Warnings, coverage...)
	fingerprint.Edge = topology.SelectEdge(fingerprint.Devices, map[string]string{
		topology.ProviderOpnsense: topology.ClassifyNextHop(interfaceGateways(ifaces)),
	})
	return fingerprint
}

// opnsenseHostSightings records DHCP lease addresses as probe-candidate
// sightings. It is a no-op when OPNsense is not observed.
func (s *TopologyService) opnsenseHostSightings(ctx context.Context, opts *OpnsenseOptions, fingerprint *topology.Fingerprint) []topology.HostSighting {
	if opts == nil {
		return nil
	}
	leases, err := s.Opnsense.ListClients(ctx, *opts)
	if err != nil {
		fingerprint.Warnings = append(fingerprint.Warnings, "OPNsense DHCP leases unavailable; probe candidates incomplete")
		return nil
	}
	hosts := make([]topology.HostSighting, 0, len(leases))
	for _, l := range leases {
		hosts = append(hosts, topology.HostSighting{Address: l.IP, Hostname: l.Hostname, Source: topology.ProviderOpnsense})
	}
	return hosts
}

// opnsenseFingerprintFacts is what the OPNsense device row contributes to
// the cross-provider segment merge.
type opnsenseFingerprintFacts struct {
	segments []topology.SegmentObservation
	subnets  []topology.SegmentSubnet
}

// appendOpnsenseFingerprint adds the OPNsense device row and returns its
// VLAN observations and gateway subnets for the segment merge.
func (s *TopologyService) appendOpnsenseFingerprint(ctx context.Context, opts OpnsenseOptions, report *TopologyReport, device topology.DeviceReport, ifaces []OpnsenseInterface, fingerprint *topology.Fingerprint) opnsenseFingerprintFacts {
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
	addressed := make(map[string]OpnsenseInterface, len(ifaces))
	for _, iface := range ifaces {
		if ip, err := netip.ParseAddr(iface.IP); err == nil && !ip.IsUnspecified() {
			addressed[iface.Device] = iface
		}
	}
	serving, bridge := false, false
	facts := opnsenseFingerprintFacts{segments: make([]topology.SegmentObservation, 0, len(vlans))}
	for _, vlan := range vlans {
		segment := topology.SegmentObservation{VLAN: vlan.Tag, Provider: topology.ProviderOpnsense}
		if iface, ok := addressed[vlan.Device]; ok && vlan.Device != "" {
			segment.Serves = true
			serving = true
			if iface.Subnet > 0 {
				facts.subnets = append(facts.subnets, topology.SegmentSubnet{VLAN: vlan.Tag, Provider: topology.ProviderOpnsense, Gateway: fmt.Sprintf("%s/%d", iface.IP, iface.Subnet)})
			}
		}
		facts.segments = append(facts.segments, segment)
	}
	for _, entry := range bridges {
		bridge = bridge || len(entry.Members) >= 2
	}
	nat := report.Opnsense
	confirmedNAT := nat.OutboundNatMode == topology.NatModeAutomatic || nat.OutboundNatMode == topology.NatModeHybrid || len(nat.SourceNatRules) > 0
	row.Role, row.WhereToLook = topology.FingerprintRole(device, serving, bridge, confirmedNAT)
	fingerprint.Devices = append(fingerprint.Devices, row)
	return facts
}
