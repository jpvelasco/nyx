package service

import (
	"context"

	opnsensebackend "github.com/jpvelasco/nyx/internal/providers/opnsense"
)

// OpnsenseClient is a DHCP lease — OPNsense does not expose live client
// state, so leases are the best host inventory available.
type OpnsenseClient struct {
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
}

// OpnsenseInventory is the firewall's point-in-time observation in a flat,
// agent-friendly shape: system metadata, the interface-derived networks with
// their gateway bindings, one device entry per networked interface, the
// firewall rule count, and the active client (DHCP lease) count. OPNsense
// exposes no managed-device inventory, so model/firmware/upgrade fields are
// intentionally empty.
type OpnsenseInventory struct {
	Host                string                   `json:"host"`
	ControllerVersion   string                   `json:"controller_version,omitempty"`
	Arch                string                   `json:"arch,omitempty"`
	Devices             []serviceDevice          `json:"devices"`
	NetworkGateways     map[string]string        `json:"network_gateways,omitempty"`
	FirewallRuleCount   int                      `json:"firewall_rule_count"`
	FirewallRulesOK     bool                     `json:"firewall_rules_ok"`
	ClientCount         int                      `json:"client_count"`
	Services            []OpnsenseServiceStatus  `json:"services,omitempty"`
	ServicesOK          bool                     `json:"services_ok,omitempty"`
	Gateways            []OpnsenseGatewayStatus  `json:"gateways,omitempty"`
	GatewaysOK          bool                     `json:"gateways_ok,omitempty"`
	Bridges             []OpnsenseBridge         `json:"bridges,omitempty"`
	BridgesOK           bool                     `json:"bridges_ok,omitempty"`
	InterfaceSettings   []OpnsenseIfSetting      `json:"interface_settings,omitempty"`
	InterfaceSettingsOK bool                     `json:"interface_settings_ok,omitempty"`
	Dnsmasq             *OpnsenseDnsmasqSettings `json:"dnsmasq,omitempty"`
	DnsmasqOK           bool                     `json:"dnsmasq_ok,omitempty"`
	Unbound             *OpnsenseUnboundSettings `json:"unbound,omitempty"`
	UnboundOK           bool                     `json:"unbound_ok,omitempty"`
	PfStatistics        *OpnsensePfStatistics    `json:"pf_statistics,omitempty"`
	PfStatisticsOK      bool                     `json:"pf_statistics_ok,omitempty"`
	KernelRoutes        []OpnsenseKernelRoute    `json:"kernel_routes,omitempty"`
	KernelRoutesOK      bool                     `json:"kernel_routes_ok,omitempty"`
	Warnings            []string                 `json:"warnings,omitempty"`
}

// ListClients returns the DHCP leases as the host inventory.
func (s *OpnsenseService) ListClients(ctx context.Context, opts OpnsenseOptions) ([]OpnsenseClient, error) {
	client := s.client(opts)
	leases, err := client.GetDHCPLeases(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]OpnsenseClient, 0, len(leases))
	for _, l := range leases {
		out = append(out, OpnsenseClient{MAC: l.MAC, IP: l.IP, Hostname: l.Hostname})
	}
	return out, nil
}

// Inventory returns the firewall's point-in-time observation. The interfaces
// fetch is fatal (networks are the inventory); system info, rules, and leases
// degrade to warnings. It is read-only: no controller state is mutated.
func (s *OpnsenseService) Inventory(ctx context.Context, opts OpnsenseOptions) (*OpnsenseInventory, error) {
	client := s.client(opts)
	snap, err := client.FetchInventory(ctx)
	if err != nil {
		return nil, err
	}
	inv := &OpnsenseInventory{
		Host:            opts.Host,
		Devices:         []serviceDevice{},
		NetworkGateways: map[string]string{},
		Warnings:        snap.Warnings,
	}
	if snap.System != nil {
		inv.ControllerVersion = snap.System.ProductVersion()
		inv.Arch = snap.System.Arch()
	}
	specInv := opnsensebackend.BuildSpecInventory(snap)
	inv.NetworkGateways = specInv.NetworkGateways
	inv.FirewallRuleCount = len(snap.Rules)
	inv.FirewallRulesOK = snap.RulesOK
	inv.ClientCount = snap.LeaseCount()
	inv.Services = flattenServices(snap.Services)
	inv.ServicesOK = snap.ServicesOK
	inv.Gateways = flattenGateways(snap.Gateways)
	inv.GatewaysOK = snap.GatewaysOK
	inv.Bridges = flattenBridges(snap.Bridges)
	inv.BridgesOK = snap.BridgesOK
	inv.InterfaceSettings = flattenIfSettings(snap.IfSettings)
	inv.InterfaceSettingsOK = snap.IfSettingsOK
	inv.Dnsmasq = flattenDnsmasq(snap.Dnsmasq)
	inv.DnsmasqOK = snap.DnsmasqOK
	inv.Unbound = flattenUnbound(snap.Unbound)
	inv.UnboundOK = snap.UnboundOK
	inv.PfStatistics = flattenPf(snap.PfStats)
	inv.PfStatisticsOK = snap.PfStatsOK
	inv.KernelRoutes = flattenRoutes(snap.KernelRoutes)
	inv.KernelRoutesOK = snap.KernelRoutesOK
	for _, d := range specInv.Devices {
		inv.Devices = append(inv.Devices, serviceDevice{
			Type:     d.Type,
			Name:     d.Name,
			IP:       d.IP,
			Networks: d.Networks,
		})
	}
	return inv, nil
}
