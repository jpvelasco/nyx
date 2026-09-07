package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/jpvelasco/nyx/internal/providers"
	opnsensebackend "github.com/jpvelasco/nyx/internal/providers/opnsense"
)

// OpnsenseOptions carries everything needed to talk to an OPNsense firewall
// via its REST API. The API secret is held only for the duration of a
// request; it is never written to logs, evidence, or tool output.
type OpnsenseOptions struct {
	Host          string
	APIKey        string
	APISecret     string
	SkipTLSVerify bool
	CACertPath    string
}

// OpnsenseInfo is the system metadata surfaced to agents.
type OpnsenseInfo struct {
	Provider string `json:"provider"`
	Host     string `json:"host"`
	Version  string `json:"version"`
	Product  string `json:"product"`
	Arch     string `json:"arch"`
}

// OpnsenseInterface is a firewall interface with its IP configuration.
type OpnsenseInterface struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	DHCP        bool     `json:"dhcp"`
	IP          string   `json:"ip"`
	Subnet      int      `json:"subnet"`
	Gateway     string   `json:"gateway"`
	Device      string   `json:"device,omitempty"`
	MAC         string   `json:"mac,omitempty"`
	LinkType    string   `json:"link_type,omitempty"`
	Enabled     bool     `json:"enabled,omitempty"`
	MTU         int      `json:"mtu,omitempty"`
	Members     []string `json:"members,omitempty"`
	RxPackets   uint64   `json:"rx_packets,omitempty"`
	RxBytes     uint64   `json:"rx_bytes,omitempty"`
	TxPackets   uint64   `json:"tx_packets,omitempty"`
	TxBytes     uint64   `json:"tx_bytes,omitempty"`
}

// OpnsenseServiceStatus is one controller service (name + running).
type OpnsenseServiceStatus struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Running     bool   `json:"running"`
}

// OpnsenseGatewayStatus is one gateway health row.
type OpnsenseGatewayStatus struct {
	Name    string `json:"name"`
	Address string `json:"address,omitempty"`
	Status  string `json:"status"`
	Delay   string `json:"delay,omitempty"`
	StdDev  string `json:"stddev,omitempty"`
	Loss    string `json:"loss,omitempty"`
}

// OpnsenseFirewallRule is a firewall filter rule in a flat, agent-friendly
// shape. Disabled is true when the rule is not active.
type OpnsenseFirewallRule struct {
	UUID        string   `json:"uuid"`
	Enabled     bool     `json:"enabled"`
	Disabled    bool     `json:"disabled"`
	Action      string   `json:"action"`
	Interfaces  []string `json:"interfaces"`
	Protocol    string   `json:"protocol"`
	Source      string   `json:"source"`
	Destination string   `json:"destination"`
	SourcePort  string   `json:"source_port,omitempty"`
	DestPort    string   `json:"destination_port,omitempty"`
	Direction   string   `json:"direction,omitempty"`
	IPProtocol  string   `json:"ipprotocol,omitempty"`
	Label       string   `json:"label"`
}

// OpnsenseClient is a DHCP lease — OPNsense does not expose live client
// state, so leases are the best host inventory available.
type OpnsenseClient struct {
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
}

// OpnsenseNatRule is a NAT rule (port forward, one-to-one, or source NAT)
// in a flat, agent-friendly shape.
type OpnsenseNatRule struct {
	UUID        string   `json:"uuid"`
	Enabled     bool     `json:"enabled"`
	Interfaces  []string `json:"interfaces"`
	Protocol    string   `json:"protocol"`
	Source      string   `json:"source"`
	Destination string   `json:"destination"`
	Port        string   `json:"port,omitempty"`
	LocalPort   string   `json:"local_port,omitempty"`
	Target      string   `json:"target,omitempty"`
	Mode        string   `json:"mode,omitempty"`
	Type        string   `json:"type,omitempty"`
	SNATMode    string   `json:"snat_mode,omitempty"`
	Label       string   `json:"label,omitempty"`
}

// OpnsenseNatSummary is the site's full NAT posture in one read: the
// outbound (source) NAT mode plus every NAT rule set. The mode is the key
// double-NAT signal — a transparent-proxy OPNsense reports "disabled".
type OpnsenseNatSummary struct {
	OutboundNatMode  string            `json:"outbound_nat_mode"`
	PortForwardRules []OpnsenseNatRule `json:"port_forward_rules"`
	OneToOneRules    []OpnsenseNatRule `json:"one_to_one_rules"`
	SourceNatRules   []OpnsenseNatRule `json:"source_nat_rules"`
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
	PfStatistics        *OpnsensePfStatistics    `json:"pf_statistics,omitempty"`
	PfStatisticsOK      bool                     `json:"pf_statistics_ok,omitempty"`
	KernelRoutes        []OpnsenseKernelRoute    `json:"kernel_routes,omitempty"`
	KernelRoutesOK      bool                     `json:"kernel_routes_ok,omitempty"`
	Warnings            []string                 `json:"warnings,omitempty"`
}

// OpnsenseBridge is one configured bridge and its members.
type OpnsenseBridge struct {
	UUID        string   `json:"uuid"`
	Description string   `json:"description,omitempty"`
	Members     []string `json:"members,omitempty"`
	STP         bool     `json:"stp,omitempty"`
}

// OpnsenseIfSetting is one configured interface from interfaces/settings/get.
type OpnsenseIfSetting struct {
	Name        string `json:"name"`
	Device      string `json:"device,omitempty"`
	Description string `json:"description,omitempty"`
	Enabled     bool   `json:"enabled"`
	IPv4        string `json:"ipv4,omitempty"`
	Subnet      string `json:"subnet,omitempty"`
}

// OpnsenseDnsmasqSettings is the observe subset of Dnsmasq settings.
type OpnsenseDnsmasqSettings struct {
	Enabled    bool                   `json:"enabled"`
	Interfaces []string               `json:"interfaces,omitempty"`
	Ranges     []OpnsenseDnsmasqRange `json:"ranges,omitempty"`
	Hosts      []OpnsenseDnsmasqHost  `json:"hosts,omitempty"`
}

// OpnsenseDnsmasqRange is one DHCP range.
type OpnsenseDnsmasqRange struct {
	UUID      string `json:"uuid,omitempty"`
	Interface string `json:"interface,omitempty"`
	Start     string `json:"start,omitempty"`
	End       string `json:"end,omitempty"`
}

// OpnsenseDnsmasqHost is one static host mapping.
type OpnsenseDnsmasqHost struct {
	UUID   string `json:"uuid,omitempty"`
	Host   string `json:"host,omitempty"`
	Domain string `json:"domain,omitempty"`
	IP     string `json:"ip,omitempty"`
}

// OpnsensePfStatistics is the pf state-table summary.
type OpnsensePfStatistics struct {
	StateCount  int `json:"state_count"`
	SourceCount int `json:"source_count,omitempty"`
	Limit       int `json:"limit,omitempty"`
}

// OpnsenseKernelRoute is one kernel routing-table row.
type OpnsenseKernelRoute struct {
	Destination string `json:"destination"`
	Gateway     string `json:"gateway,omitempty"`
	Netif       string `json:"netif,omitempty"`
	Flags       string `json:"flags,omitempty"`
}

// OpnsenseAlias is a firewall address alias.
type OpnsenseAlias struct {
	UUID        string   `json:"uuid"`
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Addresses   []string `json:"addresses"`
	Description string   `json:"description,omitempty"`
	Disabled    bool     `json:"disabled"`
}

// OpnsenseNatRuleSpec is the flat desired-state of a NAT rule for one
// collection. Collection-specific fields are ignored by the provider.
type OpnsenseNatRuleSpec struct {
	Interfaces  []string `json:"interfaces,omitempty"`
	Protocol    string   `json:"protocol,omitempty"`
	Source      string   `json:"source,omitempty"`
	Destination string   `json:"destination,omitempty"`
	Port        string   `json:"port,omitempty"`
	LocalPort   string   `json:"local_port,omitempty"`
	Target      string   `json:"target,omitempty"`
	Mode        string   `json:"mode,omitempty"`
	Type        string   `json:"type,omitempty"`
	Label       string   `json:"label,omitempty"`
}

// OpnsenseNatApplyRequest is a single NAT mutation against one of the
// three collections. RuleUUID is required for action update/delete/toggle;
// Spec is required for create/update. ToggleDisable only applies to the
// port-forward toggle (d_nat polarity: 1 = disabled).
type OpnsenseNatApplyRequest struct {
	Operation      string              `json:"operation"`
	Action         string              `json:"action,omitempty"` // "create" (default) | "update" | "delete" | "toggle"
	RuleUUID       string              `json:"rule_uuid,omitempty"`
	Spec           OpnsenseNatRuleSpec `json:"spec"`
	ToggleDisable  bool                `json:"toggle_disable,omitempty"`
	AllowDoubleNat bool                `json:"allow_double_nat,omitempty"`
	DryRun         bool                `json:"dry_run,omitempty"`
}

// OpnsenseService exposes the OPNsense observation surface shared by the MCP
// server and any future CLI commands. NewClient is a seam for tests.
type OpnsenseService struct {
	NewClient func(host, apiKey, apiSecret string, skipTLSVerify bool, caCertPath string) *opnsensebackend.Client
}

// NewOpnsenseService creates an OpnsenseService using the real client.
func NewOpnsenseService() *OpnsenseService {
	return &OpnsenseService{NewClient: opnsensebackend.NewClient}
}

// Info fetches system metadata from the firewall (version, product, arch).
func (s *OpnsenseService) Info(ctx context.Context, opts OpnsenseOptions) (*OpnsenseInfo, error) {
	client := s.client(opts)
	sys, err := client.GetSystemInformation(ctx)
	if err != nil {
		return nil, err
	}
	return &OpnsenseInfo{
		Provider: "opnsense",
		Host:     opts.Host,
		Version:  sys.ProductVersion(),
		Product:  "OPNsense",
		Arch:     sys.Arch(),
	}, nil
}

// ListInterfaces returns the firewall interfaces with IP configuration.
func (s *OpnsenseService) ListInterfaces(ctx context.Context, opts OpnsenseOptions) ([]OpnsenseInterface, error) {
	client := s.client(opts)
	ifaces, err := client.GetInterfaces(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]OpnsenseInterface, 0, len(ifaces))
	for _, i := range ifaces {
		out = append(out, flattenInterface(i))
	}
	return out, nil
}

// ListServices returns the controller service table (name + running).
func (s *OpnsenseService) ListServices(ctx context.Context, opts OpnsenseOptions) ([]OpnsenseServiceStatus, error) {
	client := s.client(opts)
	svcs, err := client.GetServices(ctx)
	if err != nil {
		return nil, err
	}
	return flattenServices(svcs), nil
}

// ListGateways returns the gateway health table.
func (s *OpnsenseService) ListGateways(ctx context.Context, opts OpnsenseOptions) ([]OpnsenseGatewayStatus, error) {
	client := s.client(opts)
	gws, err := client.GetGatewayStatus(ctx)
	if err != nil {
		return nil, err
	}
	return flattenGateways(gws), nil
}

func flattenInterface(i opnsensebackend.Interface) OpnsenseInterface {
	return OpnsenseInterface{
		Name:        i.Name,
		Description: i.Description,
		DHCP:        i.DHCP,
		IP:          i.IP,
		Subnet:      i.Subnet,
		Gateway:     i.Gateway,
		Device:      i.Device,
		MAC:         i.MAC,
		LinkType:    i.LinkType,
		Enabled:     i.Enabled,
		MTU:         i.MTU,
		Members:     i.Members,
		RxPackets:   i.RxPackets,
		RxBytes:     i.RxBytes,
		TxPackets:   i.TxPackets,
		TxBytes:     i.TxBytes,
	}
}

func flattenServices(in []opnsensebackend.Service) []OpnsenseServiceStatus {
	if len(in) == 0 {
		return nil
	}
	out := make([]OpnsenseServiceStatus, len(in))
	for i, s := range in {
		out[i] = OpnsenseServiceStatus{Name: s.Name, Description: s.Description, Running: s.Running}
	}
	return out
}

func flattenGateways(in []opnsensebackend.GatewayStatus) []OpnsenseGatewayStatus {
	if len(in) == 0 {
		return nil
	}
	out := make([]OpnsenseGatewayStatus, len(in))
	for i, g := range in {
		out[i] = OpnsenseGatewayStatus{
			Name: g.Name, Address: g.Address, Status: g.Status,
			Delay: g.Delay, StdDev: g.StdDev, Loss: g.Loss,
		}
	}
	return out
}

// ListBridges returns configured bridges and their members.
func (s *OpnsenseService) ListBridges(ctx context.Context, opts OpnsenseOptions) ([]OpnsenseBridge, error) {
	client := s.client(opts)
	got, err := client.GetBridgeSettings(ctx)
	if err != nil {
		return nil, err
	}
	return flattenBridges(got), nil
}

// ListInterfaceSettings returns the per-interface config map.
func (s *OpnsenseService) ListInterfaceSettings(ctx context.Context, opts OpnsenseOptions) ([]OpnsenseIfSetting, error) {
	client := s.client(opts)
	got, err := client.GetInterfaceSettings(ctx)
	if err != nil {
		return nil, err
	}
	return flattenIfSettings(got), nil
}

// GetDnsmasqSettings returns Dnsmasq enable/interfaces/ranges/hosts.
func (s *OpnsenseService) GetDnsmasqSettings(ctx context.Context, opts OpnsenseOptions) (*OpnsenseDnsmasqSettings, error) {
	client := s.client(opts)
	got, err := client.GetDnsmasqSettings(ctx)
	if err != nil {
		return nil, err
	}
	return flattenDnsmasq(got), nil
}

// GetPfStatistics returns the pf state-table summary.
func (s *OpnsenseService) GetPfStatistics(ctx context.Context, opts OpnsenseOptions) (*OpnsensePfStatistics, error) {
	client := s.client(opts)
	got, err := client.GetPfStatistics(ctx)
	if err != nil {
		return nil, err
	}
	return flattenPf(got), nil
}

// ListKernelRoutes returns the kernel routing table.
func (s *OpnsenseService) ListKernelRoutes(ctx context.Context, opts OpnsenseOptions) ([]OpnsenseKernelRoute, error) {
	client := s.client(opts)
	got, err := client.GetKernelRoutes(ctx)
	if err != nil {
		return nil, err
	}
	return flattenRoutes(got), nil
}

// OpnsenseKeaSubnet is one Kea DHCPv4 subnet.
type OpnsenseKeaSubnet struct {
	UUID        string `json:"uuid"`
	Subnet      string `json:"subnet"`
	Description string `json:"description,omitempty"`
}

// OpnsenseKeaReservation is one Kea static mapping.
type OpnsenseKeaReservation struct {
	UUID     string `json:"uuid"`
	IP       string `json:"ip,omitempty"`
	MAC      string `json:"mac,omitempty"`
	Hostname string `json:"hostname,omitempty"`
}

// ListKeaSubnets returns Kea DHCPv4 subnets.
func (s *OpnsenseService) ListKeaSubnets(ctx context.Context, opts OpnsenseOptions) ([]OpnsenseKeaSubnet, error) {
	got, err := s.client(opts).GetKeaSubnets(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]OpnsenseKeaSubnet, len(got))
	for i, x := range got {
		out[i] = OpnsenseKeaSubnet{UUID: x.UUID, Subnet: x.Subnet, Description: x.Description}
	}
	return out, nil
}

// ListKeaReservations returns Kea DHCPv4 reservations.
func (s *OpnsenseService) ListKeaReservations(ctx context.Context, opts OpnsenseOptions) ([]OpnsenseKeaReservation, error) {
	got, err := s.client(opts).GetKeaReservations(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]OpnsenseKeaReservation, len(got))
	for i, x := range got {
		out[i] = OpnsenseKeaReservation{UUID: x.UUID, IP: x.IP, MAC: x.MAC, Hostname: x.Hostname}
	}
	return out, nil
}

func flattenBridges(in []opnsensebackend.Bridge) []OpnsenseBridge {
	if len(in) == 0 {
		return nil
	}
	out := make([]OpnsenseBridge, len(in))
	for i, b := range in {
		out[i] = OpnsenseBridge{UUID: b.UUID, Description: b.Description, Members: b.Members, STP: b.STP}
	}
	return out
}

func flattenIfSettings(in []opnsensebackend.InterfaceSetting) []OpnsenseIfSetting {
	if len(in) == 0 {
		return nil
	}
	out := make([]OpnsenseIfSetting, len(in))
	for i, s := range in {
		out[i] = OpnsenseIfSetting{Name: s.Name, Device: s.Device, Description: s.Description, Enabled: s.Enabled, IPv4: s.IPv4, Subnet: s.Subnet}
	}
	return out
}

func flattenDnsmasq(in *opnsensebackend.DnsmasqSettings) *OpnsenseDnsmasqSettings {
	if in == nil {
		return nil
	}
	out := &OpnsenseDnsmasqSettings{Enabled: in.Enabled, Interfaces: in.Interfaces}
	for _, r := range in.Ranges {
		out.Ranges = append(out.Ranges, OpnsenseDnsmasqRange{UUID: r.UUID, Interface: r.Interface, Start: r.Start, End: r.End})
	}
	for _, h := range in.Hosts {
		out.Hosts = append(out.Hosts, OpnsenseDnsmasqHost{UUID: h.UUID, Host: h.Host, Domain: h.Domain, IP: h.IP})
	}
	return out
}

func flattenPf(in *opnsensebackend.PfStatistics) *OpnsensePfStatistics {
	if in == nil {
		return nil
	}
	return &OpnsensePfStatistics{StateCount: in.StateCount, SourceCount: in.SourceCount, Limit: in.Limit}
}

func flattenRoutes(in []opnsensebackend.KernelRoute) []OpnsenseKernelRoute {
	if len(in) == 0 {
		return nil
	}
	out := make([]OpnsenseKernelRoute, len(in))
	for i, r := range in {
		out[i] = OpnsenseKernelRoute{Destination: r.Destination, Gateway: r.Gateway, Netif: r.Netif, Flags: r.Flags}
	}
	return out
}

// ListFirewallRules returns the firewall filter rules.
func (s *OpnsenseService) ListFirewallRules(ctx context.Context, opts OpnsenseOptions) ([]OpnsenseFirewallRule, error) {
	client := s.client(opts)
	rules, err := client.GetFirewallRules(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]OpnsenseFirewallRule, 0, len(rules))
	for _, r := range rules {
		out = append(out, flattenFirewallRule(r))
	}
	return out, nil
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

// GetFirewallRule returns a single firewall rule by UUID.
func (s *OpnsenseService) GetFirewallRule(ctx context.Context, opts OpnsenseOptions, uuid string) (*OpnsenseFirewallRule, error) {
	client := s.client(opts)
	rule, err := client.GetFirewallRule(ctx, uuid)
	if err != nil {
		return nil, err
	}
	r := flattenFirewallRule(*rule)
	return &r, nil
}

func flattenFirewallRule(r opnsensebackend.FirewallRule) OpnsenseFirewallRule {
	return OpnsenseFirewallRule{
		UUID:        r.RuleUUID,
		Enabled:     !r.Disabled,
		Disabled:    r.Disabled,
		Action:      r.Action,
		Interfaces:  r.Interface,
		Protocol:    r.Protocol,
		Source:      r.Source,
		Destination: r.Destination,
		SourcePort:  r.SourcePort,
		DestPort:    r.DestPort,
		Direction:   r.Direction,
		IPProtocol:  r.IPProtocol,
		Label:       r.Label,
	}
}

// flattenNat maps the client's flat NAT rows into the service shape.
func flattenNat(rules []opnsensebackend.NatRule) []OpnsenseNatRule {
	out := make([]OpnsenseNatRule, 0, len(rules))
	for _, r := range rules {
		out = append(out, OpnsenseNatRule{
			UUID:        r.RuleUUID,
			Enabled:     !r.Disabled,
			Interfaces:  r.Interface,
			Protocol:    r.Protocol,
			Source:      r.Source,
			Destination: r.Destination,
			Port:        r.Port,
			LocalPort:   r.LocalPort,
			Target:      r.Target,
			Mode:        r.Mode,
			Type:        r.Type,
			SNATMode:    r.SNATMode,
			Label:       r.Label,
		})
	}
	return out
}

// ListPortForwardRules returns the destination-NAT (port forward) rules.
func (s *OpnsenseService) ListPortForwardRules(ctx context.Context, opts OpnsenseOptions) ([]OpnsenseNatRule, error) {
	client := s.client(opts)
	rules, err := client.GetPortForwardRules(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching port forward rules: %w", err)
	}
	return flattenNat(rules), nil
}

// ListOneToOneRules returns the one-to-one NAT rules.
func (s *OpnsenseService) ListOneToOneRules(ctx context.Context, opts OpnsenseOptions) ([]OpnsenseNatRule, error) {
	client := s.client(opts)
	rules, err := client.GetOneToOneRules(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching one-to-one rules: %w", err)
	}
	return flattenNat(rules), nil
}

// ListSourceNatRules returns the source-NAT rules, including the generic
// outbound-NAT row that carries the snat_mode field.
func (s *OpnsenseService) ListSourceNatRules(ctx context.Context, opts OpnsenseOptions) ([]OpnsenseNatRule, error) {
	client := s.client(opts)
	rules, err := client.GetSourceNatRules(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching source NAT rules: %w", err)
	}
	return flattenNat(rules), nil
}

// ListAliases returns all firewall aliases.
func (s *OpnsenseService) ListAliases(ctx context.Context, opts OpnsenseOptions) ([]OpnsenseAlias, error) {
	client := s.client(opts)
	aliases, err := client.GetAliases(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching aliases: %w", err)
	}
	out := make([]OpnsenseAlias, 0, len(aliases))
	for _, a := range aliases {
		out = append(out, OpnsenseAlias{
			UUID:        a.UUID,
			Name:        a.Name,
			Type:        a.Type,
			Addresses:   a.Addresses,
			Description: a.Description,
			Disabled:    a.Disabled,
		})
	}
	return out, nil
}

// GetOutboundNatMode returns the outbound (source) NAT mode — one of
// automatic|hybrid|advanced|disabled. It is the key double-NAT signal.
func (s *OpnsenseService) GetOutboundNatMode(ctx context.Context, opts OpnsenseOptions) (string, error) {
	client := s.client(opts)
	mode, err := client.GetOutboundNatMode(ctx)
	if err != nil {
		return "", fmt.Errorf("fetching outbound NAT mode: %w", err)
	}
	return mode, nil
}

// GetNAT returns the full NAT posture in one call: outbound mode + every NAT
// rule set. A failure on any read is surfaced — a partial NAT picture would
// mislead the double-NAT verdict.
func (s *OpnsenseService) GetNAT(ctx context.Context, opts OpnsenseOptions) (*OpnsenseNatSummary, error) {
	client := s.client(opts)
	mode, err := client.GetOutboundNatMode(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching outbound NAT mode: %w", err)
	}
	var pf, o2o, snat []opnsensebackend.NatRule
	if pf, err = client.GetPortForwardRules(ctx); err != nil {
		return nil, fmt.Errorf("fetching port forward rules: %w", err)
	}
	if o2o, err = client.GetOneToOneRules(ctx); err != nil {
		return nil, fmt.Errorf("fetching one-to-one rules: %w", err)
	}
	if snat, err = client.GetSourceNatRules(ctx); err != nil {
		return nil, fmt.Errorf("fetching source NAT rules: %w", err)
	}
	return &OpnsenseNatSummary{
		OutboundNatMode:  mode,
		PortForwardRules: flattenNat(pf),
		OneToOneRules:    flattenNat(o2o),
		SourceNatRules:   flattenNat(snat),
	}, nil
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

func (s *OpnsenseService) client(opts OpnsenseOptions) *opnsensebackend.Client {
	return s.NewClient(opts.Host, opts.APIKey, opts.APISecret, opts.SkipTLSVerify, opts.CACertPath)
}

// PlanNat previews a NAT mutation without mutating: it returns the action's
// endpoint, the current collection state as Before evidence, and the
// double-NAT guard verdict. It issues zero POSTs.
func (s *OpnsenseService) PlanNat(ctx context.Context, opts OpnsenseOptions, req OpnsenseNatApplyRequest) (*providers.NatPlan, error) {
	mutator, err := s.natMutator()
	if err != nil {
		return nil, err
	}
	return mutator.PlanNat(ctx, s.natRequest(req), s.natOpts(opts))
}

// ApplyNat performs a NAT mutation when the double-NAT guard passes and
// DryRun is false. A dry-run or an idempotent no-op (a create whose 5-tuple
// already exists with the same spec) issues zero POSTs.
func (s *OpnsenseService) ApplyNat(ctx context.Context, opts OpnsenseOptions, req OpnsenseNatApplyRequest) (*providers.NatApplyResult, error) {
	mutator, err := s.natMutator()
	if err != nil {
		return nil, err
	}
	return mutator.ApplyNat(ctx, s.natRequest(req), s.natOpts(opts))
}

// OpnsenseVLANRequest is a plan/apply VLAN or bridge-member mutation.
type OpnsenseVLANRequest struct {
	Kind        string // vlan (default) | bridge
	Parent      string
	Tag         int
	Description string
	UUID        string
	Members     []string
	Delete      bool
}

// OpnsenseVLANPlan previews a VLAN/bridge mutation.
type OpnsenseVLANPlan struct {
	Action   string   `json:"action"`
	Kind     string   `json:"kind"`
	UUID     string   `json:"uuid,omitempty"`
	Warning  string   `json:"warning"`
	Warnings []string `json:"warnings,omitempty"`
}

// OpnsenseVLANApplyResult is the apply outcome.
type OpnsenseVLANApplyResult struct {
	Outcome  string   `json:"outcome"`
	Kind     string   `json:"kind"`
	UUID     string   `json:"uuid,omitempty"`
	DryRun   bool     `json:"dry_run"`
	Warning  string   `json:"warning"`
	Warnings []string `json:"warnings,omitempty"`
}

func vlanKind(kind string) string {
	if strings.EqualFold(kind, "bridge") {
		return "bridge"
	}
	return "vlan"
}

// OpnsenseVLAN is a configured VLAN device.
type OpnsenseVLAN struct {
	UUID        string `json:"uuid"`
	Parent      string `json:"parent"`
	Tag         int    `json:"tag"`
	Description string `json:"description,omitempty"`
	Device      string `json:"device,omitempty"`
}

// ListVLANs returns configured VLAN devices.
func (s *OpnsenseService) ListVLANs(ctx context.Context, opts OpnsenseOptions) ([]OpnsenseVLAN, error) {
	rows, err := s.client(opts).GetVLANs(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]OpnsenseVLAN, 0, len(rows))
	for _, v := range rows {
		out = append(out, OpnsenseVLAN{UUID: v.UUID, Parent: v.Parent, Tag: v.Tag, Description: v.Description, Device: v.Device})
	}
	return out, nil
}

// PlanVLAN previews creating, updating, or deleting a VLAN device, or
// updating a bridge's members. The assign/IP gap is always stated.
func (s *OpnsenseService) PlanVLAN(ctx context.Context, opts OpnsenseOptions, req OpnsenseVLANRequest) (*OpnsenseVLANPlan, error) {
	kind := vlanKind(req.Kind)
	plan := &OpnsenseVLANPlan{Kind: kind, UUID: req.UUID, Warning: opnsensebackend.AssignIPGapWarning, Warnings: []string{opnsensebackend.AssignIPGapWarning}}
	client := s.client(opts)
	if kind == "bridge" {
		if req.UUID == "" && !req.Delete {
			return nil, fmt.Errorf("uuid is required for bridge member updates")
		}
		bridges, err := client.GetBridgeSettings(ctx)
		if err != nil {
			return nil, err
		}
		var cur *opnsensebackend.Bridge
		for i := range bridges {
			if strings.EqualFold(bridges[i].UUID, req.UUID) {
				cur = &bridges[i]
				break
			}
		}
		if req.Delete {
			return nil, fmt.Errorf("bridge delete is not supported; update members instead")
		}
		if cur == nil {
			return nil, fmt.Errorf("bridge %s not found", req.UUID)
		}
		if opnsensebackend.BridgeMembersMatch(cur.Members, req.Members) {
			plan.Action = "unchanged"
			return plan, nil
		}
		plan.Action = "update"
		return plan, nil
	}
	identifiedByUUID := req.Delete && req.UUID != ""
	if !identifiedByUUID && (req.Parent == "" || req.Tag <= 0) {
		return nil, fmt.Errorf("parent and tag are required (or uuid for delete)")
	}
	vlans, err := client.GetVLANs(ctx)
	if err != nil {
		return nil, err
	}
	cur, ok := opnsensebackend.FindVLAN(vlans, req.UUID, req.Parent, req.Tag)
	if req.Delete {
		if !ok {
			plan.Action = "unchanged"
			return plan, nil
		}
		plan.Action = "delete"
		plan.UUID = cur.UUID
		return plan, nil
	}
	w := opnsensebackend.VLANWrite{Parent: req.Parent, Tag: req.Tag, Description: req.Description}
	if !ok {
		plan.Action = "create"
		return plan, nil
	}
	plan.UUID = cur.UUID
	if opnsensebackend.VLANMatchesWrite(cur, w) {
		plan.Action = "unchanged"
		return plan, nil
	}
	plan.Action = "update"
	return plan, nil
}

// ApplyVLAN creates/updates/deletes a VLAN device or updates bridge members.
// Dry-run by default at the MCP layer. A real apply reconfigures.
func (s *OpnsenseService) ApplyVLAN(ctx context.Context, opts OpnsenseOptions, req OpnsenseVLANRequest, dryRun bool) (*OpnsenseVLANApplyResult, error) {
	plan, err := s.PlanVLAN(ctx, opts, req)
	if err != nil {
		return nil, err
	}
	res := &OpnsenseVLANApplyResult{
		Outcome:  plan.Action,
		Kind:     plan.Kind,
		UUID:     plan.UUID,
		DryRun:   dryRun,
		Warning:  plan.Warning,
		Warnings: plan.Warnings,
	}
	if dryRun || plan.Action == "unchanged" {
		return res, nil
	}
	client := s.client(opts)
	if plan.Kind == "bridge" {
		if err := client.SetBridgeMembers(ctx, req.UUID, req.Members, req.Description); err != nil {
			return nil, err
		}
		if err := client.ReconfigureBridges(ctx); err != nil {
			return nil, err
		}
		res.Outcome = "updated"
		return res, nil
	}
	w := opnsensebackend.VLANWrite{Parent: req.Parent, Tag: req.Tag, Description: req.Description}
	switch plan.Action {
	case "create":
		id, err := client.CreateVLAN(ctx, w)
		if err != nil {
			return nil, err
		}
		res.UUID = id
		res.Outcome = "created"
	case "update":
		if err := client.SetVLAN(ctx, plan.UUID, w); err != nil {
			return nil, err
		}
		res.Outcome = "updated"
	case "delete":
		if err := client.DeleteVLAN(ctx, plan.UUID); err != nil {
			return nil, err
		}
		res.Outcome = "deleted"
	}
	if err := client.ReconfigureVLANs(ctx); err != nil {
		return nil, err
	}
	return res, nil
}

// newNatMutator resolves the provider's NAT mutation surface (type-assertion
// safety rail, mirrors the Omada applier).
func (s *OpnsenseService) natMutator() (providers.NatMutationProvider, error) {
	p := providers.Get(opnsensebackend.ProviderName)
	mutator, ok := p.(providers.NatMutationProvider)
	if !ok {
		return nil, fmt.Errorf("provider %q does not implement NAT mutation", opnsensebackend.ProviderName)
	}
	return mutator, nil
}

// natOpts maps service options to the provider's import options.
func (s *OpnsenseService) natOpts(opts OpnsenseOptions) providers.ImportOptions {
	return providers.ImportOptions{
		Host:          opts.Host,
		ClientID:      opts.APIKey,
		ClientSecret:  opts.APISecret,
		SkipTLSVerify: opts.SkipTLSVerify,
		CACertPath:    opts.CACertPath,
	}
}

// natRequest maps the service request to the provider's NAT request shape.
func (s *OpnsenseService) natRequest(req OpnsenseNatApplyRequest) providers.NatApplyRequest {
	return providers.NatApplyRequest{
		Operation:      req.Operation,
		Action:         req.Action,
		RuleUUID:       req.RuleUUID,
		Spec:           s.natSpec(req.Spec),
		ToggleDisable:  req.ToggleDisable,
		AllowDoubleNat: req.AllowDoubleNat,
		DryRun:         req.DryRun,
	}
}

// natSpec maps the service rule spec to the provider shape.
func (s *OpnsenseService) natSpec(spec OpnsenseNatRuleSpec) providers.NatRuleSpec {
	return providers.NatRuleSpec{
		Interfaces:  spec.Interfaces,
		Protocol:    spec.Protocol,
		Source:      spec.Source,
		Destination: spec.Destination,
		Port:        spec.Port,
		LocalPort:   spec.LocalPort,
		Target:      spec.Target,
		Mode:        spec.Mode,
		Type:        spec.Type,
		Label:       spec.Label,
	}
}
