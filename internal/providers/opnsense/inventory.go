package opnsense

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/jpvelasco/nyx/internal/intent"
)

// emptyTopologyWarning is reported when interfaces_info answers 200 OK but
// decodes to zero networks with an IPv4 configuration — the signature of a
// wire shape (or version) this client cannot read. Both the import and the
// inventory surfaces report it so an empty topology is never silent.
const emptyTopologyWarning = "no networks found on the controller — the interfaces response parsed to zero configured interfaces; check the controller version against this client (run with --debug to see the raw interfaces_info payload)"

// InventorySnapshot is a point-in-time observation of the firewall: system
// metadata, its interfaces with IP configuration, the firewall filter rules,
// and the active DHCP leases (the only live host inventory OPNsense
// exposes). The interfaces fetch is mandatory — the networks ARE the
// inventory — so a failure there fails the whole call; system info, rules,
// and leases are best-effort and degrade into Warnings.
type InventorySnapshot struct {
	System           *SystemInformation
	Interfaces       []Interface
	Rules            []FirewallRule
	RulesOK          bool
	Leases           []DHCPLease
	LeasesOK         bool
	Services         []Service
	ServicesOK       bool
	Gateways         []GatewayStatus
	GatewaysOK       bool
	Bridges          []Bridge
	BridgesOK        bool
	IfSettings       []InterfaceSetting
	IfSettingsOK     bool
	Dnsmasq          *DnsmasqSettings
	DnsmasqOK        bool
	Unbound          *UnboundSettings
	UnboundOK        bool
	PfStats          *PfStatistics
	PfStatsOK        bool
	KernelRoutes     []KernelRoute
	KernelRoutesOK   bool
	WireGuardServers []WireGuardServer
	WireGuardClients []WireGuardClient
	WireGuardStatus  *WireGuardStatus
	WireGuardOK      bool
	Warnings         []string
}

// FetchInventory loads the firewall's full observation in one pass. The
// interfaces fetch is fatal (networks are the inventory); everything else
// degrades to a warning so the snapshot is still returned.
func (c *Client) FetchInventory(ctx context.Context) (*InventorySnapshot, error) {
	interfaces, err := c.GetInterfaces(ctx)
	if err != nil {
		return nil, err
	}
	snap := &InventorySnapshot{Interfaces: interfaces}
	if len(invNetworks(snap)) == 0 {
		// Same guard as the import path: a 200 OK that yields no networks
		// means the topology is empty, not that the firewall has none.
		snap.Warnings = append(snap.Warnings, emptyTopologyWarning)
	}

	sys, err := c.GetSystemInformation(ctx)
	if err != nil {
		snap.Warnings = append(snap.Warnings, fmt.Sprintf("system info unavailable: %v", err))
	} else {
		snap.System = sys
	}

	rules, err := c.GetFirewallRules(ctx)
	if err != nil {
		snap.Warnings = append(snap.Warnings, fmt.Sprintf("firewall rules unavailable: %v", err))
	} else {
		snap.Rules = rules
		snap.RulesOK = true
	}

	leases, err := c.GetDHCPLeases(ctx)
	if err != nil {
		snap.Warnings = append(snap.Warnings, fmt.Sprintf("DHCP leases unavailable: %v", err))
	} else {
		snap.Leases = leases
		snap.LeasesOK = true
	}

	svcs, err := c.GetServices(ctx)
	if err != nil {
		snap.Warnings = append(snap.Warnings, fmt.Sprintf("services unavailable: %v", err))
	} else {
		snap.Services = svcs
		snap.ServicesOK = true
	}

	gws, err := c.GetGatewayStatus(ctx)
	if err != nil {
		snap.Warnings = append(snap.Warnings, fmt.Sprintf("gateway status unavailable: %v", err))
	} else {
		snap.Gateways = gws
		snap.GatewaysOK = true
	}

	bridges, err := c.GetBridgeSettings(ctx)
	if err != nil {
		snap.Warnings = append(snap.Warnings, fmt.Sprintf("bridge settings unavailable: %v", err))
	} else {
		snap.Bridges = bridges
		snap.BridgesOK = true
	}

	ifs, err := c.GetInterfaceSettings(ctx)
	if err != nil {
		snap.Warnings = append(snap.Warnings, fmt.Sprintf("interface settings unavailable: %v", err))
	} else {
		snap.IfSettings = ifs
		snap.IfSettingsOK = true
	}

	dns, err := c.GetDnsmasqSettings(ctx)
	if err != nil {
		snap.Warnings = append(snap.Warnings, fmt.Sprintf("dnsmasq settings unavailable: %v", err))
	} else {
		snap.Dnsmasq = dns
		snap.DnsmasqOK = true
	}

	unbound, err := c.GetUnboundObserve(ctx)
	if err != nil {
		// Follow Dnsmasq: any fetch error degrades to a warning. WireGuard's
		// silent-404-plugin-absent pattern is not on this branch.
		snap.Warnings = append(snap.Warnings, fmt.Sprintf("unbound settings unavailable: %v", err))
	} else {
		snap.Unbound = unbound
		snap.UnboundOK = true
	}

	pf, err := c.GetPfStatistics(ctx)
	if err != nil {
		snap.Warnings = append(snap.Warnings, fmt.Sprintf("pf statistics unavailable: %v", err))
	} else {
		snap.PfStats = pf
		snap.PfStatsOK = true
	}

	routes, err := c.GetKernelRoutes(ctx)
	if err != nil {
		snap.Warnings = append(snap.Warnings, fmt.Sprintf("kernel routes unavailable: %v", err))
	} else {
		snap.KernelRoutes = routes
		snap.KernelRoutesOK = true
	}

	observeWireGuard(ctx, c, snap)

	return snap, nil
}

func observeWireGuard(ctx context.Context, c *Client, snap *InventorySnapshot) {
	servers, err := c.GetWireGuardServers(ctx)
	if warnWireGuard(snap, err, "servers") {
		return
	}
	clients, err := c.GetWireGuardClients(ctx)
	if warnWireGuard(snap, err, "clients") {
		return
	}
	st, err := c.GetWireGuardStatus(ctx)
	if warnWireGuard(snap, err, "status") {
		return
	}
	snap.WireGuardServers = servers
	snap.WireGuardClients = clients
	snap.WireGuardStatus = st
	snap.WireGuardOK = true
}

// warnWireGuard records a warning unless the plugin is simply not
// installed (404). A missing plugin is not a degraded fetch.
func warnWireGuard(snap *InventorySnapshot, err error, what string) bool {
	if err == nil {
		return false
	}
	if !isNotFound(err) {
		snap.Warnings = append(snap.Warnings, fmt.Sprintf("wireguard %s unavailable: %v", what, err))
	}
	return true
}

// BuildSpecInventory converts the snapshot into the spec's optional
// inventory block. The firewall is a single managed device; one device entry
// is emitted per interface that carries an IPv4 address, named after the
// interface. OPNsense does not expose managed-device inventory (models,
// firmware, upgrade state) or per-scope ACL counts, so those fields are
// deliberately left empty.
func BuildSpecInventory(snap *InventorySnapshot) *intent.Inventory {
	inv := &intent.Inventory{
		NetworkGateways: make(map[string]string),
	}
	if snap.System != nil {
		inv.ControllerVersion = snap.System.ProductVersion()
	}

	for _, n := range invNetworks(snap) {
		dev := intent.InventoryDevice{
			Type:     "gateway",
			Name:     n.Name,
			IP:       ifaceIP(snap.Interfaces, n.Name),
			Networks: []string{n.Name},
		}
		inv.Devices = append(inv.Devices, dev)
		inv.NetworkGateways[n.Name] = n.Gateway
	}
	return inv
}

// ifaceIP finds the IP of the interface with the given lower-cased name, or
// "" when no interface matches (the inventory lists the device IP per network
// so the read is traceable).
func ifaceIP(ifaces []Interface, name string) string {
	for _, i := range ifaces {
		if strings.ToLower(strings.TrimSpace(i.Name)) == name {
			return i.IP
		}
	}
	return ""
}

// RenderInventory formats the snapshot as a stable, human-readable map of the
// firewall. It mirrors the Omada inventory rendering (section banners,
// `N item%s` counts) so both providers present the same "where is
// everything" surface.
func RenderInventory(snap *InventorySnapshot, site string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Site: %s\n", site)
	if snap.System != nil && snap.System.ProductVersion() != "" {
		ver := snap.System.ProductVersion()
		if arch := snap.System.Arch(); arch != "" {
			ver += " (" + arch + ")"
		}
		fmt.Fprintf(&b, "Controller: %s\n", ver)
	}
	// Warnings are intentionally NOT rendered here: the CLI layer prints
	// them to stderr once (and the JSON surface keeps them structured).
	// Mirrors the Omada inventory rendering.

	fmt.Fprintf(&b, "\n== Networks (%d) ==\n", len(invNetworks(snap)))
	for _, n := range invNetworks(snap) {
		fmt.Fprintf(&b, "  %-16s %-18s gateway: %s\n", n.Name, n.CIDR, orDash(n.Gateway))
	}

	fmt.Fprintf(&b, "\n== Devices (%d) ==\n", len(snap.Interfaces))
	for _, iface := range snap.Interfaces {
		zone := inferZone(iface.Name, iface.Description)
		ip := orDash(iface.IP)
		extra := ""
		if iface.Device != "" {
			extra += " device:" + iface.Device
		}
		if len(iface.Members) > 0 {
			extra += " members:" + strings.Join(iface.Members, ",")
		}
		fmt.Fprintf(&b, "  %-8s %-16s %-15s zone: %s%s\n", "gateway", iface.Name, ip, zone, extra)
	}

	if snap.RulesOK {
		fmt.Fprintf(&b, "\n== Firewall rules (%d) ==\n", len(snap.Rules))
		fmt.Fprintf(&b, "  %d rule%s\n", len(snap.Rules), plural(len(snap.Rules)))
	} else {
		fmt.Fprintf(&b, "\n== Firewall rules ==\n")
		fmt.Fprintf(&b, "  unknown (fetch failed)\n")
	}

	fmt.Fprintf(&b, "\n== Clients ==\n")
	fmt.Fprintf(&b, "  %d active clients\n", snap.LeaseCount())

	if snap.ServicesOK {
		running := 0
		for _, s := range snap.Services {
			if s.Running {
				running++
			}
		}
		fmt.Fprintf(&b, "\n== Services (%d) ==\n", len(snap.Services))
		fmt.Fprintf(&b, "  %d running\n", running)
	} else {
		fmt.Fprintf(&b, "\n== Services ==\n")
		fmt.Fprintf(&b, "  unknown (fetch failed)\n")
	}

	if snap.GatewaysOK {
		fmt.Fprintf(&b, "\n== Gateways (%d) ==\n", len(snap.Gateways))
		for _, g := range snap.Gateways {
			fmt.Fprintf(&b, "  %-16s %-10s %s\n", g.Name, orDash(g.Status), orDash(g.Address))
		}
	} else {
		fmt.Fprintf(&b, "\n== Gateways ==\n")
		fmt.Fprintf(&b, "  unknown (fetch failed)\n")
	}

	if snap.BridgesOK {
		fmt.Fprintf(&b, "\n== Bridges (%d) ==\n", len(snap.Bridges))
		for _, br := range snap.Bridges {
			fmt.Fprintf(&b, "  %-16s members:%s\n", orDash(firstNonEmpty(br.Description, br.UUID)), orDash(strings.Join(br.Members, ",")))
		}
	} else {
		fmt.Fprintf(&b, "\n== Bridges ==\n")
		fmt.Fprintf(&b, "  unknown (fetch failed)\n")
	}

	if snap.IfSettingsOK {
		fmt.Fprintf(&b, "\n== Interface settings (%d) ==\n", len(snap.IfSettings))
		fmt.Fprintf(&b, "  %d configured\n", len(snap.IfSettings))
	} else {
		fmt.Fprintf(&b, "\n== Interface settings ==\n")
		fmt.Fprintf(&b, "  unknown (fetch failed)\n")
	}

	if snap.DnsmasqOK && snap.Dnsmasq != nil {
		on := "off"
		if snap.Dnsmasq.Enabled {
			on = "on"
		}
		fmt.Fprintf(&b, "\n== Dnsmasq ==\n")
		fmt.Fprintf(&b, "  %s, %d range%s, %d host%s\n", on, len(snap.Dnsmasq.Ranges), plural(len(snap.Dnsmasq.Ranges)), len(snap.Dnsmasq.Hosts), plural(len(snap.Dnsmasq.Hosts)))
	} else {
		fmt.Fprintf(&b, "\n== Dnsmasq ==\n")
		fmt.Fprintf(&b, "  unknown (fetch failed)\n")
	}

	if snap.UnboundOK && snap.Unbound != nil {
		on := "off"
		if snap.Unbound.Enabled {
			on = "on"
		}
		run := "stopped"
		if snap.Unbound.Running {
			run = "running"
		}
		fmt.Fprintf(&b, "\n== Unbound ==\n")
		fmt.Fprintf(&b, "  %s, %s, %d host override%s\n", on, run, len(snap.Unbound.Hosts), plural(len(snap.Unbound.Hosts)))
	} else {
		fmt.Fprintf(&b, "\n== Unbound ==\n")
		fmt.Fprintf(&b, "  unknown (fetch failed)\n")
	}

	if snap.PfStatsOK && snap.PfStats != nil {
		fmt.Fprintf(&b, "\n== pf statistics ==\n")
		fmt.Fprintf(&b, "  %d states\n", snap.PfStats.StateCount)
	} else {
		fmt.Fprintf(&b, "\n== pf statistics ==\n")
		fmt.Fprintf(&b, "  unknown (fetch failed)\n")
	}

	if snap.KernelRoutesOK {
		fmt.Fprintf(&b, "\n== Kernel routes (%d) ==\n", len(snap.KernelRoutes))
		fmt.Fprintf(&b, "  %d route%s\n", len(snap.KernelRoutes), plural(len(snap.KernelRoutes)))
	} else {
		fmt.Fprintf(&b, "\n== Kernel routes ==\n")
		fmt.Fprintf(&b, "  unknown (fetch failed)\n")
	}

	fmt.Fprintf(&b, "\n== WireGuard ==\n")
	if snap.WireGuardOK && snap.WireGuardStatus != nil {
		on := "off"
		if snap.WireGuardStatus.Running {
			on = "on"
		}
		fmt.Fprintf(&b, "  %s, %d server%s, %d peer%s\n", on, len(snap.WireGuardServers), plural(len(snap.WireGuardServers)), len(snap.WireGuardClients), plural(len(snap.WireGuardClients)))
	} else {
		fmt.Fprintf(&b, "  unknown (fetch failed)\n")
	}
	return b.String()
}

type invNetwork struct {
	Name    string
	CIDR    string
	Gateway string
}

// invNetworks derives the network rows from the interfaces that carry an IPv4
// address (the same derivation as BuildSpecInventory).
func invNetworks(snap *InventorySnapshot) []invNetwork {
	var out []invNetwork
	for _, iface := range snap.Interfaces {
		if iface.IP == "" || iface.Subnet == 0 {
			continue
		}
		cidr := fmt.Sprintf("%s/%d", iface.IP, iface.Subnet)
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			continue
		}
		out = append(out, invNetwork{
			Name:    strings.ToLower(strings.TrimSpace(iface.Name)),
			CIDR:    cidr,
			Gateway: iface.Gateway,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// LeaseCount is the lease count, or 0 when the lease fetch failed.
func (snap *InventorySnapshot) LeaseCount() int {
	if !snap.LeasesOK {
		return 0
	}
	return len(snap.Leases)
}

// plural renders "1 rule" / "3 rules".
func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// orDash renders an empty string as a dash.
func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
