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
	System     *SystemInformation
	Interfaces []Interface
	Rules      []FirewallRule
	RulesOK    bool
	Leases     []DHCPLease
	LeasesOK   bool
	Services   []Service
	ServicesOK bool
	Gateways   []GatewayStatus
	GatewaysOK bool
	Warnings   []string
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

	return snap, nil
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
