package omada

import (
	"context"
	"fmt"
	"strings"

	"github.com/jpvelasco/nyx/internal/intent"
)

// InventorySnapshot is a point-in-time observation of a site: the device
// inventory, LAN networks with their gateway bindings, both ACL scopes,
// and the active clients. Fetches of devices, ACLs, and clients are
// best-effort: failures are recorded in Warnings and the snapshot is still
// returned (the Networks fetch is mandatory and fails the whole call).
type InventorySnapshot struct {
	ControllerVersion  string
	ControllerCategory string
	Devices            []Device
	Networks           []Network
	GatewayACLs        ACLList
	SwitchACLs         ACLList
	GatewayACLsOK      bool
	SwitchACLsOK       bool
	Clients            []ConnectedClient
	Warnings           []string
}

// FetchInventory loads the site's full observation in one pass. Network
// fetch failure is fatal; everything else degrades to a warning.
func (c *Client) FetchInventory(ctx context.Context, siteID string) (*InventorySnapshot, error) {
	nets, err := c.GetNetworks(ctx, siteID)
	if err != nil {
		return nil, err
	}
	snap := &InventorySnapshot{
		ControllerVersion:  c.Info().ControllerVer,
		ControllerCategory: c.Info().Category,
		Networks:           nets,
	}

	devices, err := c.GetDevices(ctx, siteID)
	if err != nil {
		snap.Warnings = append(snap.Warnings, fmt.Sprintf("device inventory unavailable: %v", err))
	} else {
		snap.Devices = devices
	}

	gwList, err := c.FetchACLs(ctx, siteID, ACLTypeGateway)
	if err != nil {
		snap.Warnings = append(snap.Warnings, fmt.Sprintf("gateway ACLs unavailable: %v", err))
	} else {
		snap.GatewayACLs = gwList
		snap.GatewayACLsOK = true
	}

	swList, err := c.FetchACLs(ctx, siteID, ACLTypeSwitch)
	if err != nil {
		snap.Warnings = append(snap.Warnings, fmt.Sprintf("switch ACLs unavailable: %v", err))
	} else {
		snap.SwitchACLs = swList
		snap.SwitchACLsOK = true
	}

	clients, err := c.GetClients(ctx, siteID)
	if err != nil {
		snap.Warnings = append(snap.Warnings, fmt.Sprintf("clients unavailable: %v", err))
	}
	if eerr := c.EnrichFromDHCP(ctx, siteID, clients, nets); eerr != nil {
		snap.Warnings = append(snap.Warnings, fmt.Sprintf("client DHCP enrichment unavailable: %v", eerr))
	}
	snap.Clients = clients
	return snap, nil
}

// BuildSpecInventory converts the snapshot into the spec's optional
// inventory block. Device and gateway names stay raw; network names are
// sanitized to match the spec's network entries.
func BuildSpecInventory(snap *InventorySnapshot) *intent.Inventory {
	inv := &intent.Inventory{
		ControllerVersion:  snap.ControllerVersion,
		ControllerCategory: snap.ControllerCategory,
		NetworkGateways:    make(map[string]string),
	}
	gwMap := NetworkGatewayMap(snap.Devices, snap.Networks)
	for _, n := range snap.Networks {
		inv.NetworkGateways[sanitizeName(n.Name)] = gwMap[n.Name]
	}
	// Per-device network lists share the same binding resolution (deviceMac
	// primary, gateway-IP fallback) so a 6.2.x snapshot without deviceMac
	// still attributes the LANs to the managed gateway.
	bound := make(map[string]string, len(snap.Networks)) // network ID -> gateway name
	for _, n := range snap.Networks {
		if d := boundGatewayDevice(snap.Devices, n); d != nil {
			bound[n.ID] = d.Name
		}
	}
	for _, d := range SortedDevices(snap.Devices) {
		dev := intent.InventoryDevice{
			Type:     d.Type,
			Name:     d.Name,
			Model:    d.Model,
			IP:       d.IP,
			Firmware: d.FirmwareVersion,
			Upgrade:  d.NeedUpgrade,
		}
		for _, n := range snap.Networks {
			if bound[n.ID] == d.Name {
				dev.Networks = append(dev.Networks, sanitizeName(n.Name))
			}
		}
		inv.Devices = append(inv.Devices, dev)
	}
	if snap.GatewayACLsOK {
		inv.ACLScopes = append(inv.ACLScopes, intent.ACLScopeStatus{Scope: "gateway", RuleCount: len(snap.GatewayACLs.Rules)})
	}
	if snap.SwitchACLsOK {
		inv.ACLScopes = append(inv.ACLScopes, intent.ACLScopeStatus{Scope: "switch", RuleCount: len(snap.SwitchACLs.Rules)})
	}
	return inv
}

// RenderInventory formats the snapshot as a stable, human-readable map of
// the site. It is the standing "where is everything" surface.
func RenderInventory(snap *InventorySnapshot, siteName string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Site: %s\n", siteName)
	if snap.ControllerVersion != "" {
		cat := ""
		if snap.ControllerCategory != "" {
			cat = " (" + snap.ControllerCategory + ")"
		}
		fmt.Fprintf(&b, "Controller: %s%s\n", snap.ControllerVersion, cat)
	}
	// Warnings are intentionally NOT rendered here: the CLI layer prints
	// them to stderr once (and the JSON surface keeps them structured).

	fmt.Fprintf(&b, "\n== Devices (%d) ==\n", len(snap.Devices))
	for _, d := range SortedDevices(snap.Devices) {
		upgrade := ""
		if d.NeedUpgrade {
			upgrade = "  [upgrade available]"
		}
		fmt.Fprintf(&b, "  [%-8s] %-34s %-14s %-15s %s%s\n",
			d.Type, d.Name, d.Model, d.IP, d.FirmwareVersion, upgrade)
	}

	fmt.Fprintf(&b, "\n== Networks (%d) ==\n", len(snap.Networks))
	for _, n := range snap.Networks {
		gw := ""
		if d, ok := snap.GatewayForNetwork(n.ID); ok {
			gw = d
		}
		fmt.Fprintf(&b, "  %-16s %-18s vlan %-4d gw %-15s gateway: %s\n",
			sanitizeName(n.Name), n.CIDR(), n.VLANID, n.Gateway(), orDash(gw))
	}

	fmt.Fprintf(&b, "\n== ACL scopes ==\n")
	if snap.GatewayACLsOK {
		renderScope(&b, "gateway", snap.GatewayACLs)
	} else {
		fmt.Fprintf(&b, "  gateway: unknown (fetch failed)\n")
	}
	if snap.SwitchACLsOK {
		renderScope(&b, "switch", snap.SwitchACLs)
	} else {
		fmt.Fprintf(&b, "  switch:  unknown (fetch failed)\n")
	}

	fmt.Fprintf(&b, "\n== Clients ==\n")
	fmt.Fprintf(&b, "  %d active clients\n", len(snap.Clients))
	return b.String()
}

func renderScope(b *strings.Builder, scope string, list ACLList) {
	fmt.Fprintf(b, "  %-8s %d rule%s\n", scope+":", len(list.Rules), plural(len(list.Rules)))
}

// GatewayForNetwork is a snapshot-level convenience over the binding lookup.
func (snap *InventorySnapshot) GatewayForNetwork(networkID string) (string, bool) {
	d := GatewayForNetwork(snap.Devices, snap.Networks, networkID)
	if d == nil {
		return "", false
	}
	return d.Name, true
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
