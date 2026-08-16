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
	ControllerVersion string
	Devices           []Device
	Networks          []Network
	Bindings          NetworkBindings
	GatewayACLs       ACLList
	SwitchACLs        ACLList
	GatewayACLsOK     bool
	SwitchACLsOK      bool
	Clients           []ConnectedClient
	Warnings          []string
}

// FetchInventory loads the site's full observation in one pass. Network
// fetch failure is fatal; everything else degrades to a warning.
func (c *Client) FetchInventory(ctx context.Context, siteID string) (*InventorySnapshot, error) {
	nets, err := c.GetNetworks(ctx, siteID)
	if err != nil {
		return nil, err
	}
	snap := &InventorySnapshot{
		ControllerVersion: c.Info().ControllerVer,
		Networks:          nets,
		Bindings:          BuildNetworkBindings(nets),
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
	} else {
		EnrichClients(clients, nets)
		snap.Clients = clients
	}
	return snap, nil
}

// BuildSpecInventory converts the snapshot into the spec's optional
// inventory block. Device and gateway names stay raw; network names are
// sanitized to match the spec's network entries.
func BuildSpecInventory(snap *InventorySnapshot) *intent.Inventory {
	inv := &intent.Inventory{
		ControllerVersion: snap.ControllerVersion,
		NetworkGateways:   make(map[string]string),
	}
	gwMap := NetworkGatewayMap(snap.Devices, snap.Networks, snap.Bindings)
	for _, n := range snap.Networks {
		inv.NetworkGateways[sanitizeName(n.Name)] = gwMap[n.Name]
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
			if n.DeviceMac != "" && d.MAC != "" && normalizeMAC(n.DeviceMac) == normalizeMAC(d.MAC) {
				dev.Networks = append(dev.Networks, sanitizeName(n.Name))
			}
		}
		inv.Devices = append(inv.Devices, dev)
	}
	if snap.GatewayACLsOK {
		inv.ACLScopes = append(inv.ACLScopes, aclScopeStatus("gateway", snap.GatewayACLs))
	}
	if snap.SwitchACLsOK {
		inv.ACLScopes = append(inv.ACLScopes, aclScopeStatus("switch", snap.SwitchACLs))
	}
	return inv
}

func aclScopeStatus(scope string, list ACLList) intent.ACLScopeStatus {
	s := intent.ACLScopeStatus{Scope: scope, Enabled: !list.ACLDisable, RuleCount: len(list.Rules)}
	if scope == "gateway" {
		v := list.SupportLanToLan
		s.SupportLanToLan = &v
	}
	return s
}

// RenderInventory formats the snapshot as a stable, human-readable map of
// the site. It is the standing "where is everything" surface.
func RenderInventory(snap *InventorySnapshot, siteName string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Site: %s\n", siteName)
	if snap.ControllerVersion != "" {
		fmt.Fprintf(&b, "Controller: %s\n", snap.ControllerVersion)
	}
	for _, w := range snap.Warnings {
		fmt.Fprintf(&b, "Warning: %s\n", w)
	}

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
	state := "enabled"
	if list.ACLDisable {
		state = "DISABLED — stored rules are not enforced"
	}
	extra := ""
	if scope == "gateway" && list.SupportLanToLan {
		extra = " (lan-to-lan supported)"
	}
	fmt.Fprintf(b, "  %-8s %-55s %d rule%s%s\n", scope+":", state, len(list.Rules), plural(len(list.Rules)), extra)
}

// GatewayForNetwork is a snapshot-level convenience over the binding lookup.
func (snap *InventorySnapshot) GatewayForNetwork(networkID string) (string, bool) {
	d := GatewayForNetwork(snap.Devices, networkID, snap.Bindings)
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
