package omada

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// Device is one managed device (gateway, switch, or AP) from the site's
// device inventory.
type Device struct {
	Name            string `json:"name"`
	Model           string `json:"model"`
	Type            string `json:"type"` // "gateway" | "switch" | "ap"
	MAC             string `json:"mac"`
	IP              string `json:"ip"`
	FirmwareVersion string `json:"firmwareVersion"`
	NeedUpgrade     bool   `json:"needUpgrade"`
}

// IsGateway reports whether the device is the site's managed gateway.
func (d Device) IsGateway() bool { return strings.EqualFold(d.Type, "gateway") }

// IsSwitch reports whether the device is a managed switch.
func (d Device) IsSwitch() bool { return strings.EqualFold(d.Type, "switch") }

// IsAP reports whether the device is a wireless access point.
func (d Device) IsAP() bool { return strings.EqualFold(d.Type, "ap") }

// GetDevices returns the managed devices for a site.
func (c *Client) GetDevices(ctx context.Context, siteID string) ([]Device, error) {
	devices, _, err := fetchPaged[Device](ctx, c, fmt.Sprintf("sites/%s/networks/devices", siteID), defaultPageSize)
	if err != nil {
		return nil, fmt.Errorf("getting devices for site %s: %w", siteID, err)
	}
	return devices, nil
}

// boundGatewayDevice resolves the managed gateway a network's LAN is bound
// to. Precedence:
//
//  1. MAC — the network's "deviceMac" against a gateway's MAC (authoritative
//     when the field is present).
//  2. IP — the network's gateway address (from "gatewaySubnet") against a
//     gateway's device IP (the management LAN, or a gateway exposed per-VLAN).
//  3. Single-gateway fallback — when the LAN carries no explicit binding and
//     the site has exactly one managed gateway, that device is the only one
//     inter-VLAN traffic can transit.
//
// Omada 6.2.x serves lan-networks rows without deviceMac, and a managed
// gateway's per-VLAN routed addresses do not appear in the device inventory
// (only its management IP does), so on a one-gateway site the fallback is
// the only evidence left that the LAN transits the managed gateway.
// Multi-gateway sites are left unbound rather than guessed.
func boundGatewayDevice(devices []Device, n Network) *Device {
	var gws []Device
	for i := range devices {
		if devices[i].IsGateway() {
			gws = append(gws, devices[i])
		}
	}
	if n.DeviceMac != "" {
		for i := range gws {
			if gws[i].MAC != "" && NormalizeMAC(gws[i].MAC) == NormalizeMAC(n.DeviceMac) {
				return &gws[i]
			}
		}
	}
	if gw := n.Gateway(); gw != "" {
		for i := range gws {
			if gws[i].IP == gw {
				return &gws[i]
			}
		}
	}
	if n.DeviceMac == "" && len(gws) == 1 {
		return &gws[0]
	}
	return nil
}

// GatewayForNetwork returns the managed gateway bound to the given network,
// or nil when the inventory has no gateway or the network is not bound to
// one (e.g. third-party gateway setups).
func GatewayForNetwork(devices []Device, networks []Network, networkID string) *Device {
	for i := range networks {
		if networks[i].ID == networkID {
			return boundGatewayDevice(devices, networks[i])
		}
	}
	return nil
}

// NetworkGatewayMap maps raw network names to the name of the device their
// LAN is bound to. Networks not bound to any inventoried device map to "".
func NetworkGatewayMap(devices []Device, networks []Network) map[string]string {
	out := make(map[string]string, len(networks))
	for _, n := range networks {
		name := ""
		if d := boundGatewayDevice(devices, n); d != nil {
			name = d.Name
		}
		out[n.Name] = name
	}
	return out
}

// NormalizeMAC lowercases and strips all separators (colons, dashes,
// spaces) so 00:11:22:33:44:55, 00-11-22-33-44-55, and space-separated
// forms all compare equal.
func NormalizeMAC(mac string) string {
	mac = strings.ToLower(mac)
	mac = strings.ReplaceAll(mac, ":", "")
	mac = strings.ReplaceAll(mac, "-", "")
	mac = strings.ReplaceAll(mac, " ", "")
	return mac
}

// dashMAC formats a MAC as aa-bb-cc-dd-ee-00 for Open API path segments
// that use dash separators (e.g. the gateway DHCP user list).
func dashMAC(mac string) string {
	n := NormalizeMAC(mac)
	if len(n) != 12 {
		return mac
	}
	var b strings.Builder
	for i := 0; i < 12; i += 2 {
		if i > 0 {
			b.WriteByte('-')
		}
		b.WriteString(n[i : i+2])
	}
	return b.String()
}

// SortedDevices returns a copy of the slice sorted by type (gateway,
// switch, ap, other) then name so inventory output is stable across runs.
func SortedDevices(devices []Device) []Device {
	out := append([]Device(nil), devices...)
	sort.Slice(out, func(i, j int) bool {
		ri, rj := typeRank(out[i].Type), typeRank(out[j].Type)
		if ri != rj {
			return ri < rj
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func typeRank(typ string) int {
	switch strings.ToLower(typ) {
	case "gateway":
		return 0
	case "switch":
		return 1
	case "ap":
		return 2
	default:
		return 3
	}
}
