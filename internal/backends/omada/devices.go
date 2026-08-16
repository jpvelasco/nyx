package omada

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Device is one managed device (gateway, switch, or AP) from the site's
// device inventory. The devices endpoint returns a flat array in the result
// field; a paged {"data":[...]} wrapper is accepted as a fallback.
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
	path := fmt.Sprintf("sites/%s/devices", siteID)
	var raw json.RawMessage
	if err := c.get(ctx, path, &raw); err != nil {
		return nil, fmt.Errorf("getting devices for site %s: %w", siteID, err)
	}
	var devices []Device
	if err := json.Unmarshal(raw, &devices); err == nil {
		return devices, nil
	}
	var paged struct {
		Data []Device `json:"data"`
	}
	if err := json.Unmarshal(raw, &paged); err != nil {
		return nil, fmt.Errorf("decoding device inventory for site %s: %w", siteID, err)
	}
	return paged.Data, nil
}

// NetworkBindings maps network IDs to the MAC of the device each LAN is
// bound to (the "deviceMac" of its LAN entry). It is the evidence that
// inter-VLAN traffic transits the managed gateway.
type NetworkBindings map[string]string // network ID -> device MAC

// BuildNetworkBindings indexes the LAN networks by their bound gateway MAC.
func BuildNetworkBindings(networks []Network) NetworkBindings {
	bindings := make(NetworkBindings, len(networks))
	for _, n := range networks {
		if n.DeviceMac != "" {
			bindings[n.ID] = n.DeviceMac
		}
	}
	return bindings
}

// GatewayForNetwork returns the managed gateway bound to the given network,
// or nil when the inventory has no gateway or the network is not bound to
// one (e.g. third-party gateway setups).
func GatewayForNetwork(devices []Device, networkID string, bindings NetworkBindings) *Device {
	mac, ok := bindings[networkID]
	if !ok {
		return nil
	}
	for i := range devices {
		if devices[i].IsGateway() && devices[i].MAC != "" &&
			normalizeMAC(devices[i].MAC) == normalizeMAC(mac) {
			return &devices[i]
		}
	}
	return nil
}

// NetworkGatewayMap maps raw network names to the name of the device their
// LAN is bound to. Networks not bound to any inventoried device map to "".
func NetworkGatewayMap(devices []Device, networks []Network, bindings NetworkBindings) map[string]string {
	byMAC := make(map[string]string, len(devices))
	for _, d := range devices {
		if d.MAC != "" {
			byMAC[normalizeMAC(d.MAC)] = d.Name
		}
	}
	out := make(map[string]string, len(networks))
	for _, n := range networks {
		name := ""
		if mac, ok := bindings[n.ID]; ok {
			name = byMAC[normalizeMAC(mac)]
		}
		out[n.Name] = name
	}
	return out
}

// normalizeMAC lowercases and strips all separators (colons, dashes,
// spaces) so 00:11:22:33:44:55, 00-11-22-33-44-55, and space-separated
// forms all compare equal.
func normalizeMAC(mac string) string {
	mac = strings.ToLower(mac)
	mac = strings.ReplaceAll(mac, ":", "")
	mac = strings.ReplaceAll(mac, "-", "")
	mac = strings.ReplaceAll(mac, " ", "")
	return mac
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
