package omada

import (
	"strings"
)

// EnrichClients resolves each client's NetworkName (raw LAN name, e.g.
// "Trusted") and VLANID from the site's LAN networks. The 6.x clients endpoint
// reports an SSID and a per-row "vid" — not a network name — and omits "vid"
// on some wireless rows. Resolution order per client:
//
//  1. SSID matched case-insensitively against a network's SSID (origName)
//     or display name
//  2. VLANID matched against a network's VLAN id
//  3. otherwise NetworkName stays empty and VLANID is preserved as reported
//
// Controllers that already report a "networkName" field are left untouched.
// Mutates in place; the caller owns the slice.
func EnrichClients(clients []ConnectedClient, networks []Network) {
	bySSID, byVLAN := clientNetworkIndex(networks)
	for i := range clients {
		c := &clients[i]
		if c.NetworkName != "" {
			continue
		}
		// SSID lookup: the index never stores an empty key, so an empty
		// SSID is a guaranteed miss and needs no separate guard.
		if n, ok := bySSID[strings.ToLower(c.SSID)]; ok {
			c.NetworkName = n.Name
			if c.VLANID == 0 {
				c.VLANID = n.VLANID
			}
			continue
		}
		if c.VLANID > 0 {
			c.NetworkName = byVLAN[c.VLANID].Name
		}
	}
}

// clientNetworkIndex builds case-insensitive SSID→network and VLAN→network
// lookups. A network's SSID is indexed under both its origName (what
// clients report on the wire, e.g. "LAN") and its display name
// ("LAN(Default)"), so an SSID of either form resolves. On
// collisions the first network wins — VLAN ids are unique in practice and
// SSIDs are operator-chosen to be distinct.
func clientNetworkIndex(networks []Network) (map[string]Network, map[int]Network) {
	bySSID := make(map[string]Network, len(networks)*2)
	for _, n := range networks {
		for _, s := range []string{n.SSID, n.Name} {
			if s == "" {
				continue
			}
			key := strings.ToLower(s)
			if _, taken := bySSID[key]; !taken {
				bySSID[key] = n
			}
		}
	}
	byVLAN := make(map[int]Network, len(networks))
	for _, n := range networks {
		if n.VLANID > 0 {
			if _, taken := byVLAN[n.VLANID]; !taken {
				byVLAN[n.VLANID] = n
			}
		}
	}
	return bySSID, byVLAN
}
