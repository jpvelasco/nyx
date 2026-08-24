package omada

import (
	"bytes"
	"fmt"
	"net"
	"sort"
	"strings"
)

// ClientGroup is a set of connected clients that share the same Omada
// network name, sorted by IP address.
type ClientGroup struct {
	NetworkName string
	VLANID      int
	Count       int
	Clients     []ConnectedClient
}

// GroupClientsByNetwork groups clients by their Omada network name (the raw
// name as reported by the controller, e.g. "LAN(Default)"). Clients without
// a network name are grouped under "". Groups are sorted by VLAN id
// ascending, then by network name; clients within a group are sorted by IP
// ascending.
func GroupClientsByNetwork(clients []ConnectedClient) []ClientGroup {
	byName := make(map[string]*ClientGroup)
	for _, c := range clients {
		g, ok := byName[c.NetworkName]
		if !ok {
			g = &ClientGroup{NetworkName: c.NetworkName, VLANID: c.VLANID}
			byName[c.NetworkName] = g
		}
		g.Clients = append(g.Clients, c)
	}

	groups := make([]ClientGroup, 0, len(byName))
	for _, g := range byName {
		sort.Slice(g.Clients, func(i, j int) bool {
			return compareIPs(g.Clients[i].IP, g.Clients[j].IP)
		})
		g.Count = len(g.Clients)
		groups = append(groups, *g)
	}

	sort.Slice(groups, func(i, j int) bool {
		if groups[i].VLANID != groups[j].VLANID {
			return groups[i].VLANID < groups[j].VLANID
		}
		return groups[i].NetworkName < groups[j].NetworkName
	})
	return groups
}

// RenderClientInventory formats a human-readable inventory of clients
// grouped by network. siteName is the Omada site label shown in the header.
func RenderClientInventory(siteName string, clients []ConnectedClient) string {
	groups := GroupClientsByNetwork(clients)
	var b strings.Builder
	fmt.Fprintf(&b, "Site: %s\n\n", siteName)
	if len(groups) == 0 {
		b.WriteString("No clients reported by the controller.\n")
		return b.String()
	}
	for _, g := range groups {
		label := g.NetworkName
		if label == "" {
			label = "unknown network"
		}
		fmt.Fprintf(&b, "== %s (VLAN %d) — %d client%s ==\n",
			label, g.VLANID, g.Count, plural(g.Count))
		for _, c := range g.Clients {
			fmt.Fprintf(&b, "  %-15s %-20s %s\n",
				c.IP, c.Name, c.Type)
		}
		b.WriteString("\n")
	}
	return b.String()
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// compareIPs returns true if a sorts before b. Valid IPs are compared
// numerically (octet by octet); unparseable strings fall back to
// lexicographic order.
func compareIPs(a, b string) bool {
	ipA, ipB := net.ParseIP(a), net.ParseIP(b)
	if ipA != nil && ipB != nil {
		return bytes.Compare(ipA.To16(), ipB.To16()) < 0
	}
	return a < b
}
