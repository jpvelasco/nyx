package service

import (
	"context"
	"strconv"

	backend "github.com/jpvelasco/nyx/internal/backends/omada"
)

// switchClients indexes current wired associations on the selected switch.
// A client without a verifiable attachment prevents a single-client conclusion.
func switchClients(ctx context.Context, client *backend.Client, site, switchMAC string) (map[int][]string, bool) {
	rows, err := client.GetClients(ctx, site)
	if err != nil {
		return nil, false
	}
	ports := map[int][]string{}
	seen := map[string]bool{}
	for _, r := range rows {
		mac := backend.NormalizeMAC(r.MAC)
		if mac == "" {
			return nil, false
		}
		if seen[mac] {
			continue
		}
		seen[mac] = true
		if r.Type == "wireless" {
			continue
		}
		nodes, err := client.GetClientTopology(ctx, site, r.MAC)
		if err != nil {
			return nil, false
		}
		var attachment *backend.ClientTopologyNode
		for i := range nodes {
			n := &nodes[i]
			if n.NodeType != "clientNode" || backend.NormalizeMAC(n.MAC) != mac {
				continue
			}
			if attachment != nil {
				return nil, false
			}
			attachment = n
		}
		if attachment == nil {
			return nil, false
		}
		if attachment.APMAC != "" {
			continue
		}
		port, err := strconv.Atoi(attachment.SwitchPort)
		if attachment.SwitchMAC == "" || err != nil || port <= 0 {
			return nil, false
		}
		if backend.NormalizeMAC(attachment.SwitchMAC) == switchMAC {
			ports[port] = append(ports[port], mac)
		}
	}
	return ports, true
}
