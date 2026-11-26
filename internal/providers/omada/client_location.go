package omadaprovider

import (
	"context"
	"strconv"

	backend "github.com/jpvelasco/nyx/internal/backends/omada"
	"github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/topology"
)

func (*OmadaProvider) ObserveClient(ctx context.Context, opts providers.ImportOptions, mac string) ([]topology.ClientObservation, []string, error) {
	client, site, err := openACLSite(ctx, opts)
	if err != nil {
		return nil, nil, err
	}
	defer client.Logout(ctx)
	siteID := site.EffectiveID()
	var facts []topology.ClientObservation
	var gaps []string
	rows, err := client.GetClients(ctx, siteID)
	if err != nil {
		gaps = append(gaps, "client association inventory")
	}
	connected := false
	for _, r := range rows {
		if backend.NormalizeMAC(r.MAC) == backend.NormalizeMAC(mac) {
			connected = true
			break
		}
	}
	if connected {
		nodes, err := client.GetClientTopology(ctx, siteID, mac)
		if err != nil {
			gaps = append(gaps, "client uplink inventory")
		}
		seen := false
		for _, n := range nodes {
			if n.NodeType != "clientNode" || backend.NormalizeMAC(n.MAC) != backend.NormalizeMAC(mac) {
				continue
			}
			f := topology.ClientObservation{Kind: "association", Status: "current"}
			if n.APMAC != "" {
				f.Attachment = topology.ResourceRef{Kind: "ap", Key: backend.NormalizeMAC(n.APMAC)}
				f.Device = n.APName
			} else if n.SwitchMAC != "" {
				f.Port, _ = strconv.Atoi(n.SwitchPort)
				f.Attachment = mapPort(n.SwitchMAC, f.Port)
				f.Device = n.SwitchName
			}
			facts = append(facts, f)
			seen = true
		}
		if !seen {
			facts = append(facts, topology.ClientObservation{Kind: "association", Status: "current"})
		}
	}
	history, err := client.GetClientHistory(ctx, siteID, mac)
	if err != nil {
		gaps = append(gaps, "client history")
	}
	for _, h := range history {
		if backend.NormalizeMAC(h.MAC) != backend.NormalizeMAC(mac) {
			continue
		}
		facts = append(facts, topology.ClientObservation{Kind: "history", Status: "historical", Port: h.Port, VLAN: h.VLAN, Device: h.DeviceName, SSID: h.SSID, LastSeen: h.LastSeen})
	}
	return facts, gaps, ctx.Err()
}
