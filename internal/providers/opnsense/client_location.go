package opnsense

import (
	"context"
	"net"

	"github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/topology"
)

func (*Provider) ObserveClient(ctx context.Context, opts providers.ImportOptions, mac string) ([]topology.ClientObservation, []string, error) {
	if err := requireAuth(opts); err != nil {
		return nil, nil, err
	}
	target, err := net.ParseMAC(mac)
	if err != nil {
		return nil, nil, err
	}
	matches := func(value string) bool {
		other, err := net.ParseMAC(value)
		return err == nil && other.String() == target.String()
	}
	var facts []topology.ClientObservation
	var gaps []string
	client := newProviderClient(opts)
	leases, err := client.GetDHCPLeases(ctx)
	if err != nil {
		gaps = append(gaps, "DHCP lease inventory")
	}
	for _, l := range leases {
		if matches(l.MAC) {
			facts = append(facts, topology.ClientObservation{Kind: "DHCP lease", Status: "cached", Address: l.IP})
		}
	}
	for _, table := range []struct {
		kind string
		read func(context.Context) ([]Neighbor, error)
	}{{"ARP", client.GetARPNeighbors}, {"NDP", client.GetNDPNeighbors}} {
		rows, err := table.read(ctx)
		if err != nil {
			gaps = append(gaps, table.kind+" table")
			continue
		}
		for _, n := range rows {
			if !matches(n.MAC) {
				continue
			}
			status := "cached"
			if n.Expired {
				status = "expired"
			}
			facts = append(facts, topology.ClientObservation{Kind: table.kind, Status: status, Address: n.IP, Device: n.Interface})
		}
	}
	return facts, gaps, ctx.Err()
}
