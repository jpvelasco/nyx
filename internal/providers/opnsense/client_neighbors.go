package opnsense

import "context"

// Neighbor is a cached layer-three observation from the IPv4 ARP or IPv6
// NDP table. The interface is the firewall's local device name.
type Neighbor struct {
	MAC       string `json:"mac"`
	IP        string `json:"ip"`
	Interface string `json:"intf"`
	Expired   bool   `json:"expired"`
}

func (c *Client) GetARPNeighbors(ctx context.Context) ([]Neighbor, error) {
	return readFirewallJSON[Neighbor](ctx, c, "/diagnostics/interface/get_arp", nil)
}

func (c *Client) GetNDPNeighbors(ctx context.Context) ([]Neighbor, error) {
	return readFirewallJSON[Neighbor](ctx, c, "/diagnostics/interface/get_ndp", nil)
}
