package omada

import (
	"context"
	"fmt"
)

// ConnectedClient represents a device currently connected to the network.
type ConnectedClient struct {
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Name     string `json:"name"`
	Hostname string `json:"hostName"`
	// SSID is the wireless SSID the client joined, as reported per-client
	// (e.g. "Trusted"). Wired clients have no SSID.
	SSID string `json:"ssid"`
	// VLANID is the VLAN id the client's IP was assigned from. The 6.x
	// controller omits "vid" on some entries (mostly wireless), so it
	// decodes to 0; EnrichClients resolves it from the SSID.
	VLANID int `json:"vid"`
	// NetworkName is the raw LAN name the client belongs to (e.g.
	// "Trusted"). The 6.x wire does not report a "networkName" field — this
	// is populated by EnrichClients from the client's SSID or VLANID,
	// and is left as decoded for controllers that do send it.
	NetworkName string `json:"networkName"`
	Wireless    bool   `json:"wireless"`
	Vendor      string `json:"vendor"`
	DeviceType  string `json:"deviceType"`
	Active      bool   `json:"active"`
	Uptime      int64  `json:"uptime"`
}

// GetClients returns all active connected clients for the given site,
// walking every page.
//
// The clients endpoint requires the filters.active=true query: without it
// the 6.x controller returns errorCode -1 ("General error.").
func (c *Client) GetClients(ctx context.Context, siteID string) ([]ConnectedClient, error) {
	path := fmt.Sprintf("sites/%s/clients", siteID)
	clients, _, err := fetchPaged[ConnectedClient](ctx, c, path, defaultPageSize, "filters.active=true")
	if err != nil {
		return nil, fmt.Errorf("getting clients for site %s: %w", siteID, err)
	}
	return clients, nil
}
