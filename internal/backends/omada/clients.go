package omada

import (
	"context"
	"fmt"
)

// ConnectedClient represents a device currently connected to the network.
type ConnectedClient struct {
	MAC         string `json:"mac"`
	IP          string `json:"ip"`
	Name        string `json:"name"`
	Hostname    string `json:"hostName"`
	NetworkName string `json:"networkName"` // e.g. "Trusted", "IoT"
	SSID        string `json:"ssid"`
	VLANID      int    `json:"vid"`
	Wireless    bool   `json:"wireless"`
	Vendor      string `json:"vendor"`
	DeviceType  string `json:"deviceType"`
	Active      bool   `json:"active"`
	Uptime      int64  `json:"uptime"`
}

// GetClients returns all active connected clients for the given site,
// walking every page.
func (c *Client) GetClients(ctx context.Context, siteID string) ([]ConnectedClient, error) {
	path := fmt.Sprintf("sites/%s/clients", siteID)
	clients, _, err := fetchPaged[ConnectedClient](ctx, c, path, defaultPageSize, "filters.active=true")
	if err != nil {
		return nil, fmt.Errorf("getting clients for site %s: %w", siteID, err)
	}
	return clients, nil
}
