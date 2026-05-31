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
	NetworkName string `json:"networkName"` // e.g. "Nightfall", "Pinball"
	SSID        string `json:"ssid"`
	VLANID      int    `json:"vid"`
	Wireless    bool   `json:"wireless"`
	Vendor      string `json:"vendor"`
	DeviceType  string `json:"deviceType"`
	Active      bool   `json:"active"`
	Uptime      int64  `json:"uptime"`
}

// GetClients returns all active connected clients for the given site.
func (c *Client) GetClients(ctx context.Context, siteID string) ([]ConnectedClient, error) {
	var result struct {
		TotalRows int               `json:"totalRows"`
		Data      []ConnectedClient `json:"data"`
	}
	path := fmt.Sprintf("sites/%s/clients?currentPage=1&currentPageSize=200&filters.active=true", siteID)
	if err := c.get(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("getting clients for site %s: %w", siteID, err)
	}
	return result.Data, nil
}
