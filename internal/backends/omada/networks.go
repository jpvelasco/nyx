package omada

import (
	"context"
	"fmt"
)

// Site represents an Omada managed site.
type Site struct {
	ID   string `json:"siteId"`
	Name string `json:"name"`
	Type int    `json:"type"`
}

// Network represents a LAN network / VLAN configured in Omada.
type Network struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Purpose   string `json:"purpose"` // "gateway" | "vlan" | etc.
	VLANID    int    `json:"vlanId"`
	Subnet    string `json:"subnet"`   // CIDR e.g. "192.168.0.0/24"
	Gateway   string `json:"gateway"`  // e.g. "192.168.0.254"
	Isolated  bool   `json:"isolated"` // Omada "Isolated" VLAN flag
	DHCPEnabled bool `json:"dhcpEnabled"`
}

// pageResult is the common paginated wrapper Omada uses for list endpoints.
type pageResult struct {
	TotalRows  int             `json:"totalRows"`
	CurrentRow int             `json:"currentRow"`
	Data       []interface{}   `json:"data"` // overridden per call via typed helpers
}

// GetSites returns all sites managed by the controller.
func (c *Client) GetSites(ctx context.Context) ([]Site, error) {
	var result struct {
		TotalRows int    `json:"totalRows"`
		Data      []Site `json:"data"`
	}
	if err := c.get(ctx, "sites?currentPage=1&currentPageSize=100", &result); err != nil {
		return nil, fmt.Errorf("getting sites: %w", err)
	}
	return result.Data, nil
}

// GetNetworks returns all LAN networks configured for the given site.
// This maps to the inter-VLAN / LAN settings in the Omada controller UI.
func (c *Client) GetNetworks(ctx context.Context, siteID string) ([]Network, error) {
	var result struct {
		TotalRows int       `json:"totalRows"`
		Data      []Network `json:"data"`
	}
	path := fmt.Sprintf("sites/%s/setting/lan/networks?currentPage=1&currentPageSize=100", siteID)
	if err := c.get(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("getting networks for site %s: %w", siteID, err)
	}
	// Fall back: some controller versions return networks directly as array
	if result.Data == nil {
		var direct []Network
		if err := c.get(ctx, path, &direct); err == nil {
			return direct, nil
		}
	}
	return result.Data, nil
}
