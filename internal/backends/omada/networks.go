package omada

import (
	"context"
	"encoding/json"
	"fmt"
)

// Site represents an Omada managed site.
// Field names vary across controller versions — we try both.
type Site struct {
	ID   string `json:"id"`
	// Older controller versions use "siteId"
	SiteID string `json:"siteId"`
	Name   string `json:"name"`
	Type   int    `json:"type"`
}

// EffectiveID returns whichever ID field is populated.
func (s Site) EffectiveID() string {
	if s.ID != "" {
		return s.ID
	}
	return s.SiteID
}

// Network represents a LAN network / VLAN configured in Omada.
type Network struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Purpose     string `json:"purpose"`
	VLANID      int    `json:"vlanId"`
	Subnet      string `json:"subnet"`
	Gateway     string `json:"gateway"`
	Isolated    bool   `json:"isolated"`
	DHCPEnabled bool   `json:"dhcpEnabled"`
}

// GetSites returns all sites managed by the controller.
func (c *Client) GetSites(ctx context.Context) ([]Site, error) {
	// Capture raw result so we can inspect the actual shape if parsing fails
	var raw json.RawMessage
	if err := c.get(ctx, "sites?currentPage=1&currentPageSize=100", &raw); err != nil {
		return nil, fmt.Errorf("getting sites: %w", err)
	}

	// Try paginated wrapper first
	var paged struct {
		TotalRows int    `json:"totalRows"`
		Data      []Site `json:"data"`
	}
	if err := json.Unmarshal(raw, &paged); err == nil && len(paged.Data) > 0 {
		return paged.Data, nil
	}

	// Try direct array
	var direct []Site
	if err := json.Unmarshal(raw, &direct); err == nil && len(direct) > 0 {
		return direct, nil
	}

	// Store raw for diagnostics and return empty
	c.lastRaw = map[string]json.RawMessage{"sites": raw}
	return nil, fmt.Errorf("could not parse sites response — run with --debug to see raw output.\nRaw: %s", string(raw))
}

// GetNetworks returns all LAN networks configured for the given site.
func (c *Client) GetNetworks(ctx context.Context, siteID string) ([]Network, error) {
	// Try known path variants for 6.x
	paths := []string{
		fmt.Sprintf("sites/%s/setting/lan/networks?currentPage=1&currentPageSize=100", siteID),
		fmt.Sprintf("sites/%s/setting/networks?currentPage=1&currentPageSize=100", siteID),
		fmt.Sprintf("sites/%s/networks?currentPage=1&currentPageSize=100", siteID),
	}

	for _, path := range paths {
		var raw json.RawMessage
		if err := c.get(ctx, path, &raw); err != nil {
			continue
		}

		// Try paginated
		var paged struct {
			TotalRows int       `json:"totalRows"`
			Data      []Network `json:"data"`
		}
		if err := json.Unmarshal(raw, &paged); err == nil && len(paged.Data) > 0 {
			return paged.Data, nil
		}

		// Try direct array
		var direct []Network
		if err := json.Unmarshal(raw, &direct); err == nil && len(direct) > 0 {
			return direct, nil
		}
	}

	return nil, fmt.Errorf("could not fetch networks for site %q — no supported path responded with data", siteID)
}
