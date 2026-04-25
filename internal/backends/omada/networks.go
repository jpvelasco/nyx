package omada

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
)

// Site represents an Omada managed site.
type Site struct {
	ID     string `json:"id"`
	SiteID string `json:"siteId"` // older controller versions
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

// Network represents a LAN network / VLAN from the Omada API.
// Omada 6.x encodes the gateway+prefix in "gatewaySubnet" as "x.x.x.x/prefix".
type Network struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Purpose       string `json:"purpose"`
	VLANID        int    `json:"vlan"`
	GatewaySubnet string `json:"gatewaySubnet"` // e.g. "192.168.0.254/24"
	Isolated      bool   `json:"isolation"`
	DHCPEnabled   bool   `json:"dhcpEnabled"`
}

// CIDR derives the network CIDR from GatewaySubnet.
// "192.168.0.254/24" → "192.168.0.0/24"
func (n Network) CIDR() string {
	if n.GatewaySubnet == "" {
		return ""
	}
	ip, ipnet, err := net.ParseCIDR(n.GatewaySubnet)
	if err != nil {
		return ""
	}
	_ = ip
	return ipnet.String()
}

// Gateway extracts the gateway IP from GatewaySubnet.
// "192.168.0.254/24" → "192.168.0.254"
func (n Network) Gateway() string {
	if n.GatewaySubnet == "" {
		return ""
	}
	parts := strings.SplitN(n.GatewaySubnet, "/", 2)
	return parts[0]
}

// GetSites returns all sites managed by the controller.
func (c *Client) GetSites(ctx context.Context) ([]Site, error) {
	var raw json.RawMessage
	if err := c.get(ctx, "sites?currentPage=1&currentPageSize=100", &raw); err != nil {
		return nil, fmt.Errorf("getting sites: %w", err)
	}

	var paged struct {
		TotalRows int    `json:"totalRows"`
		Data      []Site `json:"data"`
	}
	if err := json.Unmarshal(raw, &paged); err == nil && len(paged.Data) > 0 {
		return paged.Data, nil
	}

	var direct []Site
	if err := json.Unmarshal(raw, &direct); err == nil && len(direct) > 0 {
		return direct, nil
	}

	return nil, fmt.Errorf("could not parse sites response: %s", string(raw))
}

// GetNetworks returns all LAN networks for the given site.
func (c *Client) GetNetworks(ctx context.Context, siteID string) ([]Network, error) {
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
		var paged struct {
			TotalRows int       `json:"totalRows"`
			Data      []Network `json:"data"`
		}
		if err := json.Unmarshal(raw, &paged); err == nil && len(paged.Data) > 0 {
			return paged.Data, nil
		}
		var direct []Network
		if err := json.Unmarshal(raw, &direct); err == nil && len(direct) > 0 {
			return direct, nil
		}
	}

	return nil, fmt.Errorf("could not fetch networks for site %q", siteID)
}
