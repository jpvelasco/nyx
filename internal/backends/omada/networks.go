package omada

import (
	"context"
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
	GatewaySubnet string `json:"gatewaySubnet"` // e.g. "10.0.10.1/24"
	Isolated      bool   `json:"isolation"`
	DHCPEnabled   bool   `json:"dhcpEnabled"`
}

// CIDR derives the network CIDR from GatewaySubnet.
// "10.0.10.1/24" → "10.0.10.0/24"
func (n Network) CIDR() string {
	if n.GatewaySubnet == "" {
		return ""
	}
	_, ipnet, err := net.ParseCIDR(n.GatewaySubnet)
	if err != nil {
		return ""
	}
	return ipnet.String()
}

// Gateway extracts the gateway IP from GatewaySubnet.
// "10.0.10.1/24" → "10.0.10.1"
func (n Network) Gateway() string {
	if n.GatewaySubnet == "" {
		return ""
	}
	parts := strings.SplitN(n.GatewaySubnet, "/", 2)
	return parts[0]
}

// GetSites returns all sites managed by the controller, walking every page.
func (c *Client) GetSites(ctx context.Context) ([]Site, error) {
	sites, _, err := fetchPaged[Site](ctx, c, "sites", defaultPageSize)
	if err != nil {
		return nil, fmt.Errorf("getting sites: %w", err)
	}
	if len(sites) > 0 {
		return sites, nil
	}
	return nil, fmt.Errorf("could not parse sites response")
}

// GetNetworks returns all LAN networks for the given site, walking every page
// of the first candidate endpoint that responds with data.
func (c *Client) GetNetworks(ctx context.Context, siteID string) ([]Network, error) {
	paths := []string{
		fmt.Sprintf("sites/%s/setting/lan/networks", siteID),
		fmt.Sprintf("sites/%s/setting/networks", siteID),
		fmt.Sprintf("sites/%s/networks", siteID),
	}

	for _, path := range paths {
		nets, _, err := fetchPaged[Network](ctx, c, path, defaultPageSize)
		if err != nil {
			continue
		}
		if len(nets) > 0 {
			return nets, nil
		}
	}

	return nil, fmt.Errorf("could not fetch networks for site %q", siteID)
}
