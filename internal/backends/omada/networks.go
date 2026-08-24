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
	ID            string
	Name          string
	Purpose       string
	VLANID        int
	GatewaySubnet string // e.g. "10.0.10.1/24"
	Isolated      bool
	DHCPEnabled   bool
	DeviceMac     string // MAC of the device this LAN is bound to
}

// rawNetwork is the wire shape of a network entry (Open API). There is no
// top-level "dhcpEnabled" field — the DHCP switch is nested under
// "dhcpSettingsVO"; deviceMac is optional.
type rawNetwork struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Purpose       string `json:"purpose"`
	VLANID        int    `json:"vlan"`
	GatewaySubnet string `json:"gatewaySubnet"`
	Isolated      bool   `json:"isolation"`
	DHCPSettings  struct {
		Enable bool `json:"enable"`
	} `json:"dhcpSettingsVO"`
	DeviceMac string `json:"deviceMac"`
}

// UnmarshalJSON decodes the wire shape so the nested DHCP switch
// (dhcpSettingsVO.enable) keeps its meaning.
func (n *Network) UnmarshalJSON(data []byte) error {
	var raw rawNetwork
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*n = Network{
		ID:            raw.ID,
		Name:          raw.Name,
		Purpose:       raw.Purpose,
		VLANID:        raw.VLANID,
		GatewaySubnet: raw.GatewaySubnet,
		Isolated:      raw.Isolated,
		DHCPEnabled:   raw.DHCPSettings.Enable,
		DeviceMac:     raw.DeviceMac,
	}
	return nil
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

// FindNetwork resolves a network by display name or sanitized slug
// (e.g. "LAN(Default)" and "lan" are the same network).
func FindNetwork(nets []Network, name string) (Network, bool) {
	slug := sanitizeName(name)
	for _, n := range nets {
		if strings.EqualFold(n.Name, name) || sanitizeName(n.Name) == slug {
			return n, true
		}
	}
	return Network{}, false
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
// of the sites/{id}/lan-networks endpoint.
func (c *Client) GetNetworks(ctx context.Context, siteID string) ([]Network, error) {
	nets, _, err := fetchPaged[Network](ctx, c, fmt.Sprintf("sites/%s/lan-networks", siteID), defaultPageSize)
	if err != nil {
		return nil, fmt.Errorf("could not fetch networks for site %q: %w", siteID, err)
	}
	return nets, nil
}
