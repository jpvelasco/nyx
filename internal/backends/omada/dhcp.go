package omada

import (
	"context"
	"fmt"
)

// DHCPServerInfo is the per-network DHCP pool panel
// (GET sites/{siteId}/networks/{networkId}/dhcp-server-info).
type DHCPServerInfo struct {
	AvailableIPs int
	TotalIPs     int
	Start        string
	End          string
}

// DHCPSnoopStatus is the site-wide DHCP snooping switch
// (GET sites/{siteId}/dhcpSnoops/status).
type DHCPSnoopStatus struct {
	Enabled bool
}

// DHCPSnoopRule is one DHCP snooping rule row.
type DHCPSnoopRule struct {
	ID      string
	Name    string
	Enabled bool
}

// LANMulticastRule is one multicast-filter / snooping-tab row.
type LANMulticastRule struct {
	ID      string
	Name    string
	Enabled bool
}

type dhcpServerInfoWire struct {
	AvailableIPCount int    `json:"availableIpCount"`
	TotalIPCount     int    `json:"totalIpCount"`
	IPAddrStart      string `json:"ipaddrStart"`
	IPAddrEnd        string `json:"ipaddrEnd"`
}

type dhcpSnoopStatusWire struct {
	Enable bool `json:"enable"`
	Status bool `json:"status"`
}

type namedToggleRow struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Status  bool   `json:"status"`
}

// GetDHCPServerInfo returns the pool panel for one LAN (available-IP count).
func (c *Client) GetDHCPServerInfo(ctx context.Context, siteID, networkID string) (*DHCPServerInfo, error) {
	var raw dhcpServerInfoWire
	if err := c.get(ctx, fmt.Sprintf("sites/%s/networks/%s/dhcp-server-info", siteID, networkID), &raw); err != nil {
		return nil, fmt.Errorf("getting DHCP server info for network %s: %w", networkID, err)
	}
	return &DHCPServerInfo{
		AvailableIPs: raw.AvailableIPCount,
		TotalIPs:     raw.TotalIPCount,
		Start:        raw.IPAddrStart,
		End:          raw.IPAddrEnd,
	}, nil
}

// GetDHCPSnoopStatus returns the site-wide DHCP snooping switch.
func (c *Client) GetDHCPSnoopStatus(ctx context.Context, siteID string) (*DHCPSnoopStatus, error) {
	var raw dhcpSnoopStatusWire
	if err := c.get(ctx, fmt.Sprintf("sites/%s/dhcpSnoops/status", siteID), &raw); err != nil {
		return nil, fmt.Errorf("getting DHCP snooping status for site %s: %w", siteID, err)
	}
	return &DHCPSnoopStatus{Enabled: raw.Enable || raw.Status}, nil
}

// GetDHCPSnoops returns the paged DHCP snooping rule list.
func (c *Client) GetDHCPSnoops(ctx context.Context, siteID string) ([]DHCPSnoopRule, error) {
	rows, _, err := fetchPaged[namedToggleRow](ctx, c, fmt.Sprintf("sites/%s/dhcpSnoops", siteID), defaultPageSize)
	if err != nil {
		return nil, fmt.Errorf("getting DHCP snooping rules for site %s: %w", siteID, err)
	}
	out := make([]DHCPSnoopRule, 0, len(rows))
	for _, r := range rows {
		out = append(out, DHCPSnoopRule{ID: r.ID, Name: r.Name, Enabled: r.Enabled || r.Status})
	}
	return out, nil
}

// GetLANMulticasts returns the paged multicast-filter / snooping-tab rules.
func (c *Client) GetLANMulticasts(ctx context.Context, siteID string) ([]LANMulticastRule, error) {
	rows, _, err := fetchPaged[namedToggleRow](ctx, c, fmt.Sprintf("sites/%s/lan-multicasts", siteID), defaultPageSize)
	if err != nil {
		return nil, fmt.Errorf("getting LAN multicast rules for site %s: %w", siteID, err)
	}
	out := make([]LANMulticastRule, 0, len(rows))
	for _, r := range rows {
		out = append(out, LANMulticastRule{ID: r.ID, Name: r.Name, Enabled: r.Enabled || r.Status})
	}
	return out, nil
}
