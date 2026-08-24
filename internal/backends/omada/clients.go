package omada

import (
	"context"
	"fmt"
)

// ConnectedClient represents a client connected to the network. The
// networks/client endpoint returns thin rows (mac/name/type only); IP,
// NetworkName, and VLANID are filled in by EnrichFromDHCP from the site's
// DHCP user list.
type ConnectedClient struct {
	MAC         string `json:"mac"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	IP          string
	NetworkName string
	VLANID      int
}

// dhcpUserRow is one row of the sites/{id}/setting/service/dhcp/user-list
// endpoint: an active lease, keyed by MAC.
type dhcpUserRow struct {
	IPAddress  string `json:"ipAddress"`
	MACAddress string `json:"macAddress"`
	Name       string `json:"name"`
	NetID      string `json:"netId"`
	NetName    string `json:"netName"`
}

// GetClients returns all connected clients for the given site, walking every
// page of the sites/{id}/networks/client endpoint.
func (c *Client) GetClients(ctx context.Context, siteID string) ([]ConnectedClient, error) {
	path := fmt.Sprintf("sites/%s/networks/client", siteID)
	clients, _, err := fetchPaged[ConnectedClient](ctx, c, path, defaultPageSize)
	if err != nil {
		return nil, fmt.Errorf("getting clients for site %s: %w", siteID, err)
	}
	return clients, nil
}

// EnrichFromDHCP joins the site's DHCP user list onto the client rows by
// normalized MAC. On a hit the client's IP, network name, and VLAN id are
// filled in (the VLAN id comes from the network matching the row's netId);
// clients without a DHCP row keep their thin fields and no IP.
func (c *Client) EnrichFromDHCP(ctx context.Context, siteID string, clients []ConnectedClient, networks []Network) error {
	rows, _, err := fetchPaged[dhcpUserRow](ctx, c, fmt.Sprintf("sites/%s/setting/service/dhcp/user-list", siteID), defaultPageSize)
	if err != nil {
		return fmt.Errorf("getting DHCP user list for site %s: %w", siteID, err)
	}

	byNetID := make(map[string]Network, len(networks))
	for _, n := range networks {
		if n.ID != "" {
			byNetID[n.ID] = n
		}
	}

	byMAC := make(map[string]dhcpUserRow, len(rows))
	for _, row := range rows {
		key := normalizeMAC(row.MACAddress)
		if key == "" {
			continue
		}
		if _, taken := byMAC[key]; !taken {
			byMAC[key] = row
		}
	}

	for i := range clients {
		cl := &clients[i]
		row, ok := byMAC[normalizeMAC(cl.MAC)]
		if !ok {
			continue
		}
		cl.IP = row.IPAddress
		if n, found := byNetID[row.NetID]; found {
			cl.NetworkName = n.Name
			cl.VLANID = n.VLANID
		} else {
			cl.NetworkName = row.NetName
		}
	}
	return nil
}
