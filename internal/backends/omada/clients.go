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

// GatewayDHCPUser is one row of the fresher per-gateway DHCP lease table
// (GET sites/{siteId}/gateways/{gatewayMac}/dhcp/user-list). pageSize is
// required; page starts at 1. MACs may be dash-separated.
type GatewayDHCPUser struct {
	IP           string
	MAC          string
	Name         string
	NetworkName  string
	LeftLeaseSec int
}

type gatewayDHCPUserRow struct {
	IPAddress     string `json:"ipAddress"`
	MACAddress    string `json:"macAddress"`
	Name          string `json:"name"`
	NetName       string `json:"netName"`
	LeftLeaseTime int    `json:"leftLeaseTime"`
}

// GetGatewayDHCPUsers returns the gateway's DHCP lease table. gatewayMAC
// is normalized for the path (controller accepts either separator).
func (c *Client) GetGatewayDHCPUsers(ctx context.Context, siteID, gatewayMAC string) ([]GatewayDHCPUser, error) {
	path := fmt.Sprintf("sites/%s/gateways/%s/dhcp/user-list", siteID, dashMAC(gatewayMAC))
	rows, _, err := fetchPaged[gatewayDHCPUserRow](ctx, c, path, defaultPageSize)
	if err != nil {
		return nil, fmt.Errorf("getting gateway DHCP users for site %s: %w", siteID, err)
	}
	out := make([]GatewayDHCPUser, 0, len(rows))
	for _, r := range rows {
		out = append(out, GatewayDHCPUser{
			IP:           r.IPAddress,
			MAC:          r.MACAddress,
			Name:         r.Name,
			NetworkName:  r.NetName,
			LeftLeaseSec: r.LeftLeaseTime,
		})
	}
	return out, nil
}

// ClientTopologyNode is one hop in the client's uplink chain. nodeType is
// "clientNode" for the client itself and "deviceNode" for managed
// switches/APs/gateways. A dumb switch does not appear; the chain stops
// at the managed port it is cabled into.
type ClientTopologyNode struct {
	NodeType   string
	MAC        string
	Name       string
	Model      string
	ClientType string
	// Uplink switch port (client node) or this device's own switch info.
	SwitchMAC  string
	SwitchName string
	SwitchPort string
	// Uplink AP radio (client node) when the client is wireless.
	APMAC     string
	APName    string
	LinkSpeed int
	RSSI      int
}

type rawTopologyNode struct {
	NodeType   string `json:"nodeType"`
	ClientNode struct {
		MAC        string `json:"mac"`
		Name       string `json:"name"`
		Model      string `json:"model"`
		ClientType string `json:"clientType"`
		UpOswInfo  struct {
			MAC       string `json:"mac"`
			Name      string `json:"name"`
			Port      string `json:"port"`
			LinkSpeed int    `json:"linkSpeed"`
		} `json:"upOswInfo"`
		UpApInfo struct {
			MAC   string `json:"mac"`
			Name  string `json:"name"`
			RSSI  int    `json:"rssi"`
			Radio string `json:"radio"`
		} `json:"upApInfo"`
	} `json:"clientNode"`
	DeviceNode struct {
		MAC        string `json:"mac"`
		Name       string `json:"name"`
		Model      string `json:"model"`
		SwitchInfo struct {
			MAC  string `json:"mac"`
			Name string `json:"name"`
			Port string `json:"port"`
		} `json:"switchInfo"`
		ApInfo struct {
			MAC  string `json:"mac"`
			Name string `json:"name"`
			RSSI int    `json:"rssi"`
		} `json:"apInfo"`
	} `json:"deviceNode"`
}

// GetClientTopology POSTs an empty body to the per-client link-topology
// endpoint and returns the uplink chain. GET on this path is -1600.
func (c *Client) GetClientTopology(ctx context.Context, siteID, clientMAC string) ([]ClientTopologyNode, error) {
	path := fmt.Sprintf("sites/%s/clients/%s/client-link-topology", siteID, dashMAC(clientMAC))
	var raw []rawTopologyNode
	if err := c.post(ctx, path, nil, &raw); err != nil {
		return nil, fmt.Errorf("getting client topology for site %s: %w", siteID, err)
	}
	out := make([]ClientTopologyNode, 0, len(raw))
	for _, n := range raw {
		node := ClientTopologyNode{NodeType: n.NodeType}
		if n.NodeType == "clientNode" || n.ClientNode.MAC != "" {
			node.MAC = n.ClientNode.MAC
			node.Name = n.ClientNode.Name
			node.Model = n.ClientNode.Model
			node.ClientType = n.ClientNode.ClientType
			node.SwitchMAC = n.ClientNode.UpOswInfo.MAC
			node.SwitchName = n.ClientNode.UpOswInfo.Name
			node.SwitchPort = n.ClientNode.UpOswInfo.Port
			node.LinkSpeed = n.ClientNode.UpOswInfo.LinkSpeed
			node.APMAC = n.ClientNode.UpApInfo.MAC
			node.APName = n.ClientNode.UpApInfo.Name
			node.RSSI = n.ClientNode.UpApInfo.RSSI
		} else {
			node.MAC = n.DeviceNode.MAC
			node.Name = n.DeviceNode.Name
			node.Model = n.DeviceNode.Model
			node.SwitchMAC = n.DeviceNode.SwitchInfo.MAC
			node.SwitchName = n.DeviceNode.SwitchInfo.Name
			node.SwitchPort = n.DeviceNode.SwitchInfo.Port
			node.APMAC = n.DeviceNode.ApInfo.MAC
			node.APName = n.DeviceNode.ApInfo.Name
			node.RSSI = n.DeviceNode.ApInfo.RSSI
		}
		out = append(out, node)
	}
	return out, nil
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
		key := NormalizeMAC(row.MACAddress)
		if key == "" {
			continue
		}
		if _, taken := byMAC[key]; !taken {
			byMAC[key] = row
		}
	}

	for i := range clients {
		cl := &clients[i]
		row, ok := byMAC[NormalizeMAC(cl.MAC)]
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
