package omada

import (
	"context"
	"fmt"
	"net"
	"net/url"
)

// ClientHistory is a prior association record, which may outlive an attachment.
// LastSeen is preserved in the controller's units because the stable schema
// identifies it as an integer and does not specify its time unit.
type ClientHistory struct {
	MAC        string `json:"mac"`
	DeviceName string `json:"deviceName"`
	SSID       string `json:"ssid"`
	Port       int    `json:"port"`
	VLAN       int    `json:"vid"`
	LastSeen   int64  `json:"lastSeen"`
}

// GetClientHistory reads history for one selected client MAC.
func (c *Client) GetClientHistory(ctx context.Context, siteID, clientMAC string) ([]ClientHistory, error) {
	mac, err := net.ParseMAC(dashMAC(clientMAC))
	if err != nil || len(mac) != 6 {
		return nil, fmt.Errorf("invalid client MAC for history")
	}
	path := fmt.Sprintf("sites/%s/clients/%s/client-history", url.PathEscape(siteID), dashMAC(mac.String()))
	rows, _, err := fetchPaged[ClientHistory](ctx, c, path, defaultPageSize)
	return rows, err
}
