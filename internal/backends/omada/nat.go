package omada

import (
	"context"
	"encoding/json"
	"fmt"
)

// PortForwarding is one NAT port-forwarding rule on an Omada gateway
// (GET sites/{siteId}/nat/port-forwardings).
type PortForwarding struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Enabled          bool     `json:"status"`
	From             int      `json:"from"` // 0 = anywhere, 1 = limited addresses
	LimitedAddresses []string `json:"limitedAddresses"`
	ExternalPort     string   `json:"externalPort"`
	ForwardIP        string   `json:"forwardIp"`
	ForwardPort      string   `json:"forwardPort"`
	Protocol         string   // "ALL", "TCP" or "UDP" — the wire value is an int (0/1/2)
	DMZ              bool     `json:"dMZ"`
}

// portForwardingRow is the raw wire shape of a port-forwarding entry.
type portForwardingRow struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Status           bool     `json:"status"`
	From             int      `json:"from"`
	LimitedAddresses []string `json:"limitedAddresses"`
	ExternalPort     string   `json:"externalPort"`
	ForwardIP        string   `json:"forwardIp"`
	ForwardPort      string   `json:"forwardPort"`
	Protocol         int      `json:"protocol"`
	DMZ              bool     `json:"dMZ"`
}

// natProtocol maps the wire protocol int (0 ALL, 1 TCP, 2 UDP) to a name.
func natProtocol(p int) string {
	switch p {
	case 1:
		return "TCP"
	case 2:
		return "UDP"
	default:
		return "ALL"
	}
}

// GetPortForwardings returns NAT port-forwarding rules for a site.
func (c *Client) GetPortForwardings(ctx context.Context, siteID string) ([]PortForwarding, error) {
	rows, _, err := fetchPaged[portForwardingRow](ctx, c, fmt.Sprintf("sites/%s/nat/port-forwardings", siteID), defaultPageSize)
	if err != nil {
		return nil, fmt.Errorf("could not fetch port-forwardings for site %q: %w", siteID, err)
	}
	pfs := make([]PortForwarding, 0, len(rows))
	for _, r := range rows {
		pfs = append(pfs, PortForwarding{
			ID:               r.ID,
			Name:             r.Name,
			Enabled:          r.Status,
			From:             r.From,
			LimitedAddresses: r.LimitedAddresses,
			ExternalPort:     r.ExternalPort,
			ForwardIP:        r.ForwardIP,
			ForwardPort:      r.ForwardPort,
			Protocol:         natProtocol(r.Protocol),
			DMZ:              r.DMZ,
		})
	}
	return pfs, nil
}

// OneToOneNAT is one one-to-one NAT rule on an Omada gateway
// (GET sites/{siteId}/nat/one-to-one-nat).
type OneToOneNAT struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Enabled     bool   `json:"status"`
	InternalIP  string `json:"internalIp"`
	ExternalIP  string `json:"externalIp"`
	DMZ         bool   `json:"dmz"`
	Description string `json:"description"`
}

// GetOneToOneNAT returns one-to-one NAT rules for a site.
func (c *Client) GetOneToOneNAT(ctx context.Context, siteID string) ([]OneToOneNAT, error) {
	rules, _, err := fetchPaged[OneToOneNAT](ctx, c, fmt.Sprintf("sites/%s/nat/one-to-one-nat", siteID), defaultPageSize)
	if err != nil {
		return nil, fmt.Errorf("could not fetch one-to-one NAT rules for site %q: %w", siteID, err)
	}
	return rules, nil
}

// ALGSettings reports which application-layer gateways the Omada gateway NAT
// has enabled (GET sites/{siteId}/nat/alg).
type ALGSettings struct {
	FTP   bool `json:"ftp"`
	H323  bool `json:"h323"`
	PPTP  bool `json:"pptp"`
	SIP   bool `json:"sip"`
	IPsec bool `json:"ipSec"`
}

// GetALG returns the NAT ALG (application-layer gateway) settings for a site.
func (c *Client) GetALG(ctx context.Context, siteID string) (ALGSettings, error) {
	var raw json.RawMessage
	if err := c.get(ctx, fmt.Sprintf("sites/%s/nat/alg", siteID), &raw); err != nil {
		return ALGSettings{}, fmt.Errorf("could not fetch ALG settings for site %q: %w", siteID, err)
	}
	var alg ALGSettings
	if err := json.Unmarshal(raw, &alg); err != nil {
		return ALGSettings{}, fmt.Errorf("decoding alg response: %w", err)
	}
	return alg, nil
}

// FirewallSettings is the Omada gateway firewall session-timeout and
// connection-configuration block (GET sites/{siteId}/firewall). Timeouts are
// in seconds.
type FirewallSettings struct {
	ICMP           int `json:"icmp"`
	Other          int `json:"other"`
	TCPClose       int `json:"tcpClose"`
	TCPCloseWait   int `json:"tcpCloseWait"`
	TCPEstablished int `json:"tcpEstablished"`
	TCPFinWait     int `json:"tcpFinWait"`
	TCPLastAck     int `json:"tcpLastAck"`
	TCPSynReceive  int `json:"tcpSynReceive"`
	TCPSynSent     int `json:"tcpSynSent"`
	TCPTimeWait    int `json:"tcpTimeWait"`
	UDPOther       int `json:"udpOther"`
	UDPStream      int `json:"udpStream"`

	BroadcastPing    bool `json:"broadcastPing"`
	ReceiveRedirects bool `json:"receiveRedirects"`
	SendRedirects    bool `json:"sendRedirects"`
	SynCookies       bool `json:"synCookies"`
}

// GetFirewallSettings returns the gateway firewall settings for a site.
func (c *Client) GetFirewallSettings(ctx context.Context, siteID string) (FirewallSettings, error) {
	var raw json.RawMessage
	if err := c.get(ctx, fmt.Sprintf("sites/%s/firewall", siteID), &raw); err != nil {
		return FirewallSettings{}, fmt.Errorf("could not fetch firewall settings for site %q: %w", siteID, err)
	}
	var fw FirewallSettings
	if err := json.Unmarshal(raw, &fw); err != nil {
		return FirewallSettings{}, fmt.Errorf("decoding firewall settings response: %w", err)
	}
	return fw, nil
}
