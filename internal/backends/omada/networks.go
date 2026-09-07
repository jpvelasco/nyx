package omada

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
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
	DHCPStart     string
	DHCPEnd       string
	LeaseTime     int
	DHCPDNS       string
	IGMPSnoop     bool
	MLDSnoop      bool
	DHCPL2Relay   bool
	DHCPGuard     bool
	DHCPv6Guard   bool
	Portal        bool
	AllLan        bool
	Primary       bool
}

// LANWrite is the create/update payload for a site LAN network.
type LANWrite struct {
	Name              string         `json:"name"`
	Purpose           int            `json:"purpose"` // 0 VLAN
	VLANID            int            `json:"vlan"`
	GatewaySubnet     string         `json:"gatewaySubnet"`
	Isolation         bool           `json:"isolation"`
	IGMPSnoopEnable   bool           `json:"igmpSnoopEnable"`
	MLDSnoopEnable    bool           `json:"mldSnoopEnable"`
	DHCPL2RelayEnable bool           `json:"dhcpL2RelayEnable"`
	DHCPGuard         bool           `json:"dhcpGuard"`
	DHCPv6Guard       bool           `json:"dhcpv6Guard"`
	DHCPSettings      DHCPSettingsVO `json:"dhcpSettingsVO"`
}

// DHCPSettingsVO is the nested DHCP pool on a LAN write.
type DHCPSettingsVO struct {
	Enable      bool   `json:"enable"`
	IPAddrStart string `json:"ipaddrStart,omitempty"`
	IPAddrEnd   string `json:"ipaddrEnd,omitempty"`
	LeaseTime   int    `json:"leasetime,omitempty"`
	DHCPNS      string `json:"dhcpns,omitempty"`
}

// CreateLANNetwork POSTs a new site LAN and returns its id.
func (c *Client) CreateLANNetwork(ctx context.Context, siteID string, w LANWrite) (string, error) {
	var res struct {
		ID string `json:"id"`
	}
	if err := c.post(ctx, fmt.Sprintf("sites/%s/lan-networks", siteID), w, &res); err != nil {
		return "", fmt.Errorf("creating LAN %q: %w", w.Name, err)
	}
	if res.ID == "" {
		return "", fmt.Errorf("creating LAN %q: controller returned no network id", w.Name)
	}
	return res.ID, nil
}

// UpdateLANNetwork PUTs the full writable LAN payload.
func (c *Client) UpdateLANNetwork(ctx context.Context, siteID, networkID string, w LANWrite) error {
	if err := c.put(ctx, fmt.Sprintf("sites/%s/lan-networks/%s", siteID, networkID), w, nil); err != nil {
		return fmt.Errorf("updating LAN %q: %w", networkID, err)
	}
	return nil
}

// DeleteLANNetwork deletes a site LAN.
func (c *Client) DeleteLANNetwork(ctx context.Context, siteID, networkID string) error {
	if err := c.delete(ctx, fmt.Sprintf("sites/%s/lan-networks/%s", siteID, networkID)); err != nil {
		return fmt.Errorf("deleting LAN %q: %w", networkID, err)
	}
	return nil
}

// LANMatchesWrite reports whether an existing network already has the
// requested name, VLAN, CIDR, DHCP pool, and posture.
func LANMatchesWrite(n Network, w LANWrite) bool {
	return strings.EqualFold(n.Name, w.Name) &&
		n.VLANID == w.VLANID &&
		n.GatewaySubnet == w.GatewaySubnet &&
		n.Isolated == w.Isolation &&
		n.DHCPEnabled == w.DHCPSettings.Enable &&
		n.DHCPStart == w.DHCPSettings.IPAddrStart &&
		n.DHCPEnd == w.DHCPSettings.IPAddrEnd &&
		n.DHCPL2Relay == w.DHCPL2RelayEnable &&
		n.DHCPGuard == w.DHCPGuard &&
		n.IGMPSnoop == w.IGMPSnoopEnable &&
		n.MLDSnoop == w.MLDSnoopEnable
}

// lanPurpose is the wire value of "purpose": the 6.x Open API sends
// integer(int32) (0: VLAN, 1: interface); older fixtures send the string
// form. It decodes both and exposes the display string.
type lanPurpose string

func (p *lanPurpose) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		*p = lanPurpose(s)
		return nil
	}
	var i int
	if err := json.Unmarshal(data, &i); err != nil {
		return err
	}
	switch i {
	case 0:
		*p = lanPurpose("VLAN")
	case 1:
		*p = lanPurpose("interface")
	default:
		*p = lanPurpose(strconv.Itoa(i))
	}
	return nil
}

// rawNetwork is the wire shape of a network entry (Open API). There is no
// top-level "dhcpEnabled" field — the DHCP switch is nested under
// "dhcpSettingsVO"; deviceMac is optional.
type rawNetwork struct {
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	Purpose       lanPurpose `json:"purpose"`
	VLANID        int        `json:"vlan"`
	GatewaySubnet string     `json:"gatewaySubnet"`
	Isolated      bool       `json:"isolation"`
	DHCPSettings  struct {
		Enable      bool   `json:"enable"`
		IPAddrStart string `json:"ipaddrStart"`
		IPAddrEnd   string `json:"ipaddrEnd"`
		LeaseTime   int    `json:"leasetime"`
		DHCPNS      string `json:"dhcpns"`
	} `json:"dhcpSettingsVO"`
	DeviceMac         string `json:"deviceMac"`
	IGMPSnoopEnable   bool   `json:"igmpSnoopEnable"`
	MLDSnoopEnable    bool   `json:"mldSnoopEnable"`
	DHCPL2RelayEnable bool   `json:"dhcpL2RelayEnable"`
	DHCPGuard         bool   `json:"dhcpGuard"`
	DHCPv6Guard       bool   `json:"dhcpv6Guard"`
	Portal            bool   `json:"portal"`
	AllLan            bool   `json:"allLan"`
	Primary           bool   `json:"primary"`
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
		Purpose:       string(raw.Purpose),
		VLANID:        raw.VLANID,
		GatewaySubnet: raw.GatewaySubnet,
		Isolated:      raw.Isolated,
		DHCPEnabled:   raw.DHCPSettings.Enable,
		DeviceMac:     raw.DeviceMac,
		DHCPStart:     raw.DHCPSettings.IPAddrStart,
		DHCPEnd:       raw.DHCPSettings.IPAddrEnd,
		LeaseTime:     raw.DHCPSettings.LeaseTime,
		DHCPDNS:       raw.DHCPSettings.DHCPNS,
		IGMPSnoop:     raw.IGMPSnoopEnable,
		MLDSnoop:      raw.MLDSnoopEnable,
		DHCPL2Relay:   raw.DHCPL2RelayEnable,
		DHCPGuard:     raw.DHCPGuard,
		DHCPv6Guard:   raw.DHCPv6Guard,
		Portal:        raw.Portal,
		AllLan:        raw.AllLan,
		Primary:       raw.Primary,
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
