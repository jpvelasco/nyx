package opnsense

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// DnsmasqRangeWrite is the create/update payload for a Dnsmasq DHCP range.
type DnsmasqRangeWrite struct {
	Interface string
	Start     string
	End       string
}

// DnsmasqHostWrite is the create/update payload for a Dnsmasq static host.
type DnsmasqHostWrite struct {
	Host   string
	Domain string
	IP     string
	MAC    string
}

// KeaSubnetWrite is the create/update payload for a Kea DHCPv4 subnet.
type KeaSubnetWrite struct {
	Subnet      string
	Description string
}

// KeaReservationWrite is the create/update payload for a Kea reservation.
type KeaReservationWrite struct {
	IP       string
	MAC      string
	Hostname string
}

const (
	dnsmasqAddRangePath    = "/dnsmasq/settings/add_range"
	dnsmasqSetRangePath    = "/dnsmasq/settings/set_range/%s"
	dnsmasqDelRangePath    = "/dnsmasq/settings/del_range/%s"
	dnsmasqAddHostPath     = "/dnsmasq/settings/add_host"
	dnsmasqSetHostPath     = "/dnsmasq/settings/set_host/%s"
	dnsmasqDelHostPath     = "/dnsmasq/settings/del_host/%s"
	dnsmasqReconfigurePath = "/dnsmasq/service/reconfigure"
	keaAddSubnetPath       = "/kea/dhcpv4/add_subnet"
	keaSetSubnetPath       = "/kea/dhcpv4/set_subnet/%s"
	keaDelSubnetPath       = "/kea/dhcpv4/del_subnet/%s"
	keaAddReservationPath  = "/kea/dhcpv4/add_reservation"
	keaSetReservationPath  = "/kea/dhcpv4/set_reservation/%s"
	keaDelReservationPath  = "/kea/dhcpv4/del_reservation/%s"
	keaReconfigurePath     = "/kea/service/reconfigure"
)

func dnsmasqRangeWire(w DnsmasqRangeWrite) ([]byte, error) {
	item := map[string]interface{}{
		"interface": w.Interface,
		"start":     w.Start,
		"end":       w.End,
	}
	return json.Marshal(map[string]interface{}{"range": item})
}

func dnsmasqHostWire(w DnsmasqHostWrite) ([]byte, error) {
	item := map[string]interface{}{
		"host": w.Host,
		"ip":   w.IP,
	}
	if w.Domain != "" {
		item["domain"] = w.Domain
	}
	if w.MAC != "" {
		item["hwaddr"] = w.MAC
	}
	return json.Marshal(map[string]interface{}{"host": item})
}

func keaSubnetWire(w KeaSubnetWrite) ([]byte, error) {
	item := map[string]interface{}{"subnet": w.Subnet}
	if w.Description != "" {
		item["description"] = w.Description
	}
	return json.Marshal(map[string]interface{}{"subnet": item})
}

func keaReservationWire(w KeaReservationWrite) ([]byte, error) {
	item := map[string]interface{}{
		"ip_address": w.IP,
		"hw_address": w.MAC,
	}
	if w.Hostname != "" {
		item["hostname"] = w.Hostname
	}
	return json.Marshal(map[string]interface{}{"reservation": item})
}

func (c *Client) CreateDnsmasqRange(ctx context.Context, w DnsmasqRangeWrite) (string, error) {
	body, err := dnsmasqRangeWire(w)
	if err != nil {
		return "", err
	}
	return c.natAdd(ctx, dnsmasqAddRangePath, body)
}

func (c *Client) SetDnsmasqRange(ctx context.Context, uuid string, w DnsmasqRangeWrite) error {
	body, err := dnsmasqRangeWire(w)
	if err != nil {
		return err
	}
	return c.natSet(ctx, fmt.Sprintf(dnsmasqSetRangePath, uuid), body)
}

func (c *Client) DeleteDnsmasqRange(ctx context.Context, uuid string) error {
	return c.natSet(ctx, fmt.Sprintf(dnsmasqDelRangePath, uuid), []byte(`{}`))
}

func (c *Client) CreateDnsmasqHost(ctx context.Context, w DnsmasqHostWrite) (string, error) {
	body, err := dnsmasqHostWire(w)
	if err != nil {
		return "", err
	}
	return c.natAdd(ctx, dnsmasqAddHostPath, body)
}

func (c *Client) SetDnsmasqHost(ctx context.Context, uuid string, w DnsmasqHostWrite) error {
	body, err := dnsmasqHostWire(w)
	if err != nil {
		return err
	}
	return c.natSet(ctx, fmt.Sprintf(dnsmasqSetHostPath, uuid), body)
}

func (c *Client) DeleteDnsmasqHost(ctx context.Context, uuid string) error {
	return c.natSet(ctx, fmt.Sprintf(dnsmasqDelHostPath, uuid), []byte(`{}`))
}

func (c *Client) ReconfigureDnsmasq(ctx context.Context) error {
	return c.postOK(ctx, dnsmasqReconfigurePath)
}

func (c *Client) CreateKeaSubnet(ctx context.Context, w KeaSubnetWrite) (string, error) {
	body, err := keaSubnetWire(w)
	if err != nil {
		return "", err
	}
	return c.natAdd(ctx, keaAddSubnetPath, body)
}

func (c *Client) SetKeaSubnet(ctx context.Context, uuid string, w KeaSubnetWrite) error {
	body, err := keaSubnetWire(w)
	if err != nil {
		return err
	}
	return c.natSet(ctx, fmt.Sprintf(keaSetSubnetPath, uuid), body)
}

func (c *Client) DeleteKeaSubnet(ctx context.Context, uuid string) error {
	return c.natSet(ctx, fmt.Sprintf(keaDelSubnetPath, uuid), []byte(`{}`))
}

func (c *Client) CreateKeaReservation(ctx context.Context, w KeaReservationWrite) (string, error) {
	body, err := keaReservationWire(w)
	if err != nil {
		return "", err
	}
	return c.natAdd(ctx, keaAddReservationPath, body)
}

func (c *Client) SetKeaReservation(ctx context.Context, uuid string, w KeaReservationWrite) error {
	body, err := keaReservationWire(w)
	if err != nil {
		return err
	}
	return c.natSet(ctx, fmt.Sprintf(keaSetReservationPath, uuid), body)
}

func (c *Client) DeleteKeaReservation(ctx context.Context, uuid string) error {
	return c.natSet(ctx, fmt.Sprintf(keaDelReservationPath, uuid), []byte(`{}`))
}

func (c *Client) ReconfigureKea(ctx context.Context) error {
	return c.postOK(ctx, keaReconfigurePath)
}

// FindDnsmasqRange matches by uuid or interface+start+end.
func FindDnsmasqRange(rows []DnsmasqRange, uuid, iface, start, end string) (DnsmasqRange, bool) {
	for _, r := range rows {
		if uuid != "" && strings.EqualFold(r.UUID, uuid) {
			return r, true
		}
		if iface != "" && start != "" && strings.EqualFold(r.Interface, iface) && r.Start == start && r.End == end {
			return r, true
		}
	}
	return DnsmasqRange{}, false
}

// FindDnsmasqHost matches by uuid or host+ip.
func FindDnsmasqHost(rows []DnsmasqHost, uuid, host, ip string) (DnsmasqHost, bool) {
	for _, h := range rows {
		if uuid != "" && strings.EqualFold(h.UUID, uuid) {
			return h, true
		}
		if host != "" && ip != "" && strings.EqualFold(h.Host, host) && h.IP == ip {
			return h, true
		}
	}
	return DnsmasqHost{}, false
}

// FindKeaSubnet matches by uuid or subnet CIDR.
func FindKeaSubnet(rows []KeaSubnet, uuid, subnet string) (KeaSubnet, bool) {
	for _, s := range rows {
		if uuid != "" && strings.EqualFold(s.UUID, uuid) {
			return s, true
		}
		if subnet != "" && s.Subnet == subnet {
			return s, true
		}
	}
	return KeaSubnet{}, false
}

// FindKeaReservation matches by uuid or ip+mac.
func FindKeaReservation(rows []KeaReservation, uuid, ip, mac string) (KeaReservation, bool) {
	for _, r := range rows {
		if uuid != "" && strings.EqualFold(r.UUID, uuid) {
			return r, true
		}
		if ip != "" && mac != "" && r.IP == ip && strings.EqualFold(r.MAC, mac) {
			return r, true
		}
	}
	return KeaReservation{}, false
}

// DetectDHCPBackend reports which DHCP writer is live. Dnsmasq wins when
// both are running (26.x default). Neither running is an error so a write
// cannot target a ghost pool.
func (c *Client) DetectDHCPBackend(ctx context.Context) (string, error) {
	dns, dnsErr := c.GetDnsmasqSettings(ctx)
	keaOn, keaErr := c.GetKeaServiceStatus(ctx)
	dnsOn := dnsErr == nil && dns != nil && dns.Enabled
	if keaErr != nil && !isNotFound(keaErr) && !isPermissionDenied(keaErr) {
		// Keep a transport/auth failure fatal.
		if !dnsOn {
			return "", keaErr
		}
	}
	if dnsOn {
		return "dnsmasq", nil
	}
	if keaErr == nil && keaOn {
		return "kea", nil
	}
	return "", fmt.Errorf("no running DHCP backend: start Dnsmasq or Kea before writing a pool or reservation")
}
