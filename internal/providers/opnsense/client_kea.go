package opnsense

import (
	"context"
	"encoding/json"
	"fmt"
)

// KeaSubnet is one IPv4 subnet from kea/dhcpv4/search_subnet.
type KeaSubnet struct {
	UUID        string `json:"uuid"`
	Subnet      string `json:"subnet"`
	Description string `json:"description,omitempty"`
}

// KeaReservation is one static mapping from kea/dhcpv4/search_reservation.
type KeaReservation struct {
	UUID        string `json:"uuid"`
	IP          string `json:"ip,omitempty"`
	MAC         string `json:"mac,omitempty"`
	Hostname    string `json:"hostname,omitempty"`
	Description string `json:"description,omitempty"`
}

// GetKeaSubnets lists Kea DHCPv4 subnets. A 403 is the stable
// page-privilege error; a 404 means Kea is not installed.
func (c *Client) GetKeaSubnets(ctx context.Context) ([]KeaSubnet, error) {
	var raw []json.RawMessage
	if _, err := fetchPagedList(ctx, c, "/kea/dhcpv4/search_subnet", listPageSize, &raw); err != nil {
		return nil, remapPagedDecode(err, "decoding kea subnets response")
	}
	out := make([]KeaSubnet, 0, len(raw))
	for _, row := range raw {
		var rec KeaSubnet
		if json.Unmarshal(row, &rec) != nil || rec.UUID == "" {
			continue
		}
		out = append(out, rec)
	}
	return out, nil
}

// GetKeaReservations lists Kea DHCPv4 reservations.
func (c *Client) GetKeaReservations(ctx context.Context) ([]KeaReservation, error) {
	var raw []json.RawMessage
	if _, err := fetchPagedList(ctx, c, "/kea/dhcpv4/search_reservation", listPageSize, &raw); err != nil {
		return nil, remapPagedDecode(err, "decoding kea reservations response")
	}
	out := make([]KeaReservation, 0, len(raw))
	for _, row := range raw {
		var rec struct {
			UUID        string `json:"uuid"`
			IP          string `json:"ip_address"`
			IP2         string `json:"ip"`
			MAC         string `json:"hw_address"`
			MAC2        string `json:"mac"`
			Hostname    string `json:"hostname"`
			Description string `json:"description"`
		}
		if json.Unmarshal(row, &rec) != nil || rec.UUID == "" {
			continue
		}
		out = append(out, KeaReservation{
			UUID:        rec.UUID,
			IP:          firstNonEmpty(rec.IP, rec.IP2),
			MAC:         firstNonEmpty(rec.MAC, rec.MAC2),
			Hostname:    rec.Hostname,
			Description: rec.Description,
		})
	}
	return out, nil
}

// GetKeaServiceStatus returns whether the Kea service reports as running
// (GET /kea/service/status). A 404 means the plugin is absent.
func (c *Client) GetKeaServiceStatus(ctx context.Context) (bool, error) {
	raw, err := getRaw(ctx, c, "/kea/service/status")
	if err != nil {
		return false, err
	}
	var env struct {
		Status  json.RawMessage `json:"status"`
		Running json.RawMessage `json:"running"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return false, fmt.Errorf("decoding kea service status: %w", err)
	}
	if decodeLooseBool(env.Running) || decodeLooseBool(env.Status) {
		return true, nil
	}
	// Some builds wrap {"status":{"kea":"running"}} / {"kea":{"status":"OK"}}.
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) == nil {
		for _, v := range m {
			if decodeLooseBool(v) {
				return true, nil
			}
			var s string
			if json.Unmarshal(v, &s) == nil && (s == "running" || s == "OK" || s == "ok") {
				return true, nil
			}
		}
	}
	return false, nil
}
