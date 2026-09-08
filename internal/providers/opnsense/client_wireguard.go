package opnsense

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// WireGuardServer is one instance from wireguard/server/search_server.
type WireGuardServer struct {
	UUID          string   `json:"uuid"`
	Name          string   `json:"name,omitempty"`
	Enabled       bool     `json:"enabled"`
	TunnelAddress string   `json:"tunnel_address,omitempty"`
	ListenPort    int      `json:"listen_port,omitempty"`
	Peers         []string `json:"peers,omitempty"`
}

// WireGuardClient is one peer from wireguard/client/search_client.
// Private keys from the controller payload are ignored on purpose.
type WireGuardClient struct {
	UUID          string `json:"uuid"`
	Name          string `json:"name,omitempty"`
	Enabled       bool   `json:"enabled"`
	Pubkey        string `json:"pubkey,omitempty"`
	TunnelAddress string `json:"tunnel_address,omitempty"`
	Server        string `json:"server,omitempty"`
	AllowedIPs    string `json:"allowed_ips,omitempty"`
}

// WireGuardStatus is the observe subset of wireguard/service/status.
type WireGuardStatus struct {
	Running bool `json:"running"`
}

const (
	wgServerSearchPath = "/wireguard/server/search_server"
	wgClientSearchPath = "/wireguard/client/search_client"
	wgStatusPath       = "/wireguard/service/status"
)

// GetWireGuardServers lists configured WireGuard server instances.
// A 403 is the stable page-privilege error; a 404 means the plugin is absent.
func (c *Client) GetWireGuardServers(ctx context.Context) ([]WireGuardServer, error) {
	var raw []json.RawMessage
	if _, err := fetchPagedList(ctx, c, wgServerSearchPath, listPageSize, &raw); err != nil {
		return nil, remapPagedDecode(err, "decoding wireguard servers response")
	}
	out := make([]WireGuardServer, 0, len(raw))
	for _, row := range raw {
		var rec struct {
			UUID          string          `json:"uuid"`
			Name          string          `json:"name"`
			Descr         string          `json:"descr"`
			Enabled       json.RawMessage `json:"enabled"`
			TunnelAddress string          `json:"tunneladdress"`
			TunnelAddr2   string          `json:"tunnel_address"`
			ListenPort    json.RawMessage `json:"listenport"`
			ListenPort2   json.RawMessage `json:"listen_port"`
			Peers         json.RawMessage `json:"peers"`
		}
		if json.Unmarshal(row, &rec) != nil || rec.UUID == "" {
			continue
		}
		out = append(out, WireGuardServer{
			UUID:          rec.UUID,
			Name:          firstNonEmpty(rec.Name, rec.Descr),
			Enabled:       decodeLooseBool(rec.Enabled),
			TunnelAddress: firstNonEmpty(rec.TunnelAddress, rec.TunnelAddr2),
			ListenPort:    decodeLooseInt(rec.ListenPort, rec.ListenPort2),
			Peers:         decodeStringList(rec.Peers),
		})
	}
	return out, nil
}

// GetWireGuardClients lists configured WireGuard peers.
func (c *Client) GetWireGuardClients(ctx context.Context) ([]WireGuardClient, error) {
	var raw []json.RawMessage
	if _, err := fetchPagedList(ctx, c, wgClientSearchPath, listPageSize, &raw); err != nil {
		return nil, remapPagedDecode(err, "decoding wireguard clients response")
	}
	out := make([]WireGuardClient, 0, len(raw))
	for _, row := range raw {
		var rec struct {
			UUID          string          `json:"uuid"`
			Name          string          `json:"name"`
			Descr         string          `json:"descr"`
			Enabled       json.RawMessage `json:"enabled"`
			Pubkey        string          `json:"pubkey"`
			Pubkey2       string          `json:"publickey"`
			TunnelAddress string          `json:"tunneladdress"`
			TunnelAddr2   string          `json:"tunnel_address"`
			Server        string          `json:"server"`
			AllowedIPs    string          `json:"allowedips"`
			AllowedIPs2   string          `json:"allowed_ips"`
		}
		if json.Unmarshal(row, &rec) != nil || rec.UUID == "" {
			continue
		}
		out = append(out, WireGuardClient{
			UUID:          rec.UUID,
			Name:          firstNonEmpty(rec.Name, rec.Descr),
			Enabled:       decodeLooseBool(rec.Enabled),
			Pubkey:        firstNonEmpty(rec.Pubkey, rec.Pubkey2),
			TunnelAddress: firstNonEmpty(rec.TunnelAddress, rec.TunnelAddr2),
			Server:        rec.Server,
			AllowedIPs:    firstNonEmpty(rec.AllowedIPs, rec.AllowedIPs2),
		})
	}
	return out, nil
}

// GetWireGuardStatus returns whether the WireGuard service reports as running.
func (c *Client) GetWireGuardStatus(ctx context.Context) (*WireGuardStatus, error) {
	raw, err := getRaw(ctx, c, wgStatusPath)
	if err != nil {
		return nil, err
	}
	var env struct {
		Status  json.RawMessage `json:"status"`
		Running json.RawMessage `json:"running"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("decoding wireguard service status: %w", err)
	}
	if decodeLooseBool(env.Running) || decodeLooseBool(env.Status) {
		return &WireGuardStatus{Running: true}, nil
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) == nil {
		for _, v := range m {
			if decodeLooseBool(v) {
				return &WireGuardStatus{Running: true}, nil
			}
			var s string
			if json.Unmarshal(v, &s) == nil && (s == "running" || s == "OK" || s == "ok") {
				return &WireGuardStatus{Running: true}, nil
			}
		}
	}
	return &WireGuardStatus{Running: false}, nil
}

func decodeLooseInt(vals ...json.RawMessage) int {
	for _, raw := range vals {
		if len(raw) == 0 {
			continue
		}
		var n int
		if json.Unmarshal(raw, &n) == nil {
			return n
		}
		var s string
		if json.Unmarshal(raw, &s) == nil {
			n, err := strconv.Atoi(strings.TrimSpace(s))
			if err == nil {
				return n
			}
		}
	}
	return 0
}

func decodeStringList(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var list []string
	if json.Unmarshal(raw, &list) == nil {
		return list
	}
	var s string
	if json.Unmarshal(raw, &s) == nil && s != "" {
		return splitCSV(s)
	}
	var byName map[string]json.RawMessage
	if json.Unmarshal(raw, &byName) != nil {
		return nil
	}
	var out []string
	for name, row := range byName {
		var rec struct {
			Selected json.RawMessage `json:"selected"`
		}
		if json.Unmarshal(row, &rec) != nil {
			continue
		}
		if decodeLooseBool(rec.Selected) {
			out = append(out, name)
		}
	}
	return out
}
