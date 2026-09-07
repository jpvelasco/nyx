package opnsense

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Bridge is one row from GET /api/interfaces/bridge_settings/search_item.
type Bridge struct {
	UUID        string   `json:"uuid"`
	Description string   `json:"description,omitempty"`
	Members     []string `json:"members,omitempty"`
	STP         bool     `json:"stp,omitempty"`
}

// InterfaceSetting is one configured interface from
// GET /api/interfaces/settings/get (enable, device, address).
type InterfaceSetting struct {
	Name        string `json:"name"`
	Device      string `json:"device,omitempty"`
	Description string `json:"description,omitempty"`
	Enabled     bool   `json:"enabled"`
	IPv4        string `json:"ipv4,omitempty"`
	Subnet      string `json:"subnet,omitempty"`
}

// DnsmasqRange is one DHCP range from GET /api/dnsmasq/settings/get.
type DnsmasqRange struct {
	UUID      string `json:"uuid,omitempty"`
	Interface string `json:"interface,omitempty"`
	Start     string `json:"start,omitempty"`
	End       string `json:"end,omitempty"`
}

// DnsmasqHost is one static host mapping from GET /api/dnsmasq/settings/get.
type DnsmasqHost struct {
	UUID   string `json:"uuid,omitempty"`
	Host   string `json:"host,omitempty"`
	Domain string `json:"domain,omitempty"`
	IP     string `json:"ip,omitempty"`
}

// DnsmasqSettings is the observe subset of GET /api/dnsmasq/settings/get:
// enabled, listening interfaces, DHCP ranges, and static hosts.
type DnsmasqSettings struct {
	Enabled    bool           `json:"enabled"`
	Interfaces []string       `json:"interfaces,omitempty"`
	Ranges     []DnsmasqRange `json:"ranges,omitempty"`
	Hosts      []DnsmasqHost  `json:"hosts,omitempty"`
}

// PfStatistics is the observe subset of GET /api/diagnostics/firewall/pf_statistics.
type PfStatistics struct {
	StateCount  int `json:"state_count"`
	SourceCount int `json:"source_count,omitempty"`
	Limit       int `json:"limit,omitempty"`
}

// KernelRoute is one row from GET /api/diagnostics/interface/get_routes.
type KernelRoute struct {
	Destination string `json:"destination"`
	Gateway     string `json:"gateway,omitempty"`
	Netif       string `json:"netif,omitempty"`
	Flags       string `json:"flags,omitempty"`
}

// GetBridgeSettings returns configured bridges (GET search_item). A 403 is
// the stable page-privilege error and is returned as-is so inventory can
// degrade it.
func (c *Client) GetBridgeSettings(ctx context.Context) ([]Bridge, error) {
	var raw []json.RawMessage
	if _, err := fetchPagedList(ctx, c, "/interfaces/bridge_settings/search_item", listPageSize, &raw); err != nil {
		return nil, remapPagedDecode(err, "decoding bridge settings response")
	}
	out := make([]Bridge, 0, len(raw))
	for _, row := range raw {
		var rec struct {
			UUID        string          `json:"uuid"`
			Descr       string          `json:"descr"`
			Description string          `json:"description"`
			Members     string          `json:"members"`
			STP         json.RawMessage `json:"stp"`
		}
		if err := json.Unmarshal(row, &rec); err != nil || rec.UUID == "" {
			continue
		}
		out = append(out, Bridge{
			UUID:        rec.UUID,
			Description: firstNonEmpty(rec.Description, rec.Descr),
			Members:     splitCSV(rec.Members),
			STP:         decodeLooseBool(rec.STP),
		})
	}
	return out, nil
}

// GetInterfaceSettings returns the per-interface config map
// (GET /interfaces/settings/get). A 403 is the stable page-privilege error.
func (c *Client) GetInterfaceSettings(ctx context.Context) ([]InterfaceSetting, error) {
	raw, err := getRaw(ctx, c, "/interfaces/settings/get")
	if err != nil {
		return nil, err
	}
	settings, err := parseInterfaceSettings(raw)
	if err != nil {
		return nil, fmt.Errorf("decoding interface settings response: %w", err)
	}
	return settings, nil
}

// GetDnsmasqSettings returns Dnsmasq enable/interfaces/ranges/hosts
// (GET /dnsmasq/settings/get). A 403 is the stable page-privilege error.
func (c *Client) GetDnsmasqSettings(ctx context.Context) (*DnsmasqSettings, error) {
	raw, err := getRaw(ctx, c, "/dnsmasq/settings/get")
	if err != nil {
		return nil, err
	}
	settings, err := parseDnsmasqSettings(raw)
	if err != nil {
		return nil, fmt.Errorf("decoding dnsmasq settings response: %w", err)
	}
	return settings, nil
}

// GetPfStatistics returns the pf state-table summary
// (GET /diagnostics/firewall/pf_statistics). A 403 is the stable
// page-privilege error.
func (c *Client) GetPfStatistics(ctx context.Context) (*PfStatistics, error) {
	raw, err := getRaw(ctx, c, "/diagnostics/firewall/pf_statistics")
	if err != nil {
		return nil, err
	}
	stats, err := parsePfStatistics(raw)
	if err != nil {
		return nil, fmt.Errorf("decoding pf statistics response: %w", err)
	}
	return stats, nil
}

// GetKernelRoutes returns the kernel routing table
// (GET /diagnostics/interface/get_routes). A 403 is the stable
// page-privilege error.
func (c *Client) GetKernelRoutes(ctx context.Context) ([]KernelRoute, error) {
	raw, err := getRaw(ctx, c, "/diagnostics/interface/get_routes")
	if err != nil {
		return nil, err
	}
	routes, err := parseKernelRoutes(raw)
	if err != nil {
		return nil, fmt.Errorf("decoding kernel routes response: %w", err)
	}
	return routes, nil
}

func getRaw(ctx context.Context, c *Client, path string) ([]byte, error) {
	resp, err := c.doRequest(ctx, path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading %s response: %w", path, err)
	}
	return raw, nil
}

func parseInterfaceSettings(raw []byte) ([]InterfaceSetting, error) {
	var env map[string]json.RawMessage
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, err
	}
	// 26.x uses "interface"; some builds wrap as "interfaces".
	blob := env["interface"]
	if len(blob) == 0 {
		blob = env["interfaces"]
	}
	if len(blob) == 0 {
		return []InterfaceSetting{}, nil
	}
	var byName map[string]json.RawMessage
	if err := json.Unmarshal(blob, &byName); err != nil {
		return nil, err
	}
	out := make([]InterfaceSetting, 0, len(byName))
	for name, row := range byName {
		if name == "" {
			continue
		}
		var rec struct {
			Enable string `json:"enable"`
			If     string `json:"if"`
			Descr  string `json:"descr"`
			IPAddr string `json:"ipaddr"`
			Subnet string `json:"subnet"`
		}
		if json.Unmarshal(row, &rec) != nil {
			continue
		}
		out = append(out, InterfaceSetting{
			Name:        name,
			Device:      rec.If,
			Description: rec.Descr,
			Enabled:     rec.Enable == "1" || strings.EqualFold(rec.Enable, "true"),
			IPv4:        rec.IPAddr,
			Subnet:      rec.Subnet,
		})
	}
	return out, nil
}

func parseDnsmasqSettings(raw []byte) (*DnsmasqSettings, error) {
	var env struct {
		Dnsmasq json.RawMessage `json:"dnsmasq"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, err
	}
	src := env.Dnsmasq
	if len(src) == 0 {
		src = raw
	}
	var rec struct {
		Enable    json.RawMessage `json:"enable"`
		Interface json.RawMessage `json:"interface"`
		DHCP      json.RawMessage `json:"dhcp"`
		Hosts     json.RawMessage `json:"hosts"`
	}
	if err := json.Unmarshal(src, &rec); err != nil {
		return nil, err
	}
	out := &DnsmasqSettings{
		Enabled:    decodeLooseBool(rec.Enable),
		Interfaces: selectedKeys(rec.Interface),
	}
	if ranges := uuidKeyed(firstField(rec.DHCP, "range")); len(ranges) > 0 {
		for uuid, row := range ranges {
			var r struct {
				Interface string `json:"interface"`
				Start     string `json:"start"`
				End       string `json:"end"`
			}
			if json.Unmarshal(row, &r) != nil || r.Start == "" {
				continue
			}
			out.Ranges = append(out.Ranges, DnsmasqRange{UUID: uuid, Interface: r.Interface, Start: r.Start, End: r.End})
		}
	}
	hostBlob := rec.Hosts
	if len(hostBlob) == 0 {
		hostBlob = firstField(rec.DHCP, "host")
	}
	for uuid, row := range uuidKeyed(hostBlob) {
		var h struct {
			Host   string `json:"host"`
			Domain string `json:"domain"`
			IP     string `json:"ip"`
		}
		if json.Unmarshal(row, &h) != nil || (h.Host == "" && h.IP == "") {
			continue
		}
		out.Hosts = append(out.Hosts, DnsmasqHost{UUID: uuid, Host: h.Host, Domain: h.Domain, IP: h.IP})
	}
	return out, nil
}

func parsePfStatistics(raw []byte) (*PfStatistics, error) {
	var flat struct {
		Current     int `json:"current"`
		StateCount  int `json:"state_count"`
		SourceCount int `json:"source_count"`
		Limit       int `json:"limit"`
		Info        struct {
			Current     int `json:"current"`
			StateCount  int `json:"state_count"`
			SourceCount int `json:"source_count"`
			Limit       int `json:"limit"`
		} `json:"info"`
		States struct {
			Current int `json:"current"`
			Limit   int `json:"limit"`
		} `json:"states"`
	}
	if err := json.Unmarshal(raw, &flat); err != nil {
		return nil, err
	}
	stats := &PfStatistics{
		StateCount:  firstNonZero(flat.StateCount, flat.Current, flat.Info.StateCount, flat.Info.Current, flat.States.Current),
		SourceCount: firstNonZero(flat.SourceCount, flat.Info.SourceCount),
		Limit:       firstNonZero(flat.Limit, flat.Info.Limit, flat.States.Limit),
	}
	return stats, nil
}

func parseKernelRoutes(raw []byte) ([]KernelRoute, error) {
	var env struct {
		Rows   []KernelRoute `json:"rows"`
		Routes []KernelRoute `json:"routes"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, err
	}
	if len(env.Rows) > 0 {
		return env.Rows, nil
	}
	return env.Routes, nil
}

func selectedKeys(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	// A CSV / space-separated string of interface names.
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

func uuidKeyed(raw json.RawMessage) map[string]json.RawMessage {
	if len(raw) == 0 {
		return nil
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	return m
}

func firstField(raw json.RawMessage, key string) json.RawMessage {
	if len(raw) == 0 {
		return nil
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	return m[key]
}

func firstNonZero(vals ...int) int {
	for _, v := range vals {
		if v != 0 {
			return v
		}
	}
	return 0
}
