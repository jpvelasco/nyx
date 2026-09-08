package opnsense

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// UnboundHostOverride is one Unbound host override (A record).
type UnboundHostOverride struct {
	UUID        string `json:"uuid"`
	Hostname    string `json:"hostname"`
	Domain      string `json:"domain,omitempty"`
	IP          string `json:"ip,omitempty"`
	Description string `json:"description,omitempty"`
}

// UnboundSettings is the observe subset of Unbound DNS: enabled,
// listening interfaces, host overrides, and service status.
type UnboundSettings struct {
	Enabled    bool                  `json:"enabled"`
	Running    bool                  `json:"running"`
	Interfaces []string              `json:"interfaces,omitempty"`
	Hosts      []UnboundHostOverride `json:"hosts,omitempty"`
}

// UnboundHostWrite is the create/update payload for a host override.
type UnboundHostWrite struct {
	Hostname    string
	Domain      string
	IP          string
	Description string
}

const (
	unboundSettingsPath    = "/unbound/settings/get"
	unboundSearchCamelPath = "/unbound/settings/searchHostOverride"
	unboundSearchSnakePath = "/unbound/settings/search_host_override"
	unboundAddCamelPath    = "/unbound/settings/addHostOverride"
	unboundAddSnakePath    = "/unbound/settings/add_host_override"
	unboundSetCamelPath    = "/unbound/settings/setHostOverride/%s"
	unboundSetSnakePath    = "/unbound/settings/set_host_override/%s"
	unboundDelCamelPath    = "/unbound/settings/delHostOverride/%s"
	unboundDelSnakePath    = "/unbound/settings/del_host_override/%s"
	unboundStatusPath      = "/unbound/service/status"
	unboundReconfigurePath = "/unbound/service/reconfigure"
)

// GetUnboundSettings returns Unbound enable/interfaces/hosts
// (GET /unbound/settings/get). A 403 is the stable page-privilege error.
func (c *Client) GetUnboundSettings(ctx context.Context) (*UnboundSettings, error) {
	raw, err := getRaw(ctx, c, unboundSettingsPath)
	if err != nil {
		return nil, err
	}
	settings, err := parseUnboundSettings(raw)
	if err != nil {
		return nil, fmt.Errorf("decoding unbound settings response: %w", err)
	}
	return settings, nil
}

// GetUnboundHostOverrides lists host overrides. Tries the camelCase MVC
// command first, then snake_case; a 404 on the first path falls through.
func (c *Client) GetUnboundHostOverrides(ctx context.Context) ([]UnboundHostOverride, error) {
	rows, err := searchUnboundOverrides(ctx, c, unboundSearchCamelPath)
	if isNotFound(err) {
		rows, err = searchUnboundOverrides(ctx, c, unboundSearchSnakePath)
	}
	if err != nil {
		return nil, err
	}
	return rows, nil
}

func searchUnboundOverrides(ctx context.Context, c *Client, path string) ([]UnboundHostOverride, error) {
	var raw []json.RawMessage
	if _, err := fetchPagedList(ctx, c, path, listPageSize, &raw); err != nil {
		return nil, remapPagedDecode(err, "decoding unbound host overrides response")
	}
	return decodeUnboundOverrideRows(raw), nil
}

func decodeUnboundOverrideRows(raw []json.RawMessage) []UnboundHostOverride {
	out := make([]UnboundHostOverride, 0, len(raw))
	for _, row := range raw {
		if rec, ok := decodeUnboundOverride("", row); ok {
			out = append(out, rec)
		}
	}
	return out
}

func decodeUnboundOverride(uuid string, row json.RawMessage) (UnboundHostOverride, bool) {
	var rec struct {
		UUID        string `json:"uuid"`
		Hostname    string `json:"hostname"`
		Host        string `json:"host"`
		Domain      string `json:"domain"`
		Server      string `json:"server"`
		IP          string `json:"ip"`
		Address     string `json:"address"`
		Description string `json:"description"`
		Descr       string `json:"descr"`
	}
	if json.Unmarshal(row, &rec) != nil {
		return UnboundHostOverride{}, false
	}
	id := firstNonEmpty(rec.UUID, uuid)
	host := firstNonEmpty(rec.Hostname, rec.Host)
	ip := firstNonEmpty(rec.Server, rec.IP, rec.Address)
	if id == "" && host == "" && ip == "" {
		return UnboundHostOverride{}, false
	}
	if id == "" {
		return UnboundHostOverride{}, false
	}
	return UnboundHostOverride{
		UUID:        id,
		Hostname:    host,
		Domain:      rec.Domain,
		IP:          ip,
		Description: firstNonEmpty(rec.Description, rec.Descr),
	}, true
}

// GetUnboundServiceStatus returns whether Unbound reports as running
// (GET /unbound/service/status).
func (c *Client) GetUnboundServiceStatus(ctx context.Context) (bool, error) {
	raw, err := getRaw(ctx, c, unboundStatusPath)
	if err != nil {
		return false, err
	}
	ok, err := parseUnboundServiceStatus(raw)
	if err != nil {
		return false, fmt.Errorf("decoding unbound service status: %w", err)
	}
	return ok, nil
}

func parseUnboundServiceStatus(raw []byte) (bool, error) {
	var env struct {
		Status  json.RawMessage `json:"status"`
		Running json.RawMessage `json:"running"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return false, err
	}
	if decodeLooseBool(env.Running) || decodeLooseBool(env.Status) {
		return true, nil
	}
	if statusRunning(env.Status) || statusRunning(env.Running) {
		return true, nil
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) == nil {
		for _, v := range m {
			if decodeLooseBool(v) || statusRunning(v) {
				return true, nil
			}
		}
	}
	return false, nil
}

func statusRunning(raw json.RawMessage) bool {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return false
	}
	return s == "running" || s == "OK" || s == "ok"
}

// GetUnboundObserve loads settings, host overrides, and service status
// for inventory. Search 404 (older/newer command name miss) falls back to
// hosts embedded in settings/get; any other fetch error is returned.
func (c *Client) GetUnboundObserve(ctx context.Context) (*UnboundSettings, error) {
	settings, err := c.GetUnboundSettings(ctx)
	if err != nil {
		return nil, err
	}
	hosts, err := c.GetUnboundHostOverrides(ctx)
	if err != nil && !isNotFound(err) {
		return nil, err
	}
	if len(hosts) > 0 {
		settings.Hosts = hosts
	}
	running, err := c.GetUnboundServiceStatus(ctx)
	if err != nil {
		return nil, err
	}
	settings.Running = running
	return settings, nil
}

func parseUnboundSettings(raw []byte) (*UnboundSettings, error) {
	var env struct {
		Unbound json.RawMessage `json:"unbound"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, err
	}
	src := env.Unbound
	if len(src) == 0 {
		src = raw
	}
	var rec struct {
		Enable          json.RawMessage `json:"enable"`
		Enabled         json.RawMessage `json:"enabled"`
		Interface       json.RawMessage `json:"interface"`
		ActiveInterface json.RawMessage `json:"active_interface"`
		General         json.RawMessage `json:"general"`
		Hosts           json.RawMessage `json:"hosts"`
		Dots            json.RawMessage `json:"dots"`
	}
	if err := json.Unmarshal(src, &rec); err != nil {
		return nil, err
	}
	out := &UnboundSettings{
		Enabled:    decodeLooseBool(rec.Enabled) || decodeLooseBool(rec.Enable),
		Interfaces: selectedKeys(firstNonEmptyRaw(rec.ActiveInterface, rec.Interface)),
	}
	if gen := parseUnboundGeneral(rec.General); gen != nil {
		if !out.Enabled {
			out.Enabled = gen.Enabled
		}
		if len(out.Interfaces) == 0 {
			out.Interfaces = gen.Interfaces
		}
	}
	hostBlob := rec.Hosts
	if len(hostBlob) == 0 {
		hostBlob = firstField(rec.Dots, "hosts")
	}
	for uuid, row := range uuidKeyed(hostBlob) {
		if h, ok := decodeUnboundOverride(uuid, row); ok {
			out.Hosts = append(out.Hosts, h)
		}
	}
	return out, nil
}

func parseUnboundGeneral(raw json.RawMessage) *UnboundSettings {
	if len(raw) == 0 {
		return nil
	}
	var rec struct {
		Enable          json.RawMessage `json:"enable"`
		Enabled         json.RawMessage `json:"enabled"`
		Interface       json.RawMessage `json:"interface"`
		ActiveInterface json.RawMessage `json:"active_interface"`
	}
	if json.Unmarshal(raw, &rec) != nil {
		return nil
	}
	return &UnboundSettings{
		Enabled:    decodeLooseBool(rec.Enabled) || decodeLooseBool(rec.Enable),
		Interfaces: selectedKeys(firstNonEmptyRaw(rec.ActiveInterface, rec.Interface)),
	}
}

func firstNonEmptyRaw(vals ...json.RawMessage) json.RawMessage {
	for _, v := range vals {
		if len(v) > 0 {
			return v
		}
	}
	return nil
}

func hostOverrideWire(w UnboundHostWrite) ([]byte, error) {
	item := map[string]interface{}{
		"enabled":  "1",
		"hostname": w.Hostname,
		"domain":   w.Domain,
		"rr":       "A",
		"server":   w.IP,
	}
	if w.Description != "" {
		item["description"] = w.Description
	}
	return json.Marshal(map[string]interface{}{"host": item})
}

// CreateUnboundOverride POSTs addHostOverride (snake_case fallback) and
// returns the new uuid.
func (c *Client) CreateUnboundOverride(ctx context.Context, w UnboundHostWrite) (string, error) {
	body, err := hostOverrideWire(w)
	if err != nil {
		return "", err
	}
	id, err := c.natAdd(ctx, unboundAddCamelPath, body)
	if isNotFound(err) {
		return c.natAdd(ctx, unboundAddSnakePath, body)
	}
	return id, err
}

// SetUnboundOverride POSTs setHostOverride/<uuid> (snake_case fallback).
func (c *Client) SetUnboundOverride(ctx context.Context, uuid string, w UnboundHostWrite) error {
	body, err := hostOverrideWire(w)
	if err != nil {
		return err
	}
	err = c.natSet(ctx, fmt.Sprintf(unboundSetCamelPath, uuid), body)
	if isNotFound(err) {
		return c.natSet(ctx, fmt.Sprintf(unboundSetSnakePath, uuid), body)
	}
	return err
}

// DeleteUnboundOverride POSTs delHostOverride/<uuid> (snake_case fallback).
func (c *Client) DeleteUnboundOverride(ctx context.Context, uuid string) error {
	err := c.natSet(ctx, fmt.Sprintf(unboundDelCamelPath, uuid), []byte(`{}`))
	if isNotFound(err) {
		return c.natSet(ctx, fmt.Sprintf(unboundDelSnakePath, uuid), []byte(`{}`))
	}
	return err
}

// ReconfigureUnbound activates staged Unbound changes.
func (c *Client) ReconfigureUnbound(ctx context.Context) error {
	return c.postOK(ctx, unboundReconfigurePath)
}

// FindUnboundOverride matches by uuid or hostname+domain (case-insensitive).
func FindUnboundOverride(rows []UnboundHostOverride, uuid, hostname, domain string) (UnboundHostOverride, bool) {
	for _, h := range rows {
		if uuid != "" && strings.EqualFold(h.UUID, uuid) {
			return h, true
		}
	}
	if hostname == "" {
		return UnboundHostOverride{}, false
	}
	for _, h := range rows {
		if unboundHostKeyMatch(h, hostname, domain) {
			return h, true
		}
	}
	return UnboundHostOverride{}, false
}

// UnboundOverrideMatches reports whether an existing override already has
// the requested hostname, domain, and IP.
func UnboundOverrideMatches(h UnboundHostOverride, hostname, domain, ip string) bool {
	if !unboundHostKeyMatch(h, hostname, domain) {
		return false
	}
	if ip != "" && !strings.EqualFold(h.IP, ip) {
		return false
	}
	return true
}

func unboundHostKeyMatch(h UnboundHostOverride, hostname, domain string) bool {
	if !strings.EqualFold(h.Hostname, hostname) {
		return false
	}
	return strings.EqualFold(h.Domain, domain)
}
