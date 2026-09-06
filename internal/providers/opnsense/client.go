package opnsense

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SystemInformation is the response of GET /diagnostics/system/system_information.
// Versions is a flat list of version strings, in order: OPNsense, FreeBSD,
// OpenSSL. The endpoint is covered by the Dashboard page privilege;
// /core/firmware/* requires the separate System: Firmware privilege, so
// version reads must not go there (a Dashboard-only API user would get a
// 403 on the firmware endpoints).
type SystemInformation struct {
	Name     string   `json:"name"`
	Versions []string `json:"versions"`
	Updates  string   `json:"updates"`
}

// productVersionAndArch parses the OPNsense version entry. The entry has
// the form "OPNsense <version>-<arch>"; the trailing architecture is split
// off only when it is a known arch, so a version with no arch suffix is
// reported whole and arch stays empty (read from the controller, never
// guessed).
func (si SystemInformation) productVersionAndArch() (version, arch string) {
	raw := si.stripVersionPrefix("OPNsense")
	if raw == "" {
		return "", ""
	}
	if i := strings.LastIndex(raw, "-"); i >= 0 {
		if isKnownArch(raw[i+1:]) {
			return raw[:i], raw[i+1:]
		}
	}
	return raw, ""
}

// ProductVersion returns the OPNsense product version without the product
// name and architecture (e.g. "26.7.3_8"), or "" when absent.
func (si SystemInformation) ProductVersion() string {
	v, _ := si.productVersionAndArch()
	return v
}

// Arch returns the architecture of the OPNsense product (e.g. "amd64"), or
// "" when the version carries no recognisable arch suffix.
func (si SystemInformation) Arch() string {
	_, a := si.productVersionAndArch()
	return a
}

// FreeBSDVersion returns the FreeBSD base version without its prefix
// (e.g. "15.1-RELEASE-p3"), or "" when absent.
func (si SystemInformation) FreeBSDVersion() string {
	return si.stripVersionPrefix("FreeBSD")
}

// OpenSSLVersion returns the OpenSSL version without its prefix (e.g.
// "3.5.8"), or "" when absent.
func (si SystemInformation) OpenSSLVersion() string {
	return si.stripVersionPrefix("OpenSSL")
}

// knownArches are the architectures OPNsense ships.
var knownArches = map[string]bool{"amd64": true, "armv6": true, "armv7": true, "aarch64": true}

func isKnownArch(arch string) bool { return knownArches[arch] }

// stripVersionPrefix matches the Versions entry carrying the given product
// prefix (the list order can drift across releases) and returns it without
// that prefix; a miss is "" — the version is reported absent, never guessed.
func (si SystemInformation) stripVersionPrefix(prefix string) string {
	for _, v := range si.Versions {
		if strings.HasPrefix(v, prefix) {
			return strings.TrimPrefix(v, prefix+" ")
		}
	}
	return ""
}

// Interface represents an OPNsense interface with its IP configuration.
// Details fields (Device, MAC, Members, counters) are populated when the
// controller answers interfaces_info?details=true; they stay zero on the
// legacy map shape.
type Interface struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	DHCP        bool     `json:"dhcp"`
	IP          string   `json:"ipv4"`
	Subnet      int      `json:"-"`
	Gateway     string   `json:"ipv4_gateway"`
	Device      string   `json:"device,omitempty"`
	MAC         string   `json:"mac,omitempty"`
	LinkType    string   `json:"link_type,omitempty"`
	Enabled     bool     `json:"enabled,omitempty"`
	MTU         int      `json:"mtu,omitempty"`
	Members     []string `json:"members,omitempty"`
	RxPackets   uint64   `json:"rx_packets,omitempty"`
	RxBytes     uint64   `json:"rx_bytes,omitempty"`
	TxPackets   uint64   `json:"tx_packets,omitempty"`
	TxBytes     uint64   `json:"tx_bytes,omitempty"`
}

// Service is one row from POST /api/core/service/search.
type Service struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Running     bool   `json:"running"`
}

// GatewayStatus is one row from GET /api/routes/gateway/status.
type GatewayStatus struct {
	Name    string `json:"name"`
	Address string `json:"address,omitempty"`
	Status  string `json:"status"`
	Delay   string `json:"delay,omitempty"`
	StdDev  string `json:"stddev,omitempty"`
	Loss    string `json:"loss,omitempty"`
}

// FirewallRule represents a single firewall rule from OPNsense
// (GET /api/firewall/filter/search_rule row shape).
type FirewallRule struct {
	RuleUUID    string   `json:"uuid"`
	Enabled     string   `json:"enabled"` // "1" = enabled
	Action      string   `json:"action"`  // pass / block / reject
	Interface   []string `json:"interface"`
	Protocol    string   `json:"protocol"`
	Source      string   `json:"source_net"`
	Destination string   `json:"destination_net"`
	Label       string   `json:"description"`
	// Disabled is derived from Enabled after decoding.
	Disabled bool
}

// DHCPLease represents a DHCP lease from OPNsense.
type DHCPLease struct {
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
}

// Client is a read-only OPNsense API client using API key/secret auth.
// TLS verification is enabled by default; use NewClient options to customize.
//
// The client is safe for concurrent use: requests are serialised internally.
// The API is stateless (no session, token, or re-login), so a 401 is always a
// stable credential failure and is never retried. Transient failures (network
// errors, HTTP 5xx) are retried with exponential backoff.
type Client struct {
	mu            sync.Mutex
	host          string
	apiKey        string
	apiSecret     string
	httpClient    *http.Client
	log           *slog.Logger
	Debug         bool // when true, raw API responses are printed to stderr
	maxRetries    int
	retryBase     time.Duration
	retryMaxDelay time.Duration
}

// NewClient creates an OPNsense client. No network calls are made here.
// TLS certificate verification is enabled by default. Set skipTLSVerify to true
// for self-signed certs, or provide caCertPath for a custom CA.
func NewClient(host, apiKey, apiSecret string, skipTLSVerify bool, caCertPath string) *Client {
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimRight(host, "/")
	return &Client{
		host:          host,
		apiKey:        apiKey,
		apiSecret:     apiSecret,
		maxRetries:    defaultMaxRetries,
		retryBase:     defaultRetryBase,
		retryMaxDelay: maxRetryDelay,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: buildTLSConfig(skipTLSVerify, caCertPath),
			},
		},
	}
}

// doRequest performs an authenticated GET request to the OPNsense API.
// Kept as a thin wrapper over do so existing callers read naturally.
func (c *Client) doRequest(ctx context.Context, path string) (*http.Response, error) {
	return c.do(ctx, http.MethodGet, path, nil)
}

// GetSystemInformation returns the system information from the controller
// (GET /diagnostics/system/system_information). This endpoint is covered by
// the Dashboard page privilege; the firmware endpoints (/core/firmware/*)
// require the separate System: Firmware privilege and 403 for a
// Dashboard-only API user.
func (c *Client) GetSystemInformation(ctx context.Context) (*SystemInformation, error) {
	resp, err := c.doRequest(ctx, "/diagnostics/system/system_information")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var info SystemInformation
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("decoding system information response: %w", err)
	}
	return &info, nil
}

// GetInterfaces returns the list of interfaces with IP configuration
// (GET /api/interfaces/overview/interfaces_info?details=true). The 26.x generation serves
// a paged rows shape ({"rows":[...]} keyed by "identifier"); the pre-26.x
// shape is a name-keyed map ({"interfaces":{"lan":{...}}}). The rows shape is
// tried first (26.x-first, like the dual-backend lease routes); a body with
// no rows field falls back to the legacy map.
func (c *Client) GetInterfaces(ctx context.Context) ([]Interface, error) {
	resp, err := c.doRequest(ctx, "/interfaces/overview/interfaces_info?details=true")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading interfaces response: %w", err)
	}
	ifaces, err := parseInterfaces(raw)
	if err != nil {
		return nil, fmt.Errorf("decoding interfaces response: %w", err)
	}
	slices.SortFunc(ifaces, func(a, b Interface) int {
		return strings.Compare(a.Name, b.Name)
	})
	return ifaces, nil
}

// parseInterfaces decodes both interfaces_info wire shapes (see
// GetInterfaces). A rows body with an empty identifier names an unassigned
// interface (enc0, pflog0, ...) — those carry no configuration and are
// skipped.
func parseInterfaces(raw []byte) ([]Interface, error) {
	var paged struct {
		Rows []struct {
			Identifier  string `json:"identifier"`
			Description string `json:"description"`
			Device      string `json:"device"`
			MAC         string `json:"macaddr"`
			LinkType    string `json:"link_type"`
			Enabled     bool   `json:"enabled"`
			Addr4       string `json:"addr4"`
			IPV4        []struct {
				IPAddr string `json:"ipaddr"`
			} `json:"ipv4"`
			Gateways   []string `json:"gateways"`
			Statistics struct {
				RX struct {
					Packets uint64 `json:"packets"`
					Bytes   uint64 `json:"bytes"`
				} `json:"rx"`
				TX struct {
					Packets uint64 `json:"packets"`
					Bytes   uint64 `json:"bytes"`
				} `json:"tx"`
			} `json:"statistics"`
			Config struct {
				IF      string `json:"if"`
				Enable  string `json:"enable"`
				MTU     string `json:"mtu"`
				Members string `json:"members"`
			} `json:"config"`
		} `json:"rows"`
	}
	if err := json.Unmarshal(raw, &paged); err != nil {
		return nil, err
	}
	if len(paged.Rows) > 0 {
		var out []Interface
		for _, row := range paged.Rows {
			name := strings.TrimSpace(row.Identifier)
			if name == "" {
				continue
			}
			iface := Interface{
				Name:        name,
				Description: row.Description,
				Device:      firstNonEmpty(row.Device, row.Config.IF),
				MAC:         row.MAC,
				LinkType:    row.LinkType,
				Enabled:     row.Enabled || row.Config.Enable == "1",
				RxPackets:   row.Statistics.RX.Packets,
				RxBytes:     row.Statistics.RX.Bytes,
				TxPackets:   row.Statistics.TX.Packets,
				TxBytes:     row.Statistics.TX.Bytes,
			}
			if mtu, err := strconv.Atoi(row.Config.MTU); err == nil {
				iface.MTU = mtu
			}
			if members := splitCSV(row.Config.Members); len(members) > 0 {
				iface.Members = members
			}
			cidr := row.Addr4
			if cidr == "" && len(row.IPV4) > 0 {
				cidr = row.IPV4[0].IPAddr
			}
			applyCIDR(&iface, cidr)
			if len(row.Gateways) > 0 {
				iface.Gateway = row.Gateways[0]
			}
			out = append(out, iface)
		}
		return out, nil
	}

	var legacy struct {
		Interfaces map[string]struct {
			Description string `json:"description"`
			DHCP        bool   `json:"dhcp"`
			IPProto     string `json:"ipv4"`
			Gateway     string `json:"ipv4_gateway"`
		} `json:"interfaces"`
	}
	if err := json.Unmarshal(raw, &legacy); err != nil {
		return nil, err
	}
	var out []Interface
	for name, entry := range legacy.Interfaces {
		iface := Interface{
			Name:        name,
			Description: entry.Description,
			DHCP:        entry.DHCP,
			Gateway:     entry.Gateway,
		}
		applyCIDR(&iface, entry.IPProto)
		out = append(out, iface)
	}
	return out, nil
}

// applyCIDR splits an "ip/prefix" address into the Interface's IP and
// Subnet fields; an unparseable value leaves both unset.
func applyCIDR(iface *Interface, cidr string) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return
	}
	iface.IP = ip.String()
	ones, _ := ipnet.Mask.Size()
	iface.Subnet = ones
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// GetServices returns the controller service table (POST /api/core/service/search).
// A 403 is the stable page-privilege error and is returned as-is so inventory
// can degrade it the same way as GetFirewallRules.
func (c *Client) GetServices(ctx context.Context) ([]Service, error) {
	var raw []json.RawMessage
	if _, err := fetchPagedListPOST(ctx, c, "/core/service/search", listPageSize, &raw); err != nil {
		return nil, remapPagedDecode(err, "decoding services response")
	}
	out := make([]Service, 0, len(raw))
	for _, row := range raw {
		var rec struct {
			Name        string          `json:"name"`
			Description string          `json:"description"`
			Running     json.RawMessage `json:"running"`
		}
		if err := json.Unmarshal(row, &rec); err != nil || rec.Name == "" {
			continue
		}
		out = append(out, Service{
			Name:        rec.Name,
			Description: rec.Description,
			Running:     decodeLooseBool(rec.Running),
		})
	}
	return out, nil
}

// GetGatewayStatus returns the gateway health table
// (GET /api/routes/gateway/status). A 403 is the stable page-privilege
// error and is returned as-is so inventory can degrade it.
func (c *Client) GetGatewayStatus(ctx context.Context) ([]GatewayStatus, error) {
	resp, err := c.doRequest(ctx, "/routes/gateway/status")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var env struct {
		Items []GatewayStatus `json:"items"`
		Rows  []GatewayStatus `json:"rows"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return nil, fmt.Errorf("decoding gateway status response: %w", err)
	}
	if len(env.Items) > 0 {
		return env.Items, nil
	}
	return env.Rows, nil
}

func decodeLooseBool(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var b bool
	if json.Unmarshal(raw, &b) == nil {
		return b
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s == "1" || strings.EqualFold(s, "true")
	}
	var n int
	if json.Unmarshal(raw, &n) == nil {
		return n != 0
	}
	return false
}

// GetFirewallRules returns all firewall rules from OPNsense.
// Rules are served by a single paged endpoint (GET /api/firewall/filter/search_rule).
// A fetch failure is returned as-is: the provider's import path degrades
// only a stable 403 privilege error (the API user lacks the page privilege)
// to a warned zero-policy spec, and keeps every other failure (401,
// transport, 5xx) fatal — a silent "0 policies" import for a broken key or
// an unreachable controller would hide the real problem.
func (c *Client) GetFirewallRules(ctx context.Context) ([]FirewallRule, error) {
	var raw []json.RawMessage
	if _, err := fetchPagedList(ctx, c, "/firewall/filter/search_rule", listPageSize, &raw); err != nil {
		return nil, remapPagedDecode(err, "decoding firewall rules response")
	}
	out := make([]FirewallRule, 0, len(raw))
	for _, row := range raw {
		var rule FirewallRule
		if err := json.Unmarshal(row, &rule); err != nil {
			continue
		}
		rule.Disabled = rule.Enabled != "1"
		out = append(out, rule)
	}
	return out, nil
}

// leaseRoutes lists the DHCP lease endpoints per active DHCP backend. The
// 26.x generation ships dnsmasq as the default backend, so its route is
// probed first; pre-26.x used the dhcpd backend. Probing order distinguishes
// a missing route (404, skip and try the next) from a present route the API
// user lacks the page privilege for (403, stable — the actionable
// permission-denied error is returned, never retried or masked).
var leaseRoutes = []string{"/dnsmasq/leases/search", "/dhcpd/leases"}

// GetDHCPLeases returns all DHCP leases from OPNsense. The active DHCP
// backend's route is probed in order (see leaseRoutes); a 404 falls through
// to the next route, a 403 fails immediately with the privilege error.
// Accepts both the {"leases": [...]} and paged {"rows": [...]} response
// shapes.
func (c *Client) GetDHCPLeases(ctx context.Context) ([]DHCPLease, error) {
	var lastErr error
	for _, path := range leaseRoutes {
		resp, err := c.doRequest(ctx, path)
		if err != nil {
			var notFound *stableError
			if errors.As(err, &notFound) && strings.Contains(err.Error(), "resource not found") {
				lastErr = err
				continue
			}
			return nil, err
		}
		defer resp.Body.Close()
		leases, derr := decodeDHCPLeases(resp.Body)
		if derr != nil {
			return nil, derr
		}
		return leases, nil
	}
	return nil, lastErr
}

// decodeDHCPLeases decodes either the {"leases": [...]} or paged {"rows":
// [...]} DHCP leases response shape.
func decodeDHCPLeases(r io.Reader) ([]DHCPLease, error) {
	var result struct {
		Leases []DHCPLease `json:"leases"`
		Rows   []DHCPLease `json:"rows"`
	}
	if err := json.NewDecoder(r).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding DHCP leases response: %w", err)
	}
	if len(result.Leases) > 0 {
		return result.Leases, nil
	}
	return result.Rows, nil
}

// buildTLSConfig creates a TLS config based on the provided options.
// By default, standard certificate verification is used.
// If skipTLSVerify is true, verification is disabled (for self-signed certs).
// If caCertPath is set, a custom CA is loaded for verification.
func buildTLSConfig(skipTLSVerify bool, caCertPath string) *tls.Config {
	if caCertPath != "" {
		certPool := x509.NewCertPool()
		// #nosec G304 — path from CLI flag, not user-controlled
		pemData, err := os.ReadFile(caCertPath) // nosemgrep
		if err != nil {
			// Fall back to system pool if file can't be read
			return &tls.Config{MinVersion: tls.VersionTLS12}
		}
		if !certPool.AppendCertsFromPEM(pemData) {
			return &tls.Config{MinVersion: tls.VersionTLS12}
		}
		return &tls.Config{
			RootCAs:    certPool,
			MinVersion: tls.VersionTLS12,
		}
	}
	if skipTLSVerify {
		// nosemgrep codacy.tools-configs.problem-based-packs.insecure-transport.go-stdlib.bypass-tls-verification.bypass-tls-verification — user explicitly opted out for self-signed certs
		return &tls.Config{
			InsecureSkipVerify: true, // #nosec G402 — user explicitly opted out
			MinVersion:         tls.VersionTLS12,
		}
	}
	return &tls.Config{MinVersion: tls.VersionTLS12}
}
