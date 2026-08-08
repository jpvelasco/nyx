package opnsense

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"
)

// FirmwareInfoResponse holds the firmware version, name, and architecture from OPNsense.
type FirmwareInfoResponse struct {
	ProductVersion string `json:"product_version"`
	ProductName    string `json:"product_name"`
	ProductArch    string `json:"product_arch"`
}

// Interface represents an OPNsense interface with its IP configuration.
type Interface struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	DHCP        bool   `json:"dhcp"`
	IP          string `json:"ipv4"`
	Subnet      int    `json:"-"`
	Gateway     string `json:"ipv4_gateway"`
}

// FirewallRule represents a single firewall rule from OPNsense
// (GET /api/firewall/filter/searchRule row shape).
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
type Client struct {
	host       string
	apiKey     string
	apiSecret  string
	httpClient *http.Client
}

// NewClient creates an OPNsense client. No network calls are made here.
// TLS certificate verification is enabled by default. Set skipTLSVerify to true
// for self-signed certs, or provide caCertPath for a custom CA.
func NewClient(host, apiKey, apiSecret string, skipTLSVerify bool, caCertPath string) *Client {
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimRight(host, "/")
	return &Client{
		host:      host,
		apiKey:    apiKey,
		apiSecret: apiSecret,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: buildTLSConfig(skipTLSVerify, caCertPath),
			},
		},
	}
}

// doRequest performs an authenticated GET request to the OPNsense API.
func (c *Client) doRequest(ctx context.Context, path string) (*http.Response, error) {
	url := fmt.Sprintf("https://%s/api%s", c.host, path)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.apiKey, c.apiSecret)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("connecting to OPNsense at %s: %w", c.host, err)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		resp.Body.Close() // #nosec G104 — close error unactionable in error path
		return nil, fmt.Errorf("authentication failed — check API key and secret")
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		return nil, fmt.Errorf("unexpected status %d from OPNsense for %s", resp.StatusCode, path)
	}
	return resp, nil
}

// GetFirmwareInfo returns the running firmware version from the controller.
func (c *Client) GetFirmwareInfo(ctx context.Context) (*FirmwareInfoResponse, error) {
	resp, err := c.doRequest(ctx, "/core/firmware/running")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var info FirmwareInfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("decoding firmware response: %w", err)
	}
	return &info, nil
}

// GetInterfaces returns the list of interfaces with IP configuration.
// OPNsense serves these keyed by interface name with the address as
// "ip/prefix" under ipv4 (GET /api/interfaces/overview/interfaces_info).
func (c *Client) GetInterfaces(ctx context.Context) ([]Interface, error) {
	resp, err := c.doRequest(ctx, "/interfaces/overview/interfaces_info")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Interfaces map[string]struct {
			Description string `json:"description"`
			DHCP        bool   `json:"dhcp"`
			IPProto     string `json:"ipv4"`
			Gateway     string `json:"ipv4_gateway"`
		} `json:"interfaces"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding interfaces response: %w", err)
	}

	var ifaces []Interface
	for name, raw := range result.Interfaces {
		iface := Interface{
			Name:        name,
			Description: raw.Description,
			DHCP:        raw.DHCP,
			Gateway:     raw.Gateway,
		}
		if ip, ipnet, err := net.ParseCIDR(raw.IPProto); err == nil {
			iface.IP = ip.String()
			ones, _ := ipnet.Mask.Size()
			iface.Subnet = ones
		}
		ifaces = append(ifaces, iface)
	}
	slices.SortFunc(ifaces, func(a, b Interface) int {
		return strings.Compare(a.Name, b.Name)
	})
	return ifaces, nil
}

// GetFirewallRules returns all firewall rules from OPNsense.
// Rules are served by a single paged endpoint (GET /api/firewall/filter/searchRule);
// any fetch failure is surfaced to the caller — a silent "0 policies" import
// would hide real problems like revoked keys or an unreachable controller.
func (c *Client) GetFirewallRules(ctx context.Context) ([]FirewallRule, error) {
	resp, err := c.doRequest(ctx, "/firewall/filter/searchRule")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Total int            `json:"total"`
		Rows  []FirewallRule `json:"rows"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding firewall rules response: %w", err)
	}
	for i := range result.Rows {
		result.Rows[i].Disabled = result.Rows[i].Enabled != "1"
	}
	return result.Rows, nil
}

// GetDHCPLeases returns all DHCP leases from OPNsense.
// Accepts both the {"leases": [...]} and paged {"rows": [...]} response shapes.
func (c *Client) GetDHCPLeases(ctx context.Context) ([]DHCPLease, error) {
	resp, err := c.doRequest(ctx, "/dhcpd/leases")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Leases []DHCPLease `json:"leases"`
		Rows   []DHCPLease `json:"rows"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
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
