package opnsense

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
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
	DHCP        string `json:"dhcp"`
	IP          string `json:"ip"`
	Subnet      int    `json:"subnet"`
	Gateway     string `json:"gateway"`
}

// FirewallRule represents a single firewall rule from OPNsense.
type FirewallRule struct {
	Type      string `json:"type"`
	Interface string `json:"interface"`
	Protocol  string `json:"protocol"`
	Source    struct {
		Address string `json:"address"`
	} `json:"source"`
	Destination struct {
		Address string `json:"address"`
	} `json:"destination"`
	Action   string `json:"action"`
	Disabled bool   `json:"disabled"`
	Label    string `json:"label"`
	RuleUUID string `json:"uuid"`
}

// DHCPLease represents a DHCP lease from OPNsense.
type DHCPLease struct {
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
}

// Client is a read-only OPNsense API client using API key/secret auth.
// TLS verification is skipped because OPNsense ships with a self-signed cert.
type Client struct {
	host       string
	apiKey     string
	apiSecret  string
	httpClient *http.Client
}

// NewClient creates an OPNsense client. No network calls are made here.
func NewClient(host, apiKey, apiSecret string) *Client {
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
				// nosemgrep
				TLSClientConfig: &tls.Config{
					// #nosec G402 — self-signed controller cert
					// lgtm[go/disabled-certificate-check]
					InsecureSkipVerify: true, // nosemgrep
				},
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
func (c *Client) GetInterfaces(ctx context.Context) ([]Interface, error) {
	resp, err := c.doRequest(ctx, "/core/interfaces/status")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Interfaces []Interface `json:"interfaces"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding interfaces response: %w", err)
	}
	return result.Interfaces, nil
}

// GetFirewallRules returns all firewall rules from OPNsense.
func (c *Client) GetFirewallRules(ctx context.Context) ([]FirewallRule, error) {
	var allRules []FirewallRule

	// Fetch rules from each interface
	for _, iface := range []string{"wan", "lan", "opt1", "opt2", "opt3", "opt4", "opt5"} {
		resp, err := c.doRequest(ctx, fmt.Sprintf("/core/firewall/rules/%s", iface))
		if err != nil {
			// Some interfaces may not exist; skip them
			continue
		}
		defer resp.Body.Close() //nolint:defer-in-loop // best-effort: if a request panics, the process exits anyway

		var result struct {
			Rules []FirewallRule `json:"rules"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			continue
		}
		allRules = append(allRules, result.Rules...)
	}
	return allRules, nil
}

// GetDHCPLeases returns all DHCP leases from OPNsense.
func (c *Client) GetDHCPLeases(ctx context.Context) ([]DHCPLease, error) {
	resp, err := c.doRequest(ctx, "/core/dhcp/leases")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Leases []DHCPLease `json:"leases"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding DHCP leases response: %w", err)
	}
	return result.Leases, nil
}
