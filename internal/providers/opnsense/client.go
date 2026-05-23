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

type firmwareInfoResponse struct {
	ProductVersion string `json:"product_version"`
	ProductName    string `json:"product_name"`
	ProductArch    string `json:"product_arch"`
}

// Client is a minimal read-only OPNsense API client using Basic Auth.
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
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, //nolint:gosec // self-signed controller cert
				},
			},
		},
	}
}

// GetFirmwareInfo returns the running firmware version from the controller.
func (c *Client) GetFirmwareInfo(ctx context.Context) (*firmwareInfoResponse, error) {
	url := fmt.Sprintf("https://%s/api/core/firmware/running", c.host)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.apiKey, c.apiSecret)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("connecting to OPNsense at %s: %w", c.host, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("authentication failed — check API key and secret")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d from OPNsense", resp.StatusCode)
	}

	var info firmwareInfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("decoding firmware response: %w", err)
	}
	return &info, nil
}
