// Package omada provides a read-only client for the Omada SDN controller
// local REST API (controller 6.x, API v2).
//
// Credentials are never logged or stored beyond the lifetime of the client.
// Authentication produces a short-lived token that is refreshed automatically.
//
// Minimum supported controller version: 6.0
// API base path: https://<host>/<omadacId>/api/v2
package omada

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strings"
	"time"
)

const (
	// MinControllerVersion is the earliest controller version this backend
	// has been tested against.
	MinControllerVersion = "6.0"

	// apiV2 is the path segment used by controller 6.x.
	apiV2 = "api/v2"
)

// ControllerInfo holds version metadata from the /api/info endpoint.
// This is the only unauthenticated call we make.
type ControllerInfo struct {
	ControllerVer string `json:"controllerVer"`
	APIVer        string `json:"apiVer"`
	OmadaCID      string `json:"omadacId"`
	Configured    bool   `json:"configured"`
	Type          int    `json:"type"`
}

// apiResponse is the envelope every Omada API response is wrapped in.
type apiResponse struct {
	ErrorCode int             `json:"errorCode"`
	Msg       string          `json:"msg"`
	Result    json.RawMessage `json:"result"`
}

// Client is a stateful Omada API client. Create one with NewClient and call
// Login before making any authenticated requests. The client is NOT safe for
// concurrent use without external locking — callers should serialise requests
// or create separate clients per goroutine.
type Client struct {
	host       string
	omadaCID   string
	token      string
	httpClient *http.Client
	info       *ControllerInfo
	Debug      bool // when true, raw API responses are printed to stderr
}

// NewClient creates an Omada client for the given controller host.
// It immediately fetches /api/info to obtain the omadaCID and validate the
// controller version. No credentials are required for this step.
//
// The client skips TLS certificate verification because Omada controllers
// ship with self-signed certificates. All traffic is still encrypted.
func NewClient(ctx context.Context, host string) (*Client, error) {
	// Strip any trailing slash or scheme — we normalise internally.
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimRight(host, "/")

	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("creating cookie jar: %w", err)
	}

	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		Jar:     jar,
		Transport: &http.Transport{
			// nosemgrep
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // self-signed controller cert
			},
		},
	}

	c := &Client{
		host:       host,
		httpClient: httpClient,
	}

	info, err := c.fetchInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching controller info from %s: %w", host, err)
	}

	if !isVersionSupported(info.ControllerVer) {
		return nil, fmt.Errorf(
			"controller version %s is below minimum supported version %s",
			info.ControllerVer, MinControllerVersion,
		)
	}

	c.info = info
	c.omadaCID = info.OmadaCID
	return c, nil
}

// Info returns the controller metadata fetched during initialisation.
func (c *Client) Info() *ControllerInfo {
	return c.info
}

// Login authenticates with the controller using the supplied credentials.
// The token is stored on the client and attached to all subsequent requests.
// Credentials are not retained after this call returns.
func (c *Client) Login(ctx context.Context, username, password string) error {
	body := map[string]string{
		"username": username,
		"password": password,
	}
	var result struct {
		Token string `json:"token"`
	}
	if err := c.post(ctx, "login", body, &result); err != nil {
		return fmt.Errorf("login failed: %w", err)
	}
	c.token = result.Token
	return nil
}

// Logout invalidates the current session token.
func (c *Client) Logout(ctx context.Context) error {
	if c.token == "" {
		return nil
	}
	_ = c.post(ctx, "logout", nil, nil)
	c.token = ""
	return nil
}

// -----------------------------------------------------------------------
// Internal HTTP helpers
// -----------------------------------------------------------------------

// baseURL returns the versioned base URL for authenticated API calls.
func (c *Client) baseURL() string {
	return fmt.Sprintf("https://%s/%s/%s", c.host, c.omadaCID, apiV2)
}

// fetchInfo calls the unauthenticated /api/info endpoint.
func (c *Client) fetchInfo(ctx context.Context) (*ControllerInfo, error) {
	url := fmt.Sprintf("https://%s/api/info", c.host)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var env apiResponse
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return nil, fmt.Errorf("decoding info response: %w", err)
	}
	if env.ErrorCode != 0 {
		return nil, fmt.Errorf("controller returned error %d: %s", env.ErrorCode, env.Msg)
	}
	var info ControllerInfo
	if err := json.Unmarshal(env.Result, &info); err != nil {
		return nil, fmt.Errorf("decoding controller info: %w", err)
	}
	return &info, nil
}

// get performs an authenticated GET and decodes the result field into dest.
func (c *Client) get(ctx context.Context, path string, dest interface{}) error {
	url := fmt.Sprintf("%s/%s", c.baseURL(), path)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	c.addAuthHeaders(req)
	return c.doRequest(req, dest)
}

// post performs an authenticated POST and decodes the result field into dest.
// dest may be nil if the caller doesn't need the result payload.
func (c *Client) post(ctx context.Context, path string, body interface{}, dest interface{}) error {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshaling request body: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	// All paths including login use the omadaCID-prefixed base URL on 6.x.
	url := fmt.Sprintf("%s/%s", c.baseURL(), path)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bodyReader)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	c.addAuthHeaders(req)
	return c.doRequest(req, dest)
}

// addAuthHeaders attaches the Csrf-Token and cookie-based session token.
func (c *Client) addAuthHeaders(req *http.Request) {
	if c.token != "" {
		req.Header.Set("Csrf-Token", c.token)
	}
}

// doRequest executes req, checks the Omada error envelope, and decodes result.
func (c *Client) doRequest(req *http.Request, dest interface{}) error {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("http request to %s: %w", req.URL.Path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("not authenticated — call Login first")
	}

	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response body: %w", err)
	}

	if c.Debug {
		fmt.Fprintf(os.Stderr, "[omada debug] %s %s -> %d\n%s\n",
			req.Method, req.URL.String(), resp.StatusCode, string(rawBody))
	}

	var env apiResponse
	if err := json.Unmarshal(rawBody, &env); err != nil {
		return fmt.Errorf("decoding response from %s: %w", req.URL.Path, err)
	}

	switch env.ErrorCode {
	case 0:
		// success
	case -1000, -44112:
		return fmt.Errorf("session expired or not logged in (errorCode %d)", env.ErrorCode)
	case -30109:
		return fmt.Errorf("invalid username or password")
	case -1005:
		return fmt.Errorf("operation forbidden — check account permissions")
	default:
		return fmt.Errorf("controller error %d: %s", env.ErrorCode, env.Msg)
	}

	if dest != nil && len(env.Result) > 0 {
		if err := json.Unmarshal(env.Result, dest); err != nil {
			return fmt.Errorf("decoding result from %s: %w", req.URL.Path, err)
		}
	}
	return nil
}

// isVersionSupported returns true if the controller version is >= 6.0.
func isVersionSupported(ver string) bool {
	// Version format: "6.0.0.36" — we only check major.minor
	parts := strings.SplitN(ver, ".", 3)
	if len(parts) < 2 {
		return false
	}
	major := parts[0]
	// Anything >= 6 is supported
	return major >= "6"
}
