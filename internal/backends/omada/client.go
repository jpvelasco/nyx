// Package omada provides a client for the Omada SDN controller Open API
// (controller 6.x). Reads cover sites, networks, ACL rules, clients, and
// controller info; writes cover ACL rule create and update.
//
// Credentials are never logged or stored beyond the lifetime of the client.
// Authentication mints an access token (OAuth2 client credentials) that is
// refreshed automatically when it expires; the client id and secret are
// retained in memory for that refresh and cleared on Logout, which is a
// local-only operation (the Open API has no logout endpoint).
//
// The client is safe for concurrent use: requests are serialised internally,
// and an expired-token response triggers a single automatic re-mint before
// the original request is retried. Transient failures (network errors, HTTP
// 5xx) are retried with exponential backoff.
//
// Minimum supported controller version: 6.0
// API base path: https://<host>/<omadacId>/openapi/v1
package omada

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jpvelasco/nyx/internal/logger"
)

const (
	// MinControllerVersion is the earliest controller version this backend
	// has been tested against.
	MinControllerVersion = "6.0"

	// openAPIBase is the path segment used by the Omada Open API (6.x).
	openAPIBase = "openapi/v1"

	// defaultMaxRetries is the number of times a transient failure is retried
	// before the error is returned to the caller.
	defaultMaxRetries = 3

	// defaultRetryBase is the initial backoff delay; each retry doubles it.
	defaultRetryBase = 500 * time.Millisecond

	// maxRetryDelay caps the exponential backoff delay.
	maxRetryDelay = 5 * time.Second

	// tokenEndpoint mints access tokens. The grant_type query parameter is
	// mandatory — without it the controller rejects the request.
	tokenEndpoint = "/openapi/authorize/token?grant_type=client_credentials"
)

// retryAction describes how the client responds to a failed request.
type retryAction int

const (
	retryFail    retryAction = iota // give up immediately
	retryBackoff                    // retry with exponential backoff
	retryReauth                     // re-login once, then retry
)

// apiError is a structured failure returned by execute so that the retry
// policy can classify it without string matching.
type apiError struct {
	StatusCode int
	ErrorCode  int
	Msg        string
}

func (e *apiError) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	return fmt.Sprintf("controller error %d", e.ErrorCode)
}

// classifyRetry decides what to do with a failed request error.
func classifyRetry(err error) retryAction {
	var ae *apiError
	if errors.As(err, &ae) {
		switch {
		case ae.ErrorCode == -1000 || ae.ErrorCode == -44112:
			return retryReauth
		case ae.StatusCode == http.StatusUnauthorized:
			return retryReauth
		case ae.StatusCode >= http.StatusInternalServerError:
			return retryBackoff
		default:
			return retryFail
		}
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return retryFail
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		return retryBackoff
	}
	return retryFail
}

// backoffDelay returns the delay before retry attempt n: base doubled per
// attempt, capped at max.
func backoffDelay(attempt int, base, max time.Duration) time.Duration {
	d := base
	for i := 0; i < attempt; i++ {
		if d >= max {
			return max
		}
		d *= 2
	}
	if d > max {
		return max
	}
	return d
}

// sleepCtx sleeps for d or returns early with ctx's error when cancelled.
func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// ControllerInfo holds version metadata from the /api/info endpoint.
// This is the only unauthenticated call we make.
type ControllerInfo struct {
	ControllerVer string `json:"controllerVer"`
	APIVer        string `json:"apiVer"`
	OmadaCID      string `json:"omadacId"`
	Configured    bool   `json:"configured"`
	Type          int    `json:"type"`
	Category      string `json:"omadacCategory"`
}

// apiResponse is the envelope every Omada API response is wrapped in.
type apiResponse struct {
	ErrorCode int             `json:"errorCode"`
	Msg       string          `json:"msg"`
	Result    json.RawMessage `json:"result"`
}

// Client is a stateful Omada Open API client. Create one with NewClient and
// call Login before making any authenticated requests. The client is safe
// for concurrent use — requests are serialised through an internal mutex,
// and an expired-token response triggers a single automatic re-mint using
// the client credentials from the last successful Login.
type Client struct {
	mu           sync.Mutex
	host         string
	omadaCID     string
	token        string
	clientID     string
	clientSecret string // retained in memory for automatic token refresh; cleared on Logout
	httpClient   *http.Client
	info         *ControllerInfo
	log          *logger.Logger
	Debug        bool // when true, raw API responses are printed to stderr

	maxRetries int
	retryBase  time.Duration
}

// NewClient creates an Omada client for the given controller host.
// It immediately fetches /api/info to obtain the omadaCID and validate the
// controller version. No credentials are required for this step.
//
// TLS certificate verification is enabled by default. If the controller uses a
// self-signed certificate, set skipTLSVerify to true or provide caCertPath
// pointing to the controller's CA certificate.
func NewClient(ctx context.Context, host string, skipTLSVerify bool, caCertPath string) (*Client, error) {
	// Strip any trailing slash or scheme — we normalise internally.
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimRight(host, "/")

	tlsConfig := buildTLSConfig(skipTLSVerify, caCertPath)

	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	c := &Client{
		host:       host,
		httpClient: httpClient,
		maxRetries: defaultMaxRetries,
		retryBase:  defaultRetryBase,
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

// Login mints an access token with the supplied client credentials. The
// token is stored on the client and attached to all subsequent requests.
// The credentials are retained in memory so the client can re-mint
// automatically when the token expires, and are cleared by Logout.
// Credentials are never written to any log or evidence output.
func (c *Client) Login(ctx context.Context, clientID, clientSecret string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.clientID = clientID
	c.clientSecret = clientSecret
	if err := c.mintToken(ctx); err != nil {
		c.clientID = ""
		c.clientSecret = ""
		c.logEvent("token_mint_failed", map[string]interface{}{"error": logSafeError(err)})
		return fmt.Errorf("token mint failed: %w", err)
	}
	c.logEvent("token_mint", nil)
	return nil
}

// Logout clears the stored token and client credentials. It is a local-only
// operation: the Open API has no logout endpoint and the token simply
// expires, so no HTTP request is made.
func (c *Client) Logout(_ context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.token == "" {
		c.clientID = ""
		c.clientSecret = ""
		return nil
	}
	c.token = ""
	c.clientID = ""
	c.clientSecret = ""
	c.logEvent("logout", nil)
	return nil
}

// SetLogger attaches an optional structured logger for operation events
// (token mint, re-mint, token expiry, retries). A nil logger disables
// logging. Credentials are never written to the log.
func (c *Client) SetLogger(l *logger.Logger) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.log = l
}

// logEvent records a structured operation event. Callers must hold c.mu.
// Fields never include credentials, hostnames, or IP addresses.
func (c *Client) logEvent(event string, fields map[string]interface{}) {
	if c.log == nil {
		return
	}
	entry := map[string]interface{}{"event": event}
	for k, v := range fields {
		entry[k] = v
	}
	c.log.Info("omada", entry)
}

// logSafeError reduces an error to a static description safe for the log
// file. Transport errors embed the full URL (including the controller
// hostname/IP) and must not be written verbatim.
func logSafeError(err error) string {
	var ae *apiError
	if errors.As(err, &ae) {
		return ae.Error()
	}
	return "transport or protocol error"
}

// -----------------------------------------------------------------------
// Internal HTTP helpers
// -----------------------------------------------------------------------

// baseURL returns the versioned base URL for authenticated API calls.
func (c *Client) baseURL() string {
	return fmt.Sprintf("https://%s/%s/%s", c.host, c.omadaCID, openAPIBase)
}

// mintURL returns the token-mint endpoint. It lives outside the versioned
// base path and is not itself authenticated.
func (c *Client) mintURL() string {
	return fmt.Sprintf("https://%s%s", c.host, tokenEndpoint)
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
	return c.doRequest(ctx, http.MethodGet, path, nil, dest)
}

// post performs an authenticated POST and decodes the result field into dest.
// dest may be nil if the caller doesn't need the result payload.
func (c *Client) post(ctx context.Context, path string, body interface{}, dest interface{}) error {
	if body == nil {
		return c.doRequest(ctx, http.MethodPost, path, nil, dest)
	}
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshaling request body: %w", err)
	}
	return c.doRequest(ctx, http.MethodPost, path, data, dest)
}

// doRequest serialises a request through the client mutex and applies the
// retry and token-refresh policy.
func (c *Client) doRequest(ctx context.Context, method, path string, body []byte, dest interface{}) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.doRequestLocked(ctx, method, c.requestURL(path), path, body, dest, true)
}

// doRequestLocked executes a request, retrying transient failures with
// exponential backoff and re-minting the token once when it has expired.
// logPath is the request path used in retry log entries — the log must
// never carry the controller address. allowReauth is false for the token
// mint itself, so a failed mint can never trigger a recursive re-mint.
func (c *Client) doRequestLocked(ctx context.Context, method, reqURL, logPath string, body []byte, dest interface{}, allowReauth bool) error {
	reauthUsed := false
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, reqURL, bytes.NewReader(body))
		if err != nil {
			return err
		}
		if method == http.MethodPost || method == http.MethodPatch || method == http.MethodPut {
			req.Header.Set("Content-Type", "application/json")
		}
		c.addAuthHeaders(req)

		err = c.execute(req, dest)
		if err == nil {
			return nil
		}
		switch classifyRetry(err) {
		case retryReauth:
			if !allowReauth || reauthUsed || c.clientID == "" {
				return err
			}
			reauthUsed = true
			c.logEvent("token_expired", nil)
			if rerr := c.mintToken(ctx); rerr != nil {
				c.logEvent("token_re_mint_failed", map[string]interface{}{"error": logSafeError(rerr)})
				return fmt.Errorf("%v (automatic re-mint failed: %v)", err, rerr)
			}
			c.logEvent("token_re_mint", nil)
		case retryBackoff:
			if attempt >= c.maxRetries {
				return err
			}
			delay := backoffDelay(attempt, c.retryBase, maxRetryDelay)
			c.logEvent("retry", map[string]interface{}{
				"attempt":  attempt + 1,
				"delay_ms": delay.Milliseconds(),
				"method":   method,
				"path":     logPath,
			})
			if err := sleepCtx(ctx, delay); err != nil {
				return err
			}
		default:
			return err
		}
	}
}

// requestURL joins a versioned base path with the given path.
func (c *Client) requestURL(path string) string {
	return fmt.Sprintf("%s/%s", c.baseURL(), path)
}

// mintToken mints a fresh access token with the stored client credentials
// and updates c.token. Callers must hold c.mu.
func (c *Client) mintToken(ctx context.Context) error {
	body, err := json.Marshal(map[string]string{
		"omadacId":      c.omadaCID,
		"client_id":     c.clientID,
		"client_secret": c.clientSecret,
	})
	if err != nil {
		return fmt.Errorf("marshaling token mint body: %w", err)
	}
	var result struct {
		AccessToken string `json:"accessToken"`
	}
	if err := c.doRequestLocked(ctx, http.MethodPost, c.mintURL(), tokenEndpoint, body, &result, false); err != nil {
		return err
	}
	c.token = result.AccessToken
	return nil
}

// addAuthHeaders attaches the access-token header for authenticated calls.
func (c *Client) addAuthHeaders(req *http.Request) {
	if c.token != "" {
		req.Header.Set("Authorization", "AccessToken="+c.token)
	}
}

// execute performs a single HTTP request, checks the Omada error envelope,
// and decodes the result. Errors are returned as *apiError so the retry
// policy can classify them. Callers must hold c.mu.
func (c *Client) execute(req *http.Request, dest interface{}) error {
	// #nosec G704 — user-specified controller host, not a third-party redirect
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("http request to %s: %w", req.URL.Path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return &apiError{StatusCode: resp.StatusCode, Msg: "not authenticated — call Login first"}
	}

	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response body: %w", err)
	}

	if c.Debug {
		fmt.Fprintf(os.Stderr, "[omada debug] %s %s -> %d\n%s\n",
			req.Method, req.URL.String(), resp.StatusCode, string(rawBody))
	}

	if resp.StatusCode >= http.StatusInternalServerError {
		return &apiError{StatusCode: resp.StatusCode, Msg: fmt.Sprintf("controller returned HTTP %d", resp.StatusCode)}
	}

	var env apiResponse
	if err := json.Unmarshal(rawBody, &env); err != nil {
		return fmt.Errorf("decoding response from %s: %w", req.URL.Path, err)
	}

	switch env.ErrorCode {
	case 0:
		// success
	case -44112:
		return &apiError{ErrorCode: env.ErrorCode, Msg: "access token expired"}
	case -1000:
		return &apiError{ErrorCode: env.ErrorCode, Msg: fmt.Sprintf("session expired or not logged in (errorCode %d)", env.ErrorCode)}
	case -44106:
		return &apiError{ErrorCode: env.ErrorCode, Msg: "invalid client credentials — check OMADA_CLIENT_ID and OMADA_CLIENT_SECRET"}
	case -1005:
		return &apiError{ErrorCode: env.ErrorCode, Msg: "operation forbidden — check account permissions"}
	default:
		return &apiError{ErrorCode: env.ErrorCode, Msg: fmt.Sprintf("controller error %d: %s", env.ErrorCode, env.Msg)}
	}

	if dest != nil && len(env.Result) > 0 {
		if err := json.Unmarshal(env.Result, dest); err != nil {
			return fmt.Errorf("decoding result from %s: %w", req.URL.Path, err)
		}
	}
	return nil
}

// isVersionSupported returns true if the controller version is at least
// MinControllerVersion, compared numerically on major and minor.
func isVersionSupported(ver string) bool {
	parts := strings.Split(ver, ".")
	if len(parts) < 2 {
		return false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return false
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return false
	}
	return major > 6 || (major == 6 && minor >= 0)
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
			fmt.Fprintf(os.Stderr, "warning: failed to read CA cert %q: %v; using system CA pool\n", caCertPath, err)
			return &tls.Config{MinVersion: tls.VersionTLS12}
		}
		if !certPool.AppendCertsFromPEM(pemData) {
			fmt.Fprintf(os.Stderr, "warning: no valid certs found in %q; using system CA pool\n", caCertPath)
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
