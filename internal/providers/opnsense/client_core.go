package opnsense

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/jpvelasco/nyx/internal/logger"
)

const (
	// defaultMaxRetries is the number of times a transient failure is retried
	// before the error is returned to the caller.
	defaultMaxRetries = 3

	// defaultRetryBase is the initial backoff delay; each retry doubles it.
	defaultRetryBase = 500 * time.Millisecond

	// maxRetryDelay caps the exponential backoff delay.
	maxRetryDelay = 5 * time.Second
)

// SetLogger attaches an optional structured logger for operation events
// (retries). A nil logger disables logging. Credentials are never written
// to the log.
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
	c.log.Info("opnsense", entry)
}

// do performs an authenticated request to the OPNsense API and returns the
// raw response. GET and POST (JSON body) are supported. The request is
// serialised through the client mutex and transient failures (transport
// errors, HTTP 5xx) are retried with exponential backoff. Stable failures —
// 401 (stateless API key/secret: retrying cannot repair bad credentials),
// 404, and other 4xx — fail immediately without retry.
func (c *Client) do(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	url := fmt.Sprintf("https://%s/api%s", c.host, path)
	var lastErr error
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
		if err != nil {
			// A context error surfaces as a bare error here (not wrapped
			// in *url.Error) — fail fast, never retry.
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil, err
			}
			return nil, fmt.Errorf("building request for %s: %w", path, err)
		}
		req.SetBasicAuth(c.apiKey, c.apiSecret)
		if method != http.MethodGet {
			req.Header.Set("Content-Type", "application/json")
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			// http.Client wraps transport failures in *url.Error; a
			// context deadline mid-flight surfaces as the context error.
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil, err
			}
			lastErr = fmt.Errorf("connecting to OPNsense at %s: %w", c.host, err)
		} else {
			lastErr = c.classifyStatus(resp, path)
			if lastErr == nil {
				return resp, nil
			}
			// A failed response body must be drained and closed so the
			// retry does not leak the connection.
			drainBody(resp.Body)
		}

		action := classifyRetry(lastErr)
		if action == retryFail || attempt >= c.maxRetries {
			return nil, lastErr
		}
		delay := backoffDelay(attempt, c.retryBase, c.retryMaxDelay)
		c.logEvent("retry", map[string]interface{}{
			"attempt":  attempt + 1,
			"delay_ms": delay.Milliseconds(),
			"method":   method,
			"path":     path,
		})
		if err := sleepCtx(ctx, delay); err != nil {
			return nil, err
		}
	}
}

// classifyStatus turns a non-2xx response into a typed error, or nil when the
// response is a plain success. The response body is left open — the caller
// owns it and must drain/close on error.
func (c *Client) classifyStatus(resp *http.Response, path string) error {
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return &stableError{fmt.Errorf("authentication failed — check API key and secret")}
	}
	if resp.StatusCode == http.StatusForbidden {
		return &stableError{fmt.Errorf("permission denied: %s on OPNsense at %s — the API user lacks the privilege for this endpoint; grant the matching page privilege to the user (System ‣ Access ‣ Users)", path, c.host)}
	}
	if resp.StatusCode == http.StatusNotFound {
		return &stableError{fmt.Errorf("resource not found: %s on OPNsense at %s", path, c.host)}
	}
	if resp.StatusCode >= http.StatusInternalServerError {
		return fmt.Errorf("unexpected status %d from OPNsense for %s", resp.StatusCode, path)
	}
	return &stableError{fmt.Errorf("unexpected status %d from OPNsense for %s", resp.StatusCode, path)}
}

// stableError marks a failure that must not be retried: the failure is
// deterministic (bad credentials, missing resource, client-side 4xx).
type stableError struct{ err error }

func (e *stableError) Error() string { return e.err.Error() }

// retryAction describes how the client responds to a failed request.
type retryAction int

const (
	retryFail    retryAction = iota // give up immediately
	retryBackoff                    // retry with exponential backoff
)

// classifyRetry decides whether a failed request is retried with backoff
// (transient) or fails immediately (stable).
func classifyRetry(err error) retryAction {
	var se *stableError
	if errors.As(err, &se) {
		return retryFail
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return retryFail
	}
	return retryBackoff
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

// drainBody fully reads and closes a response body. Used on the retry path
// where the response is discarded, so the connection can be reused.
func drainBody(body io.ReadCloser) {
	if body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, body)
	_ = body.Close()
}
