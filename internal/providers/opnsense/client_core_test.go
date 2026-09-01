package opnsense

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jpvelasco/nyx/internal/logger"
	"github.com/jpvelasco/nyx/internal/testutil"
)

// captureStderr runs f while redirecting os.Stderr and returns what f wrote.
func captureStderr(t *testing.T, f func()) string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stderr = w
	f()
	_ = w.Close()
	os.Stderr = old
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	return buf.String()
}

// fastTestClient is like newTestClient but with a 1ms retry base so retry
// paths don't sleep; the default retry count (3) is preserved.
func fastTestClient(t *testing.T, h http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	c, ts := newTestClient(t, h)
	c.retryBase = time.Millisecond
	return c, ts
}

// S1.1 — Basic auth on every call.
func TestDoBasicAuth(t *testing.T) {
	var sawKey, sawSecret string
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if k, s, ok := r.BasicAuth(); ok {
			sawKey, sawSecret = k, s
		}
		testutil.WriteBody(w, systemInfoJSON)
	}))
	resp, err := c.do(context.Background(), http.MethodGet, "/diagnostics/system/system_information", nil)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	resp.Body.Close()
	if sawKey != "key" || sawSecret != "secret" {
		t.Errorf("basic auth = %q/%q, want key/secret", sawKey, sawSecret)
	}
}

// S1.1 — do POSTs a JSON body verbatim with the JSON content type.
func TestDoPostJSON(t *testing.T) {
	var method, contentType, body string
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		contentType = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		testutil.WriteBody(w, `{"ok":true}`)
	}))
	resp, err := c.do(context.Background(), http.MethodPost, "/firewall/alias/search_item", []byte(`{"current":1,"rowCount":5}`))
	if err != nil {
		t.Fatalf("do POST: %v", err)
	}
	var out struct {
		OK bool `json:"ok"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	resp.Body.Close()
	if !out.OK {
		t.Errorf("response = %+v, want ok", out)
	}
	if method != http.MethodPost {
		t.Errorf("method = %q, want POST", method)
	}
	if contentType != "application/json" {
		t.Errorf("content type = %q, want application/json", contentType)
	}
	if body != `{"current":1,"rowCount":5}` {
		t.Errorf("body = %q, want the JSON payload verbatim", body)
	}
}

// S1.2 — 401 is a stable auth failure: no retry.
func TestDoUnauthorizedNoRetry(t *testing.T) {
	var calls int32
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	_, err := c.do(context.Background(), http.MethodGet, "/x", nil)
	if err == nil || !strings.Contains(err.Error(), "authentication failed — check API key and secret") {
		t.Errorf("error = %v, want authentication failed", err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("requests = %d, want 1 (401 must not be retried)", got)
	}
}

// S1.3 — 404 is a stable failure: no retry, path surfaced.
func TestDoNotFound(t *testing.T) {
	var calls int32
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusNotFound)
	}))
	_, err := c.do(context.Background(), http.MethodGet, "/firewall/d_nat/search_rule", nil)
	if err == nil ||
		!strings.Contains(err.Error(), "resource not found") ||
		!strings.Contains(err.Error(), "/firewall/d_nat/search_rule") {
		t.Errorf("error = %v, want resource not found naming the path", err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("requests = %d, want 1 (404 must not be retried)", got)
	}
}

// S1.4 — 5xx is retried with doubling backoff: two failures then success on
// the third attempt (3 requests total).
func TestDoRetriesTransientThenSucceeds(t *testing.T) {
	var calls int32
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n <= 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		testutil.WriteBody(w, `{"ok":true}`)
	}))
	resp, err := c.do(context.Background(), http.MethodGet, "/diagnostics/system/system_information", nil)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	resp.Body.Close()
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Errorf("requests = %d, want 3 (2 failures + success)", got)
	}
}

// S1.4 — the default schedule: 500ms base doubled to 1s, and the retry
// budget caps at 3 retries (4 requests total).
func TestDoDefaultRetryBudgetAndDelays(t *testing.T) {
	var calls int32
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	start := time.Now()
	_, err := c.do(context.Background(), http.MethodGet, "/x", nil)
	elapsed := time.Since(start)
	if err == nil || !strings.Contains(err.Error(), "unexpected status 500") {
		t.Errorf("error = %v, want unexpected status 500", err)
	}
	if got := atomic.LoadInt32(&calls); got != 4 {
		t.Errorf("requests = %d, want 4 (1 initial + 3 default retries)", got)
	}
	// Default schedule: 500ms + 1s = 1.5s (the third retry is skipped when
	// the budget runs out), so the elapsed time brackets that sum.
	if elapsed < 1300*time.Millisecond || elapsed > 5*time.Second {
		t.Errorf("elapsed = %v, want ~1.5s of backoff (500ms then 1s)", elapsed)
	}
}

// S1.5 — retry budget exhausted with a fast base: exactly 4 attempts.
func TestDoRetryExhausted(t *testing.T) {
	var calls int32
	c, _ := fastTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	_, err := c.do(context.Background(), http.MethodGet, "/x", nil)
	if err == nil || !strings.Contains(err.Error(), "unexpected status 500") {
		t.Errorf("error = %v, want unexpected status 500", err)
	}
	if got := atomic.LoadInt32(&calls); got != 4 {
		t.Errorf("requests = %d, want 4 (1 initial + 3 retries)", got)
	}
}

// S1.6 — transport failures surface the connecting-to-OPNsense message.
func TestDoConnectionFailure(t *testing.T) {
	c := NewClient("https://127.0.0.1:1", "k", "s", true, "")
	c.retryBase = time.Millisecond
	_, err := c.do(context.Background(), http.MethodGet, "/x", nil)
	if err == nil || !strings.Contains(err.Error(), "connecting to OPNsense") {
		t.Errorf("error = %v, want connecting-to-OPNsense", err)
	}
}

// S1.7 — 4xx (other than 401) is not retried.
func TestDoClientErrorNoRetry(t *testing.T) {
	var calls int32
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusForbidden)
	}))
	_, err := c.do(context.Background(), http.MethodGet, "/x", nil)
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("error = %v, want permission denied", err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("requests = %d, want 1 (403 must not be retried)", got)
	}
}

// S1.7b — 403 is a stable failure with an actionable privilege hint: the
// error must name the endpoint and point at the user privilege settings,
// because a Forbidden means the API user lacks the page privilege.
func TestDoForbiddenPrivilegeHint(t *testing.T) {
	var calls int32
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusForbidden)
		testutil.WriteBody(w, `{"status":403,"message":"Forbidden"}`)
	}))
	_, err := c.do(context.Background(), http.MethodGet, "/diagnostics/system/system_information", nil)
	for _, want := range []string{"/diagnostics/system/system_information", "permission denied", "lacks the privilege"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("error = %v, want it to contain %q", err, want)
		}
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("requests = %d, want 1 (403 must not be retried)", got)
	}
}

// S1.8 — concurrent calls never overlap (internal mutex).
func TestDoRequestsSerialised(t *testing.T) {
	var inFlight, maxInFlight int32
	c, _ := fastTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cur := atomic.AddInt32(&inFlight, 1)
		if cur > atomic.LoadInt32(&maxInFlight) {
			atomic.StoreInt32(&maxInFlight, cur)
		}
		time.Sleep(5 * time.Millisecond)
		atomic.AddInt32(&inFlight, -1)
		testutil.WriteBody(w, `{"ok":true}`)
	}))
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := c.do(context.Background(), http.MethodGet, "/diagnostics/system/system_information", nil)
			if err != nil {
				t.Errorf("do: %v", err)
				return
			}
			resp.Body.Close()
		}()
	}
	wg.Wait()
	if got := atomic.LoadInt32(&maxInFlight); got > 1 {
		t.Errorf("max concurrent in-flight = %d, want 1 (requests must be serialised)", got)
	}
}

// S1.9 — a cancelled context ends the call promptly without retrying.
func TestDoCancelledContext(t *testing.T) {
	var calls int32
	c, _ := fastTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	_, err := c.do(ctx, http.MethodGet, "/x", nil)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want context.Canceled", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("call took %v, want prompt return on cancelled context", elapsed)
	}
	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Errorf("requests = %d, want 0 (cancelled before the first attempt)", got)
	}
}

// S1.9b — a cancelled context during the retry backoff ends the call with
// the context error; the second request never starts. Cancellation is
// deterministic: the handler holds the first request until the test signals
// (past the first attempt, before the backoff sleep) and the main goroutine
// cancels immediately on that signal.
func TestDoCancelledDuringRetryBackoff(t *testing.T) {
	var calls int32
	first := make(chan struct{})
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			close(first)
			time.Sleep(20 * time.Millisecond) // still inside the first attempt when cancel fires
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	c.retryBase = 200 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, err := c.do(ctx, http.MethodGet, "/x", nil)
		done <- err
	}()

	select {
	case <-first:
	case <-time.After(5 * time.Second):
		t.Fatal("first request never reached the server")
	}
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("error = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("do did not return after context cancellation")
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("requests = %d, want 1 (retry must not start after cancellation)", got)
	}
}

// S1.10 — retries emit a structured event carrying method, path, attempt,
// and delay; no event carries credentials or the controller host.
func TestDoRetriesAreLogged(t *testing.T) {
	var calls int32
	c, _ := fastTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		testutil.WriteBody(w, `{"ok":true}`)
	}))

	dir := t.TempDir()
	l, err := logger.NewSlog(dir+"/nyx.log", 5*1024*1024, 3, slog.LevelDebug)
	if err != nil {
		t.Fatalf("logger.NewSlog: %v", err)
	}
	c.SetLogger(l)

	resp, err := c.do(context.Background(), http.MethodGet, "/firewall/d_nat/search_rule", nil)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	resp.Body.Close()
	logger.CloseSlog(l)

	raw, err := os.ReadFile(dir + "/nyx.log") // nosemgrep: go_filesystem_rule-fileread — path is a fixed test log name under t.TempDir()
	if err != nil {
		t.Fatalf("reading log: %v", err)
	}
	text := string(raw)
	for _, want := range []string{`"event":"retry"`, `d_nat/search_rule`, `"attempt":1`, `"method":"GET"`} {
		if !strings.Contains(text, want) {
			t.Errorf("log missing %s: %s", want, text)
		}
	}
	// The client was built with API key "key" / secret "secret" (see
	// newTestClient) — neither may appear, nor the controller host.
	for _, secret := range []string{`"key"`, `secret`, c.host} {
		if strings.Contains(text, secret) {
			t.Errorf("log leaked %q: %s", secret, text)
		}
	}
}

// S1.10 — a nil logger never breaks a call (success or retry path).
func TestDoNilLogger(t *testing.T) {
	var calls int32
	c, _ := fastTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		testutil.WriteBody(w, `{"ok":true}`)
	}))
	c.SetLogger(nil)
	resp, err := c.do(context.Background(), http.MethodGet, "/diagnostics/system/system_information", nil)
	if err != nil {
		t.Fatalf("do with nil logger: %v", err)
	}
	resp.Body.Close()
}

// backoffDelay math: base doubled per attempt, capped at max.
func TestBackoffDelay(t *testing.T) {
	cases := []struct {
		attempt int
		base    time.Duration
		max     time.Duration
		want    time.Duration
	}{
		{0, 500 * time.Millisecond, 5 * time.Second, 500 * time.Millisecond},
		{1, 500 * time.Millisecond, 5 * time.Second, time.Second},
		{2, 500 * time.Millisecond, 5 * time.Second, 2 * time.Second},
		{3, 500 * time.Millisecond, 5 * time.Second, 4 * time.Second},
		{4, 500 * time.Millisecond, 5 * time.Second, 5 * time.Second},
		{10, 500 * time.Millisecond, 5 * time.Second, 5 * time.Second},
	}
	for _, tc := range cases {
		if got := backoffDelay(tc.attempt, tc.base, tc.max); got != tc.want {
			t.Errorf("backoffDelay(%d, %v, %v) = %v, want %v", tc.attempt, tc.base, tc.max, got, tc.want)
		}
	}
}

// classifyRetry: stable failures and context errors fail fast; everything
// else is transient and retried with backoff.
func TestClassifyRetry(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want retryAction
	}{
		{"stable 401", &stableError{errors.New("authentication failed — check API key and secret")}, retryFail},
		{"stable 404", &stableError{errors.New("resource not found")}, retryFail},
		{"wrapped stable", fmt.Errorf("outer: %w", &stableError{errors.New("bad")}), retryFail},
		{"context canceled", context.Canceled, retryFail},
		{"context deadline exceeded", context.DeadlineExceeded, retryFail},
		{"transient 5xx", errors.New("unexpected status 500 from OPNsense for /x"), retryBackoff},
		{"transient transport", errors.New("connecting to OPNsense at gateway.local: connection refused"), retryBackoff},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyRetry(tc.err); got != tc.want {
				t.Errorf("classifyRetry(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// sleepCtx: nil on a natural timeout, the context error when cancelled.
func TestSleepCtx(t *testing.T) {
	t.Run("returns nil when the timer fires", func(t *testing.T) {
		if err := sleepCtx(context.Background(), 2*time.Millisecond); err != nil {
			t.Fatalf("sleepCtx = %v, want nil", err)
		}
	})
	t.Run("returns the context error when cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := sleepCtx(ctx, 500*time.Millisecond); !errors.Is(err, context.Canceled) {
			t.Fatalf("sleepCtx = %v, want context.Canceled", err)
		}
	})
	t.Run("returns the deadline error when the deadline passes", func(t *testing.T) {
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(1*time.Millisecond))
		defer cancel()
		if err := sleepCtx(ctx, 500*time.Millisecond); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("sleepCtx = %v, want context.DeadlineExceeded", err)
		}
	})
}

// fetchPagedList walks a paged OPNsense list endpoint
// ({"total":N,"rowCount":P,"current":C,"rows":[...]}).
func TestFetchPagedList(t *testing.T) {
	t.Run("walks all pages", func(t *testing.T) {
		var pages []string
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			pages = append(pages, r.URL.Query().Get("current"))
			switch r.URL.Query().Get("current") {
			case "1":
				testutil.WriteBody(w, `{"total":3,"rowCount":2,"current":1,"rows":[{"n":1},{"n":2}]}`)
			case "2":
				testutil.WriteBody(w, `{"total":3,"rowCount":2,"current":2,"rows":[{"n":3}]}`)
			default:
				t.Errorf("unexpected page query %q", r.URL.Query().Get("current"))
				w.WriteHeader(http.StatusBadRequest)
			}
		}))
		var got []json.RawMessage
		total, err := fetchPagedList(context.Background(), c, "/firewall/filter/search_rule", 2, &got)
		if err != nil {
			t.Fatalf("fetchPagedList: %v", err)
		}
		if total != 3 || len(got) != 3 {
			t.Fatalf("total=%d rows=%d, want 3/3", total, len(got))
		}
		if len(pages) != 2 || pages[0] != "1" || pages[1] != "2" {
			t.Errorf("pages requested = %v, want [1 2]", pages)
		}
		var last struct {
			N int `json:"n"`
		}
		if err := json.Unmarshal(got[2], &last); err != nil || last.N != 3 {
			t.Errorf("last row = %s, want n=3 (err %v)", got[2], err)
		}
	})

	t.Run("page size is passed as rowCount", func(t *testing.T) {
		var gotQuery string
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotQuery = r.URL.RawQuery
			testutil.WriteBody(w, `{"total":0,"rowCount":200,"current":1,"rows":[]}`)
		}))
		var got []json.RawMessage
		if _, err := fetchPagedList(context.Background(), c, "/firewall/filter/search_rule", 200, &got); err != nil {
			t.Fatalf("fetchPagedList: %v", err)
		}
		if !strings.Contains(gotQuery, "current=1") || !strings.Contains(gotQuery, "rowCount=200") {
			t.Errorf("query = %q, want current=1&rowCount=200", gotQuery)
		}
	})

	t.Run("empty result is not an error", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			testutil.WriteBody(w, `{"total":0,"rowCount":200,"current":1,"rows":[]}`)
		}))
		var got []json.RawMessage
		total, err := fetchPagedList(context.Background(), c, "/firewall/alias/search_item", 200, &got)
		if err != nil {
			t.Fatalf("fetchPagedList: %v", err)
		}
		if total != 0 || len(got) != 0 {
			t.Errorf("total=%d rows=%d, want 0/0", total, len(got))
		}
	})

	t.Run("controller without total still terminates", func(t *testing.T) {
		var calls int32
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			n := atomic.AddInt32(&calls, 1)
			if n == 1 {
				testutil.WriteBody(w, `{"rows":[{"n":1}]}`)
				return
			}
			// A second page is only requested when the first page was full;
			// with no total and 1 row the walk must stop after page 1.
			t.Errorf("walk did not terminate: page %d requested", n)
			w.WriteHeader(http.StatusBadRequest)
		}))
		var got []json.RawMessage
		_, err := fetchPagedList(context.Background(), c, "/firewall/filter/search_rule", 200, &got)
		if err != nil {
			t.Fatalf("fetchPagedList: %v", err)
		}
		if len(got) != 1 {
			t.Errorf("rows = %d, want 1", len(got))
		}
	})

	t.Run("bad json", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			testutil.WriteBody(w, `not json`)
		}))
		var got []json.RawMessage
		_, err := fetchPagedList(context.Background(), c, "/firewall/filter/search_rule", 200, &got)
		if err == nil || !strings.Contains(err.Error(), "decoding paged list response") {
			t.Errorf("error = %v, want decoding paged list response", err)
		}
	})

	t.Run("full pages stop once total is reached", func(t *testing.T) {
		var calls int32
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			n := atomic.AddInt32(&calls, 1)
			testutil.WriteBody(w, fmt.Sprintf(`{"total":4,"rowCount":2,"current":%d,"rows":[{"n":1},{"n":2}]}`, n))
		}))
		var got []json.RawMessage
		total, err := fetchPagedList(context.Background(), c, "/firewall/filter/search_rule", 2, &got)
		if err != nil {
			t.Fatalf("fetchPagedList: %v", err)
		}
		// Page 1 is full (2 of 2) with total=4: page 2 fetches the last two
		// rows, and the walk stops on total — a third request would be a bug.
		if total != 4 || len(got) != 4 {
			t.Fatalf("total=%d rows=%d, want 4/4", total, len(got))
		}
		if gotCalls := atomic.LoadInt32(&calls); gotCalls != 2 {
			t.Errorf("requests = %d, want 2", gotCalls)
		}
	})

	t.Run("short page against rowCount stops the walk", func(t *testing.T) {
		var calls int32
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&calls, 1)
			// 2 rows with a declared rowCount of 3: shorter than the page
			// size? no — exactly full — but shorter than the declared row
			// count, which terminates the walk.
			testutil.WriteBody(w, `{"total":0,"rowCount":3,"current":1,"rows":[{"n":1},{"n":2}]}`)
		}))
		var got []json.RawMessage
		if _, err := fetchPagedList(context.Background(), c, "/firewall/filter/search_rule", 2, &got); err != nil {
			t.Fatalf("fetchPagedList: %v", err)
		}
		if len(got) != 2 {
			t.Errorf("rows = %d, want 2", len(got))
		}
		if gotCalls := atomic.LoadInt32(&calls); gotCalls != 1 {
			t.Errorf("requests = %d, want 1 (walk must stop on short rowCount)", gotCalls)
		}
	})

	t.Run("non-array rows is a decode error", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			testutil.WriteBody(w, `{"total":1,"rowCount":1,"current":1,"rows":{"not":"array"}}`)
		}))
		var got []json.RawMessage
		_, err := fetchPagedList(context.Background(), c, "/firewall/filter/search_rule", 200, &got)
		if err == nil || !strings.Contains(err.Error(), "decoding paged list response") {
			t.Errorf("error = %v, want decoding paged list response", err)
		}
	})

	t.Run("page cap guards against non-terminating controllers", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Always a full page: the walk must hit the page cap, not loop.
			testutil.WriteBody(w, `{"total":0,"rowCount":2,"current":99,"rows":[{"n":1},{"n":2}]}`)
		}))
		var got []json.RawMessage
		_, err := fetchPagedList(context.Background(), c, "/firewall/filter/search_rule", 2, &got)
		if err == nil || !strings.Contains(err.Error(), "did not terminate after 100 pages") {
			t.Errorf("error = %v, want the page-cap error", err)
		}
	})

	t.Run("do error surfaces from getJSON", func(t *testing.T) {
		// A 404 is a stable error (no retries), so the fetch fails fast.
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			testutil.WriteBody(w, `{"message":"missing"}`)
		}))
		var got []json.RawMessage
		_, err := fetchPagedList(context.Background(), c, "/firewall/missing", 200, &got)
		if err == nil || !strings.Contains(err.Error(), "resource not found") {
			t.Errorf("error = %v, want resource-not-found", err)
		}
	})
}

// A host that fails URL parsing (e.g. contains a space) makes
// http.NewRequestWithContext fail before any network I/O: do() must wrap the
// parse error without retrying.
func TestDoRequestBuildFailure(t *testing.T) {
	c := NewClient("bad host", "key", "secret", true, "")
	_, err := c.do(context.Background(), http.MethodGet, "/x", nil)
	if err == nil || !strings.Contains(err.Error(), "building request for /x") {
		t.Fatalf("err = %v, want building-request error", err)
	}
}

func TestDrainBodyNil(t *testing.T) {
	// Must not panic on a nil body.
	drainBody(nil)
}

// --debug: raw API responses (method, path, status, body) are printed to
// stderr for both GET and POST paths, and no credential value ever appears
// in the printed payload.
func TestDebugDumpPrintsRawResponse(t *testing.T) {
	t.Run("GET prints the raw body and leaves it decodable", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			testutil.WriteBody(w, `{"markers":["wire-shape-abc"]}`)
		}))
		c.Debug = true
		out := captureStderr(t, func() {
			resp, err := c.do(context.Background(), http.MethodGet, "/interfaces/overview/interfaces_info", nil)
			if err != nil {
				t.Fatalf("do: %v", err)
			}
			defer resp.Body.Close()
			var got struct{ Markers []string }
			if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
				t.Fatalf("body no longer decodable after debug dump: %v", err)
			}
			if len(got.Markers) != 1 || got.Markers[0] != "wire-shape-abc" {
				t.Errorf("decoded = %+v, want the body restored for the caller", got)
			}
		})
		for _, want := range []string{
			"[opnsense debug] GET https://",
			"/api/interfaces/overview/interfaces_info",
			"-> 200",
			`"markers":["wire-shape-abc"]`,
		} {
			if !strings.Contains(out, want) {
				t.Errorf("stderr missing %q: %s", want, out)
			}
		}
	})

	t.Run("POST prints method and body", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			testutil.WriteBody(w, `{"ok":true}`)
		}))
		c.Debug = true
		out := captureStderr(t, func() {
			resp, err := c.do(context.Background(), http.MethodPost, "/firewall/filter/add_rule", []byte(`{"label":"x"}`))
			if err != nil {
				t.Fatalf("do POST: %v", err)
			}
			resp.Body.Close()
		})
		for _, want := range []string{
			"[opnsense debug] POST https://",
			"/api/firewall/filter/add_rule",
			`{"ok":true}`,
		} {
			if !strings.Contains(out, want) {
				t.Errorf("stderr missing %q: %s", want, out)
			}
		}
	})

	t.Run("credentials never appear in the dump", func(t *testing.T) {
		var sawAuth bool
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// The client's credentials travel in the basic-auth header, not
			// in the response body — so the dump (method, path, status,
			// body) cannot carry them. The server confirms the request was
			// in fact authenticated, so the absence below is meaningful.
			if k, s, ok := r.BasicAuth(); ok && k == "key" && s == "secret" {
				sawAuth = true
			}
			testutil.WriteBody(w, `{"plain":"body"}`)
		}))
		c.Debug = true
		out := captureStderr(t, func() {
			resp, err := c.do(context.Background(), http.MethodGet, "/x", nil)
			if err != nil {
				t.Fatalf("do: %v", err)
			}
			resp.Body.Close()
		})
		if !sawAuth {
			t.Fatal("server did not see the basic-auth credentials")
		}
		for _, secret := range []string{"key", "secret", "Basic"} {
			if strings.Contains(out, secret) {
				t.Errorf("stderr leaked %q: %s", secret, out)
			}
		}
	})

	t.Run("unreadable body reports the read error", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(errorReader{err: errors.New("boom")}),
		}
		c := &Client{host: "ctl.example:8443", Debug: true}
		out := captureStderr(t, func() {
			c.debugDump(resp, http.MethodGet, "/x")
		})
		if !strings.Contains(out, "-> 200") || !strings.Contains(out, "boom") {
			t.Errorf("stderr = %q, want the status and the read error", out)
		}
	})
}

// errorReader is an io.Reader whose Read always fails.
type errorReader struct{ err error }

func (e errorReader) Read([]byte) (int, error) { return 0, e.err }
