package opnsense

import (
	"context"
	"encoding/json"
	"errors"
	"io"
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
		testutil.WriteBody(w, firmwareJSON)
	}))
	resp, err := c.do(context.Background(), http.MethodGet, "/core/firmware/running", nil)
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
	resp, err := c.do(context.Background(), http.MethodGet, "/core/firmware/running", nil)
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
	if err == nil || !strings.Contains(err.Error(), "unexpected status 403") {
		t.Errorf("error = %v, want unexpected status 403", err)
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
			resp, err := c.do(context.Background(), http.MethodGet, "/core/firmware/running", nil)
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
	l, err := logger.New(dir+"/nyx.log", 5*1024*1024, 3)
	if err != nil {
		t.Fatalf("logger.New: %v", err)
	}
	c.SetLogger(l)

	resp, err := c.do(context.Background(), http.MethodGet, "/firewall/d_nat/search_rule", nil)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	resp.Body.Close()
	l.Close()

	raw, err := os.ReadFile(dir + "/nyx.log")
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
	resp, err := c.do(context.Background(), http.MethodGet, "/core/firmware/running", nil)
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
		total, err := fetchPagedList(context.Background(), c, "/firewall/filter/searchRule", 2, &got)
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
		if _, err := fetchPagedList(context.Background(), c, "/firewall/filter/searchRule", 200, &got); err != nil {
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
		_, err := fetchPagedList(context.Background(), c, "/firewall/filter/searchRule", 200, &got)
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
		_, err := fetchPagedList(context.Background(), c, "/firewall/filter/searchRule", 200, &got)
		if err == nil || !strings.Contains(err.Error(), "decoding paged list response") {
			t.Errorf("error = %v, want decoding paged list response", err)
		}
	})
}
