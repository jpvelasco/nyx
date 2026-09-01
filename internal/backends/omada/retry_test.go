package omada

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jpvelasco/nyx/internal/logger"
)

// ---------------------------------------------------------------------------
// Retry classification — which errors retry, which do not.
// ---------------------------------------------------------------------------

func TestClassifyRetry(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want retryAction
	}{
		{"nil", nil, retryFail},
		{"token expired", &apiError{ErrorCode: -44112}, retryReauth},
		{"not logged in", &apiError{ErrorCode: -1000}, retryReauth},
		{"http 401", &apiError{StatusCode: http.StatusUnauthorized}, retryReauth},
		{"http 500", &apiError{StatusCode: http.StatusInternalServerError}, retryBackoff},
		{"http 503", &apiError{StatusCode: http.StatusServiceUnavailable}, retryBackoff},
		{"invalid client credentials", &apiError{ErrorCode: -44106}, retryFail},
		{"forbidden", &apiError{ErrorCode: -1005}, retryFail},
		{"controller error", &apiError{ErrorCode: -7}, retryFail},
		{"network error", &url.Error{Op: "dial", Err: errors.New("connection refused")}, retryBackoff},
		{"network error wrapping context", &url.Error{Op: "Get", Err: context.Canceled}, retryFail},
		{"cancelled context", context.Canceled, retryFail},
		{"deadline exceeded", context.DeadlineExceeded, retryFail},
		{"unknown", errors.New("boom"), retryFail},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyRetry(tc.err); got != tc.want {
				t.Errorf("classifyRetry(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestBackoffDelay(t *testing.T) {
	const (
		base = 500 * time.Millisecond
		max  = 5 * time.Second
	)
	cases := []struct {
		name    string
		attempt int
		base    time.Duration
		max     time.Duration
		want    time.Duration
	}{
		{"first attempt", 0, base, max, 500 * time.Millisecond},
		{"second attempt", 1, base, max, 1 * time.Second},
		{"third attempt", 2, base, max, 2 * time.Second},
		{"fourth attempt", 3, base, max, 4 * time.Second},
		{"capped", 4, base, max, 5 * time.Second},
		{"capped small max", 2, time.Millisecond, 3 * time.Millisecond, 3 * time.Millisecond},
		{"small base no cap", 0, time.Millisecond, 3 * time.Millisecond, time.Millisecond},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := backoffDelay(tc.attempt, tc.base, tc.max); got != tc.want {
				t.Errorf("backoffDelay(%d, %v, %v) = %v, want %v", tc.attempt, tc.base, tc.max, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Retry behavior over HTTP.
// ---------------------------------------------------------------------------

func TestRetryTransientThenSuccess(t *testing.T) {
	var calls int
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			writeEnvelope(w, 0, "", `{"accessToken":"tok1"}`)
		case "/openapi/v1/abc123/sites":
			calls++
			if calls < 3 {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			writeEnvelope(w, 0, "", `{"data":[]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	if err := c.Login(context.Background(), "cid-1", "csecret"); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if err := c.get(context.Background(), "sites", nil); err != nil {
		t.Fatalf("get after transient failures: %v", err)
	}
	if calls != 3 {
		t.Errorf("requests = %d, want 3 (two failures then success)", calls)
	}
}

func TestRetryExhausted(t *testing.T) {
	var calls int
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	c.maxRetries = 2
	c.retryBase = time.Millisecond
	err := c.get(context.Background(), "sites", nil)
	if err == nil {
		t.Fatal("expected error after retries exhausted")
	}
	if calls != 3 {
		t.Errorf("requests = %d, want 3 (1 initial + 2 retries)", calls)
	}
}

func TestNoRetryOnPermanentError(t *testing.T) {
	var calls int
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		writeEnvelope(w, -7, "boom", "null")
	}))
	err := c.get(context.Background(), "sites", nil)
	if err == nil {
		t.Fatal("expected controller error")
	}
	if calls != 1 {
		t.Errorf("requests = %d, want 1 (permanent errors must not retry)", calls)
	}
}

func TestNoRetryOnCancelledContext(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, 0, "", `{"data":[]}`)
	}))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := c.get(ctx, "sites", nil)
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want context.Canceled", err)
	}
}

// ---------------------------------------------------------------------------
// BDD S1.3 — expired token → single re-mint → retry.
// ---------------------------------------------------------------------------

func TestTokenExpiryRemintAndRetry(t *testing.T) {
	var (
		mu         sync.Mutex
		mintBodies []map[string]string
		getTokens  []string
		expired    bool
	)
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			mintBodies = append(mintBodies, body)
			tok := fmt.Sprintf("AT-%d", len(mintBodies))
			mu.Unlock()
			writeEnvelope(w, 0, "", `{"accessToken":"`+tok+`"}`)
		case "/openapi/v1/abc123/sites":
			mu.Lock()
			getTokens = append(getTokens, r.Header.Get("Authorization"))
			expire := !expired
			expired = true
			mu.Unlock()
			if expire {
				writeEnvelope(w, -44112, "access token expired", "null")
				return
			}
			writeEnvelope(w, 0, "", `{"data":[]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))

	if err := c.Login(context.Background(), "cid-1", "csecret"); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if err := c.get(context.Background(), "sites", nil); err != nil {
		t.Fatalf("get with token refresh: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(mintBodies) != 2 {
		t.Fatalf("mints = %d, want 2 (initial + refresh)", len(mintBodies))
	}
	// The re-mint reuses the stored client credentials (BDD S1.3).
	if mintBodies[1]["client_id"] != "cid-1" || mintBodies[1]["client_secret"] != "csecret" {
		t.Errorf("re-mint used credentials %v, want the stored client credentials", mintBodies[1])
	}
	if len(getTokens) != 2 {
		t.Fatalf("gets = %d, want 2 (expired then retried)", len(getTokens))
	}
	if getTokens[0] != "AccessToken=AT-1" {
		t.Errorf("first get auth = %q, want AccessToken=AT-1", getTokens[0])
	}
	if getTokens[1] != "AccessToken=AT-2" {
		t.Errorf("retried get auth = %q, want AccessToken=AT-2 (re-minted token)", getTokens[1])
	}
	if c.token != "AT-2" {
		t.Errorf("client token = %q, want AT-2", c.token)
	}
}

func TestTokenExpiryWithoutCredentials(t *testing.T) {
	var (
		mu        sync.Mutex
		mintCalls int
		getCalls  int
	)
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			mu.Lock()
			mintCalls++
			mu.Unlock()
			writeEnvelope(w, 0, "", `{"accessToken":"t"}`)
		default:
			mu.Lock()
			getCalls++
			mu.Unlock()
			writeEnvelope(w, -44112, "access token expired", "null")
		}
	}))
	err := c.get(context.Background(), "sites", nil)
	if err == nil || !strings.Contains(err.Error(), "access token expired") {
		t.Fatalf("get error = %v, want access token expired", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if mintCalls != 0 {
		t.Errorf("mints = %d, want 0 (no stored credentials)", mintCalls)
	}
	if getCalls != 1 {
		t.Errorf("gets = %d, want 1 (no retry without credentials)", getCalls)
	}
}

func TestTokenExpiryRemintFails(t *testing.T) {
	var (
		mu        sync.Mutex
		mintCalls int
		getCalls  int
	)
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			mu.Lock()
			mintCalls++
			expired := mintCalls > 1
			mu.Unlock()
			if expired {
				writeEnvelope(w, -44106, "invalid client credentials", "null")
				return
			}
			writeEnvelope(w, 0, "", `{"accessToken":"AT-1"}`)
		default:
			mu.Lock()
			getCalls++
			mu.Unlock()
			writeEnvelope(w, -44112, "access token expired", "null")
		}
	}))
	if err := c.Login(context.Background(), "cid-1", "csecret"); err != nil {
		t.Fatalf("Login: %v", err)
	}
	err := c.get(context.Background(), "sites", nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "access token expired") {
		t.Errorf("error = %v, want original expiry cause", err)
	}
	if !strings.Contains(err.Error(), "automatic re-mint failed") {
		t.Errorf("error = %v, want re-mint failure note", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if mintCalls != 2 {
		t.Errorf("mints = %d, want 2 (initial + failed refresh)", mintCalls)
	}
	if getCalls != 1 {
		t.Errorf("gets = %d, want 1", getCalls)
	}
}

func TestTokenExpiryRemintOnlyOnce(t *testing.T) {
	var (
		mu        sync.Mutex
		mintCalls int
		getCalls  int
	)
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			mu.Lock()
			mintCalls++
			mu.Unlock()
			writeEnvelope(w, 0, "", `{"accessToken":"tok"}`)
		default:
			mu.Lock()
			getCalls++
			mu.Unlock()
			writeEnvelope(w, -44112, "access token expired", "null")
		}
	}))
	if err := c.Login(context.Background(), "cid-1", "csecret"); err != nil {
		t.Fatalf("Login: %v", err)
	}
	err := c.get(context.Background(), "sites", nil)
	if err == nil {
		t.Fatal("expected error after re-mint still expires")
	}
	mu.Lock()
	defer mu.Unlock()
	if mintCalls != 2 {
		t.Errorf("mints = %d, want 2 (initial + one re-mint only)", mintCalls)
	}
	if getCalls != 2 {
		t.Errorf("gets = %d, want 2 (initial + one retry only)", getCalls)
	}
}

// ---------------------------------------------------------------------------
// Concurrency.
// ---------------------------------------------------------------------------

func TestConcurrentTokenRefreshSingleFlight(t *testing.T) {
	var state struct {
		sync.Mutex
		mints  int
		gets   int
		expire bool
	}
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			state.Lock()
			state.mints++
			tok := fmt.Sprintf("AT-%d", state.mints)
			state.Unlock()
			writeEnvelope(w, 0, "", `{"accessToken":"`+tok+`"}`)
		default:
			state.Lock()
			state.gets++
			auth := r.Header.Get("Authorization")
			expire := auth != "AccessToken="+fmt.Sprintf("AT-%d", state.mints) || !state.expire
			state.expire = true
			state.Unlock()
			if expire {
				writeEnvelope(w, -44112, "access token expired", "null")
				return
			}
			writeEnvelope(w, 0, "", `{"data":[]}`)
		}
	}))
	if err := c.Login(context.Background(), "cid-1", "csecret"); err != nil {
		t.Fatalf("Login: %v", err)
	}

	const goroutines = 8
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.get(context.Background(), "sites", nil); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent get: %v", err)
	}

	state.Lock()
	defer state.Unlock()
	if state.mints != 2 {
		t.Errorf("mints = %d, want 2 (initial + single-flight re-mint)", state.mints)
	}
	wantGets := goroutines + 1
	if state.gets != wantGets {
		t.Errorf("gets = %d, want %d (one retried)", state.gets, wantGets)
	}
}

func TestConcurrentRequestsAndSetLogger(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			writeEnvelope(w, 0, "", `{"accessToken":"AT-1"}`)
		default:
			writeEnvelope(w, 0, "", `{"data":[]}`)
		}
	}))
	if err := c.Login(context.Background(), "cid-1", "csecret"); err != nil {
		t.Fatalf("Login: %v", err)
	}

	dir := t.TempDir()
	l, err := logger.NewSlog(filepath.Join(dir, "nyx.log"), 5*1024*1024, 3, slog.LevelDebug)
	if err != nil {
		t.Fatalf("logger.NewSlog: %v", err)
	}
	defer logger.CloseSlog(l)

	stop := make(chan struct{})
	var setter sync.WaitGroup
	setter.Add(1)
	go func() {
		defer setter.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if i%2 == 0 {
				c.SetLogger(l)
			} else {
				c.SetLogger(nil)
			}
		}
	}()
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.get(context.Background(), "sites", nil); err != nil {
				t.Errorf("concurrent get: %v", err)
			}
		}()
	}
	wg.Wait()
	close(stop)
	setter.Wait()
}

// ---------------------------------------------------------------------------
// Structured operation logging (BDD S1.5 — secrets never leak).
// ---------------------------------------------------------------------------

func TestOperationLogging(t *testing.T) {
	var (
		mu           sync.Mutex
		clientCalls  int
		expiredFirst bool
	)
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			writeEnvelope(w, 0, "", `{"accessToken":"AT-1"}`)
		case "/openapi/v1/abc123/sites":
			mu.Lock()
			expire := !expiredFirst
			expiredFirst = true
			mu.Unlock()
			if expire {
				writeEnvelope(w, -44112, "access token expired", "null")
				return
			}
			writeEnvelope(w, 0, "", `{"data":[]}`)
		case "/openapi/v1/abc123/clients":
			mu.Lock()
			clientCalls++
			first := clientCalls == 1
			mu.Unlock()
			if first {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			writeEnvelope(w, 0, "", `{"data":[]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))

	dir := t.TempDir()
	path := filepath.Join(dir, "nyx.log")
	l, err := logger.NewSlog(path, 5*1024*1024, 3, slog.LevelDebug)
	if err != nil {
		t.Fatalf("logger.NewSlog: %v", err)
	}
	c.SetLogger(l)

	if err := c.Login(context.Background(), "cid-1", "csecret"); err != nil {
		t.Fatalf("Login: %v", err)
	}
	// Transient failure → retry event.
	if err := c.get(context.Background(), "clients", nil); err != nil {
		t.Fatalf("get: %v", err)
	}
	// Token expiry → re-mint event.
	if err := c.get(context.Background(), "sites", nil); err != nil {
		t.Fatalf("get: %v", err)
	}
	if err := c.Logout(context.Background()); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	logger.CloseSlog(l)

	// Codacy false positive: path names this test's log inside t.TempDir().
	data, err := os.ReadFile(path) // nosemgrep: go_filesystem_rule-fileread
	if err != nil {
		t.Fatalf("reading log: %v", err)
	}
	logText := string(data)
	for _, want := range []string{`"event":"token_mint"`, `"event":"retry"`, `"event":"token_expired"`, `"event":"token_re_mint"`, `"event":"logout"`} {
		if !strings.Contains(logText, want) {
			t.Errorf("log missing %s; got:\n%s", want, logText)
		}
	}
	if strings.Contains(logText, "csecret") || strings.Contains(logText, "cid-1") {
		t.Error("log contains client credentials — they must never be logged")
	}
	if strings.Contains(logText, "127.0.0.1") {
		t.Error("log contains the controller address — IPs/hostnames must not be logged")
	}
}

func TestSetLoggerNilSafe(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			writeEnvelope(w, 0, "", `{"accessToken":"AT-1"}`)
		default:
			writeEnvelope(w, 0, "", `{"data":[]}`)
		}
	}))
	c.SetLogger(nil)
	if err := c.Login(context.Background(), "cid-1", "csecret"); err != nil {
		t.Fatalf("Login with nil logger: %v", err)
	}
	if err := c.get(context.Background(), "sites", nil); err != nil {
		t.Fatalf("get with nil logger: %v", err)
	}
}

// logSafeError reduces errors to a static, host-free description so the log
// file never carries the controller hostname/IP.
func TestLogSafeErrorStripsHost(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{&apiError{StatusCode: 500, ErrorCode: -1, Msg: "controller error -1"}, "controller error -1"},
		{&apiError{StatusCode: 500, ErrorCode: -44112}, "controller error -44112"},
		{&url.Error{Op: "Get", URL: "https://controller-host:443/openapi/v1/x", Err: context.DeadlineExceeded}, "transport or protocol error"},
	}
	for _, c := range cases {
		got := logSafeError(c.err)
		if got != c.want {
			t.Errorf("logSafeError(%v) = %q, want %q", c.err, got, c.want)
		}
		if strings.Contains(got, "controller-host") || strings.Contains(got, "443") {
			t.Errorf("logSafeError(%v) leaked host/port: %q", c.err, got)
		}
	}
}
