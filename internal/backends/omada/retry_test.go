package omada

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
		{"session expired", &apiError{ErrorCode: -1000}, retryReauth},
		{"session expired alt", &apiError{ErrorCode: -44112}, retryReauth},
		{"http 401", &apiError{StatusCode: http.StatusUnauthorized}, retryReauth},
		{"http 500", &apiError{StatusCode: http.StatusInternalServerError}, retryBackoff},
		{"http 503", &apiError{StatusCode: http.StatusServiceUnavailable}, retryBackoff},
		{"bad credentials", &apiError{ErrorCode: -30109}, retryFail},
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
		case "/abc123/api/v2/login":
			writeEnvelope(w, 0, "", `{"token":"tok1"}`)
		case "/abc123/api/v2/sites":
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
	if err := c.Login(context.Background(), "admin", "secret"); err != nil {
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
// Session expiry → single re-login → retry.
// ---------------------------------------------------------------------------

func TestSessionExpiryReloginAndRetry(t *testing.T) {
	var (
		mu           sync.Mutex
		loginBodies  []map[string]string
		getCSRF      []string
		expiredFirst bool
	)
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/abc123/api/v2/login":
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			loginBodies = append(loginBodies, body)
			tok := fmt.Sprintf("tok%d", len(loginBodies))
			mu.Unlock()
			writeEnvelope(w, 0, "", `{"token":"`+tok+`"}`)
		case "/abc123/api/v2/sites":
			mu.Lock()
			getCSRF = append(getCSRF, r.Header.Get("Csrf-Token"))
			expire := !expiredFirst
			expiredFirst = true
			mu.Unlock()
			if expire {
				writeEnvelope(w, -1000, "session expired", "null")
				return
			}
			writeEnvelope(w, 0, "", `{"data":[]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))

	if err := c.Login(context.Background(), "admin", "secret"); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if err := c.get(context.Background(), "sites", nil); err != nil {
		t.Fatalf("get with session refresh: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(loginBodies) != 2 {
		t.Fatalf("logins = %d, want 2 (initial + refresh)", len(loginBodies))
	}
	if loginBodies[1]["username"] != "admin" || loginBodies[1]["password"] != "secret" {
		t.Errorf("refresh login used credentials %v, want admin/secret", loginBodies[1])
	}
	if len(getCSRF) != 2 {
		t.Fatalf("gets = %d, want 2 (expired then retried)", len(getCSRF))
	}
	if getCSRF[0] != "tok1" {
		t.Errorf("first get csrf = %q, want tok1", getCSRF[0])
	}
	if getCSRF[1] != "tok2" {
		t.Errorf("retried get csrf = %q, want tok2 (refreshed token)", getCSRF[1])
	}
	if c.token != "tok2" {
		t.Errorf("client token = %q, want tok2", c.token)
	}
}

func TestSessionExpiryWithoutCredentials(t *testing.T) {
	var (
		mu         sync.Mutex
		loginCalls int
		getCalls   int
	)
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/abc123/api/v2/login":
			mu.Lock()
			loginCalls++
			mu.Unlock()
			writeEnvelope(w, 0, "", `{"token":"t"}`)
		default:
			mu.Lock()
			getCalls++
			mu.Unlock()
			writeEnvelope(w, -1000, "session expired", "null")
		}
	}))
	err := c.get(context.Background(), "sites", nil)
	if err == nil || !strings.Contains(err.Error(), "session expired") {
		t.Fatalf("get error = %v, want session expired", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if loginCalls != 0 {
		t.Errorf("logins = %d, want 0 (no stored credentials)", loginCalls)
	}
	if getCalls != 1 {
		t.Errorf("gets = %d, want 1 (no retry without credentials)", getCalls)
	}
}

func TestSessionExpiryReloginFails(t *testing.T) {
	var (
		mu         sync.Mutex
		loginCalls int
		getCalls   int
	)
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/abc123/api/v2/login":
			mu.Lock()
			loginCalls++
			expired := loginCalls > 1
			mu.Unlock()
			if expired {
				writeEnvelope(w, -30109, "invalid username or password", "null")
				return
			}
			writeEnvelope(w, 0, "", `{"token":"tok1"}`)
		default:
			mu.Lock()
			getCalls++
			mu.Unlock()
			writeEnvelope(w, -1000, "session expired", "null")
		}
	}))
	if err := c.Login(context.Background(), "admin", "secret"); err != nil {
		t.Fatalf("Login: %v", err)
	}
	err := c.get(context.Background(), "sites", nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "session expired") {
		t.Errorf("error = %v, want original session expired cause", err)
	}
	if !strings.Contains(err.Error(), "automatic re-login failed") {
		t.Errorf("error = %v, want re-login failure note", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if loginCalls != 2 {
		t.Errorf("logins = %d, want 2 (initial + failed refresh)", loginCalls)
	}
	if getCalls != 1 {
		t.Errorf("gets = %d, want 1", getCalls)
	}
}

func TestSessionExpiryReloginOnlyOnce(t *testing.T) {
	var (
		mu         sync.Mutex
		loginCalls int
		getCalls   int
	)
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/abc123/api/v2/login":
			mu.Lock()
			loginCalls++
			mu.Unlock()
			writeEnvelope(w, 0, "", `{"token":"tok"}`)
		default:
			mu.Lock()
			getCalls++
			mu.Unlock()
			writeEnvelope(w, -1000, "session expired", "null")
		}
	}))
	if err := c.Login(context.Background(), "admin", "secret"); err != nil {
		t.Fatalf("Login: %v", err)
	}
	err := c.get(context.Background(), "sites", nil)
	if err == nil {
		t.Fatal("expected error after re-login still expires")
	}
	mu.Lock()
	defer mu.Unlock()
	if loginCalls != 2 {
		t.Errorf("logins = %d, want 2 (initial + one refresh only)", loginCalls)
	}
	if getCalls != 2 {
		t.Errorf("gets = %d, want 2 (initial + one retry only)", getCalls)
	}
}

// ---------------------------------------------------------------------------
// Concurrency.
// ---------------------------------------------------------------------------

func TestConcurrentSessionRefreshSingleFlight(t *testing.T) {
	var state struct {
		sync.Mutex
		logins int
		gets   int
		expire bool
	}
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/abc123/api/v2/login":
			state.Lock()
			state.logins++
			tok := fmt.Sprintf("tok%d", state.logins)
			state.Unlock()
			writeEnvelope(w, 0, "", `{"token":"`+tok+`"}`)
		default:
			state.Lock()
			state.gets++
			csrf := r.Header.Get("Csrf-Token")
			expire := csrf != fmt.Sprintf("tok%d", state.logins) || !state.expire
			state.expire = true
			state.Unlock()
			if expire {
				writeEnvelope(w, -1000, "session expired", "null")
				return
			}
			writeEnvelope(w, 0, "", `{"data":[]}`)
		}
	}))
	if err := c.Login(context.Background(), "admin", "secret"); err != nil {
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
	if state.logins != 2 {
		t.Errorf("logins = %d, want 2 (initial + single-flight refresh)", state.logins)
	}
	wantGets := goroutines + 1
	if state.gets != wantGets {
		t.Errorf("gets = %d, want %d (one retried)", state.gets, wantGets)
	}
}

func TestConcurrentRequestsAndSetLogger(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/abc123/api/v2/login":
			writeEnvelope(w, 0, "", `{"token":"tok1"}`)
		default:
			writeEnvelope(w, 0, "", `{"data":[]}`)
		}
	}))
	if err := c.Login(context.Background(), "admin", "secret"); err != nil {
		t.Fatalf("Login: %v", err)
	}

	dir := t.TempDir()
	l, err := logger.New(filepath.Join(dir, "nyx.log"), 5*1024*1024, 3)
	if err != nil {
		t.Fatalf("logger.New: %v", err)
	}
	defer l.Close()

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
// Structured operation logging.
// ---------------------------------------------------------------------------

func TestOperationLogging(t *testing.T) {
	var (
		mu           sync.Mutex
		clientCalls  int
		expiredFirst bool
	)
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/abc123/api/v2/login":
			writeEnvelope(w, 0, "", `{"token":"tok1"}`)
		case "/abc123/api/v2/sites":
			mu.Lock()
			expire := !expiredFirst
			expiredFirst = true
			mu.Unlock()
			if expire {
				writeEnvelope(w, -1000, "session expired", "null")
				return
			}
			writeEnvelope(w, 0, "", `{"data":[]}`)
		case "/abc123/api/v2/clients":
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
	l, err := logger.New(path, 5*1024*1024, 3)
	if err != nil {
		t.Fatalf("logger.New: %v", err)
	}
	c.SetLogger(l)

	if err := c.Login(context.Background(), "admin", "secret"); err != nil {
		t.Fatalf("Login: %v", err)
	}
	// Transient failure → retry event.
	if err := c.get(context.Background(), "clients", nil); err != nil {
		t.Fatalf("get: %v", err)
	}
	// Session expiry → re-login event.
	if err := c.get(context.Background(), "sites", nil); err != nil {
		t.Fatalf("get: %v", err)
	}
	if err := c.Logout(context.Background()); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	l.Close()

	// Codacy false positive: path names this test's log inside t.TempDir().
	data, err := os.ReadFile(path) // nosemgrep: go_filesystem_rule-fileread
	if err != nil {
		t.Fatalf("reading log: %v", err)
	}
	logText := string(data)
	for _, want := range []string{`"event":"login"`, `"event":"retry"`, `"event":"session_expired"`, `"event":"re_login"`, `"event":"logout"`} {
		if !strings.Contains(logText, want) {
			t.Errorf("log missing %s; got:\n%s", want, logText)
		}
	}
	if strings.Contains(logText, "secret") {
		t.Error("log contains the password — credentials must never be logged")
	}
	if strings.Contains(logText, "127.0.0.1") {
		t.Error("log contains the controller address — IPs/hostnames must not be logged")
	}
}

func TestSetLoggerNilSafe(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/abc123/api/v2/login":
			writeEnvelope(w, 0, "", `{"token":"tok1"}`)
		default:
			writeEnvelope(w, 0, "", `{"data":[]}`)
		}
	}))
	c.SetLogger(nil)
	if err := c.Login(context.Background(), "admin", "secret"); err != nil {
		t.Fatalf("Login with nil logger: %v", err)
	}
	if err := c.get(context.Background(), "sites", nil); err != nil {
		t.Fatalf("get with nil logger: %v", err)
	}
}
