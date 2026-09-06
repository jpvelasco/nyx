package omada

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jpvelasco/nyx/internal/testutil"
)

const testInfoResponse = `{"errorCode":0,"msg":"","result":{"controllerVer":"6.4.5.1","apiVer":"2.0","omadacId":"abc123","configured":true,"omadacCategory":"advanced"}}`

// newTestClient spins up a TLS test server with a default /api/info handler
// and returns a ready-to-use Client pointing at it.
func newTestClient(t *testing.T, h http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/info" {
			testutil.WriteBody(w, testInfoResponse)
			return
		}
		h(w, r)
	}))
	t.Cleanup(ts.Close)

	c, err := NewClient(context.Background(), ts.URL, true, "")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	// Keep retries cheap so retry-path tests don't sleep.
	c.retryBase = time.Millisecond
	return c, ts
}

func writeEnvelope(w io.Writer, errorCode int, msg, result string) {
	testutil.WriteBody(w, `{"errorCode":`+strconv.Itoa(errorCode)+`,"msg":"`+msg+`","result":`+result+`}`)
}

func TestNewClientInfoErrors(t *testing.T) {
	cases := []struct {
		name      string
		infoBody  string
		wantError string
	}{
		{"bad json", `not json`, "decoding info response"},
		{"error code", `{"errorCode":57,"msg":"boom","result":null}`, "controller returned error 57"},
		{"malformed result", `{"errorCode":0,"msg":"","result":"not-an-object"}`, "decoding controller info"},
		{"old controller", `{"errorCode":0,"msg":"","result":{"controllerVer":"5.9.0","omadacId":"x"}}`, "below minimum supported version"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				testutil.WriteBody(w, tc.infoBody)
			}))
			defer ts.Close()
			_, err := NewClient(context.Background(), ts.URL, true, "")
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantError) {
				t.Errorf("error = %q, want contains %q", err, tc.wantError)
			}
		})
	}
}

func TestNewClientFetchFailure(t *testing.T) {
	_, err := NewClient(context.Background(), "https://127.0.0.1:1", true, "")
	if err == nil {
		t.Fatal("expected connection error")
	}
}

func TestNewClientNormalisesHost(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testutil.WriteBody(w, testInfoResponse)
	}))
	defer ts.Close()
	host := strings.TrimPrefix(ts.URL, "https://")

	// A host given with a plain-http scheme must still be normalised.
	c, err := NewClient(context.Background(), "http://"+host+"/", true, "")
	if err != nil {
		t.Fatalf("NewClient with http:// scheme: %v", err)
	}
	if c.host != host {
		t.Errorf("host = %q, want %q (scheme and slash stripped)", c.host, host)
	}
	if c.omadaCID != "abc123" {
		t.Errorf("omadaCID = %q, want abc123", c.omadaCID)
	}
	if c.info == nil || c.info.ControllerVer != "6.4.5.1" {
		t.Errorf("info = %+v, want version 6.4.5.1", c.info)
	}
	if c.info == nil || c.info.Category != "advanced" {
		t.Errorf("info = %+v, want category advanced", c.info)
	}
}

// BDD S1.1 — token mint: POST /openapi/authorize/token?grant_type=client_credentials
// with the exact client-credentials body, result.accessToken stored, and
// every subsequent request authenticated with Authorization: AccessToken=.
func TestLoginTokenMint(t *testing.T) {
	var (
		mu       sync.Mutex
		gotQuery string
		gotCT    string
		gotBody  map[string]string
	)
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/openapi/authorize/token":
			if r.Method != http.MethodPost {
				t.Errorf("mint method = %s, want POST", r.Method)
			}
			gotQuery = r.URL.RawQuery
			gotCT = r.Header.Get("Content-Type")
			_ = json.NewDecoder(r.Body).Decode(&gotBody)
			writeEnvelope(w, 0, "", `{"accessToken":"AT-123"}`)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))

	if err := c.Login(context.Background(), "cid-1", "csecret"); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if c.token != "AT-123" {
		t.Errorf("token = %q, want AT-123 (result.accessToken)", c.token)
	}
	if gotQuery != "grant_type=client_credentials" {
		t.Errorf("mint query = %q, want grant_type=client_credentials", gotQuery)
	}
	if gotCT != "application/json" {
		t.Errorf("mint content-type = %q, want application/json", gotCT)
	}
	wantBody := map[string]string{"omadacId": "abc123", "client_id": "cid-1", "client_secret": "csecret"}
	if len(gotBody) != len(wantBody) {
		t.Fatalf("mint body = %v, want exactly %v", gotBody, wantBody)
	}
	for k, v := range wantBody {
		if gotBody[k] != v {
			t.Errorf("mint body[%s] = %q, want %q", k, gotBody[k], v)
		}
	}
	// BDD S1.4 — no cookie jar on the client.
	if c.httpClient.Jar != nil {
		t.Error("client uses a cookie jar, want none (Open API is stateless)")
	}
}

// BDD S1.4 — Logout clears the token and credentials locally and makes no
// HTTP request (there is no logout endpoint).
func TestLogoutClearsLocallyOnly(t *testing.T) {
	var (
		mu        sync.Mutex
		mintCalls int
	)
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			mu.Lock()
			mintCalls++
			mu.Unlock()
			writeEnvelope(w, 0, "", `{"accessToken":"AT-1"}`)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	if err := c.Login(context.Background(), "cid-1", "csecret"); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if err := c.Logout(context.Background()); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if c.token != "" {
		t.Errorf("token after logout = %q, want empty", c.token)
	}
	if c.clientID != "" || c.clientSecret != "" {
		t.Error("credentials not cleared after logout")
	}
	mu.Lock()
	defer mu.Unlock()
	if mintCalls != 1 {
		t.Errorf("mint calls = %d, want 1 (logout must not touch the network)", mintCalls)
	}
}

func TestLogoutWithoutTokenIsNoop(t *testing.T) {
	var called bool
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	if err := c.Logout(context.Background()); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if called {
		t.Error("request sent despite empty token")
	}
}

// BDD S1.2 — invalid client credentials are a permanent failure: the mint
// gets errorCode -44106, the error names the invalid credentials, and no
// retry or re-mint loop runs.
func TestLoginInvalidClientCredentials(t *testing.T) {
	var calls int
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		writeEnvelope(w, -44106, "invalid client", "null")
	}))
	err := c.Login(context.Background(), "bad", "worse")
	if err == nil || !strings.Contains(err.Error(), "invalid client credentials") {
		t.Fatalf("Login error = %v, want invalid client credentials", err)
	}
	if calls != 1 {
		t.Errorf("mint calls = %d, want 1 (bad credentials must not retry)", calls)
	}
}

func TestGetErrorCodes(t *testing.T) {
	cases := []struct {
		name      string
		errorCode int
		wantError string
	}{
		{"token expired", -44112, "access token expired"},
		{"not logged in", -1000, "session expired"},
		{"bad credentials", -44106, "invalid client credentials"},
		{"forbidden", -1005, "operation forbidden"},
		{"unsupported path", -1600, "unsupported request path"},
		{"other", -7, "controller error -7"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeEnvelope(w, tc.errorCode, "boom", "null")
			}))
			err := c.get(context.Background(), "sites?page=1&pageSize=100", nil)
			if err == nil || !strings.Contains(err.Error(), tc.wantError) {
				t.Errorf("get error = %v, want contains %q", err, tc.wantError)
			}
		})
	}
}

// BDD S3.2 — authenticated requests target /openapi/v1/{omadacId}/..., the
// official Omada Open API path order. A controller answers the inverted
// /{omadacId}/openapi/v1/... order with 404, so pin the exact path here.
func TestGetSitesBasePathOrder(t *testing.T) {
	var got string
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Path
		if got != "/openapi/v1/abc123/sites" {
			testutil.WriteBody(w, `{"error":{"code":404,"message":"Not Found"}}`)
			return
		}
		writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"siteId":"s1","name":"HQ"}]}`)
	}))
	if _, err := c.GetSites(context.Background()); err != nil {
		t.Fatalf("GetSites: %v (request hit %q)", err, got)
	}
	if got != "/openapi/v1/abc123/sites" {
		t.Errorf("path = %q, want /openapi/v1/abc123/sites", got)
	}
}

func TestGetSitesResponseShapes(t *testing.T) {
	t.Run("paged", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"siteId":"s1","name":"HQ"}]}`)
		}))
		sites, err := c.GetSites(context.Background())
		if err != nil {
			t.Fatalf("GetSites: %v", err)
		}
		if len(sites) != 1 || sites[0].Name != "HQ" {
			t.Errorf("sites = %+v, want one HQ site", sites)
		}
	})

	t.Run("direct array", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeEnvelope(w, 0, "", `[{"siteId":"s1","name":"HQ"}]`)
		}))
		sites, err := c.GetSites(context.Background())
		if err != nil {
			t.Fatalf("GetSites: %v", err)
		}
		if len(sites) != 1 || sites[0].Name != "HQ" {
			t.Errorf("sites = %+v, want one HQ site", sites)
		}
	})

	t.Run("unparseable", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeEnvelope(w, 0, "", `"not-site-shaped"`)
		}))
		_, err := c.GetSites(context.Background())
		if err == nil || !strings.Contains(err.Error(), "decoding paged list response") {
			t.Errorf("GetSites error = %v, want decode failure", err)
		}
	})
}

// BDD S1.1 — the access token is sent as Authorization: AccessToken=<token>,
// and only when a token is present.
func TestDoRequestAuthHeader(t *testing.T) {
	var first, second string
	call := 0
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call++
		if call == 1 {
			first = r.Header.Get("Authorization")
		} else {
			second = r.Header.Get("Authorization")
		}
		writeEnvelope(w, 0, "", `{"data":[]}`)
	}))

	c.token = "abc"
	if err := c.get(context.Background(), "whatever", nil); err != nil {
		t.Fatalf("get: %v", err)
	}
	c.token = ""
	if err := c.get(context.Background(), "whatever", nil); err != nil {
		t.Fatalf("get: %v", err)
	}
	if first != "AccessToken=abc" {
		t.Errorf("Authorization with token = %q, want AccessToken=abc", first)
	}
	if second != "" {
		t.Errorf("Authorization without token = %q, want empty", second)
	}
}

func TestDoRequestCancelledContext(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, 0, "", `{}`)
	}))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := c.get(ctx, "sites?page=1&pageSize=100", nil)
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
}

func TestDoRequestUnauthorized(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	err := c.get(context.Background(), "sites?page=1&pageSize=100", nil)
	if err == nil || !strings.Contains(err.Error(), "not authenticated") {
		t.Errorf("error = %v, want not-authenticated message", err)
	}
}

func TestDoRequestBadJSON(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testutil.WriteBody(w, `{not json`)
	}))
	err := c.get(context.Background(), "sites?page=1&pageSize=100", nil)
	if err == nil || !strings.Contains(err.Error(), "decoding response") {
		t.Errorf("error = %v, want decoding response error", err)
	}
}

func TestDoRequestDebug(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, 0, "", `{"accessToken":"x"}`)
	}))
	c.Debug = true
	if err := c.get(context.Background(), "sites?page=1&pageSize=100", nil); err != nil {
		t.Fatalf("get with debug: %v", err)
	}
}

func TestDoRequestResultUnmarshal(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, 0, "", `"not-shape"`)
	}))
	var dest struct{ X int }
	err := c.get(context.Background(), "sites?page=1&pageSize=100", &dest)
	if err == nil || !strings.Contains(err.Error(), "decoding result") {
		t.Errorf("error = %v, want decoding result error", err)
	}
}

func TestDoRequestSkipNilBody(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength != 0 {
			t.Errorf("content length = %d, want 0 for nil body", r.ContentLength)
		}
		writeEnvelope(w, 0, "", "null")
	}))
	if err := c.post(context.Background(), "sites/page1", nil, nil); err != nil {
		t.Fatalf("post nil body: %v", err)
	}
}

func TestPostTransportError(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, 0, "", "{}")
	}))
	c.httpClient = &http.Client{Transport: failingRoundTripper{}}
	var dest struct{}
	err := c.post(context.Background(), "x", map[string]string{"a": "b"}, &dest)
	if err == nil {
		t.Fatal("expected transport error")
	}
}

type failingRoundTripper struct{}

func (failingRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("connection refused")
}
