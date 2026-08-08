package omada

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

const testInfoResponse = `{"errorCode":0,"msg":"","result":{"controllerVer":"6.4.5.1","apiVer":"2.0","omadacId":"abc123","configured":true}}`

// newTestClient spins up a TLS test server with a default /api/info handler
// and returns a ready-to-use Client pointing at it.
func newTestClient(t *testing.T, h http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/info" {
			w.Write([]byte(testInfoResponse))
			return
		}
		h(w, r)
	}))
	t.Cleanup(ts.Close)

	c, err := NewClient(context.Background(), ts.URL, true, "")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c, ts
}

func writeEnvelope(w http.ResponseWriter, errorCode int, msg, result string) {
	w.Write([]byte(`{"errorCode":` + strconv.Itoa(errorCode) + `,"msg":"` + msg + `","result":` + result + `}`))
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
				w.Write([]byte(tc.infoBody))
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
		w.Write([]byte(testInfoResponse))
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
}

func TestLoginLogout(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/abc123/api/v2/login":
			if r.Method != http.MethodPost {
				t.Errorf("login method = %s, want POST", r.Method)
			}
			if ct := r.Header.Get("Content-Type"); ct != "application/json" {
				t.Errorf("login content-type = %q, want application/json", ct)
			}
			writeEnvelope(w, 0, "", `{"token":"tok123"}`)
		case "/abc123/api/v2/logout":
			if csrf := r.Header.Get("Csrf-Token"); csrf != "tok123" {
				t.Errorf("logout csrf = %q, want tok123", csrf)
			}
			writeEnvelope(w, 0, "", "null")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))

	if err := c.Login(context.Background(), "admin", "secret"); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if c.token != "tok123" {
		t.Errorf("token = %q, want tok123", c.token)
	}
	if err := c.Logout(context.Background()); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if c.token != "" {
		t.Errorf("token after logout = %q, want empty", c.token)
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
		t.Error("logout request sent despite empty token")
	}
}

func TestLoginError(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, -30109, "bad credentials", "null")
	}))
	err := c.Login(context.Background(), "admin", "nope")
	if err == nil || !strings.Contains(err.Error(), "invalid username or password") {
		t.Fatalf("Login error = %v, want invalid username or password", err)
	}
}

func TestGetErrorCodes(t *testing.T) {
	cases := []struct {
		name      string
		errorCode int
		wantError string
	}{
		{"session expired", -1000, "session expired"},
		{"session expired alt", -44112, "session expired"},
		{"bad password", -30109, "invalid username or password"},
		{"forbidden", -1005, "operation forbidden"},
		{"other", -7, "controller error -7"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeEnvelope(w, tc.errorCode, "boom", "null")
			}))
			err := c.get(context.Background(), "sites?currentPage=1&currentPageSize=100", nil)
			if err == nil || !strings.Contains(err.Error(), tc.wantError) {
				t.Errorf("get error = %v, want contains %q", err, tc.wantError)
			}
		})
	}
}

func TestGetSitesResponseShapes(t *testing.T) {
	t.Run("paged", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
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
			writeEnvelope(w, 0, "", `[{"id":"s1","name":"HQ"}]`)
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
		if err == nil || !strings.Contains(err.Error(), "could not parse sites response") {
			t.Errorf("GetSites error = %v, want parse failure", err)
		}
	})
}

func TestDoRequestAuthHeader(t *testing.T) {
	var first, second string
	call := 0
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call++
		if call == 1 {
			first = r.Header.Get("Csrf-Token")
		} else {
			second = r.Header.Get("Csrf-Token")
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
	if first != "abc" {
		t.Errorf("Csrf-Token with session = %q, want abc", first)
	}
	if second != "" {
		t.Errorf("Csrf-Token logged out = %q, want empty", second)
	}
}

func TestDoRequestCancelledContext(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, 0, "", `{}`)
	}))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := c.get(ctx, "sites?currentPage=1&currentPageSize=100", nil)
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
}

func TestDoRequestUnauthorized(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	err := c.get(context.Background(), "sites?currentPage=1&currentPageSize=100", nil)
	if err == nil || !strings.Contains(err.Error(), "not authenticated") {
		t.Errorf("error = %v, want not-authenticated message", err)
	}
}

func TestDoRequestBadJSON(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{not json`))
	}))
	err := c.get(context.Background(), "sites?currentPage=1&currentPageSize=100", nil)
	if err == nil || !strings.Contains(err.Error(), "decoding response") {
		t.Errorf("error = %v, want decoding response error", err)
	}
}

func TestDoRequestDebug(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, 0, "", `{"token":"x"}`)
	}))
	c.Debug = true
	if err := c.get(context.Background(), "sites?currentPage=1&currentPageSize=100", nil); err != nil {
		t.Fatalf("get with debug: %v", err)
	}
}

func TestDoRequestResultUnmarshal(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, 0, "", `"not-shape"`)
	}))
	var dest struct{ X int }
	err := c.get(context.Background(), "sites?currentPage=1&currentPageSize=100", &dest)
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
	if err := c.post(context.Background(), "logout", nil, nil); err != nil {
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
