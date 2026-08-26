package omadaprovider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	providers "github.com/jpvelasco/nyx/internal/providers"
)

// natCheckHandlers serves the NAT-observation endpoints with a canned device
// set. gateway controls whether a managed gateway device is present.
func natCheckHandlers(gateway bool) http.HandlerFunc {
	devices := `[{"id":"d2","name":"SW-2428P","model":"SW-2428P","type":"switch","mac":"aa:bb:cc:dd:ee:01","ip":"10.0.0.253"}]`
	if gateway {
		devices = `[
			{"id":"d1","name":"GW-CORE","model":"GW-CORE","type":"gateway","mac":"aa:bb:cc:dd:ee:00","ip":"10.0.0.254"},
			{"id":"d2","name":"SW-2428P","model":"SW-2428P","type":"switch","mac":"aa:bb:cc:dd:ee:01","ip":"10.0.0.253"}]`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			writeEnvelope(w, 0, "", `{"accessToken":"t1"}`)
		case "/openapi/v1/abc123/sites":
			writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		case "/openapi/v1/abc123/sites/s1/networks/devices":
			writeEnvelope(w, 0, "", devices)
		case "/openapi/v1/abc123/sites/s1/nat/port-forwardings":
			writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"pf1","name":"web","status":true,"externalPort":"443","forwardIp":"10.0.40.10","forwardPort":"443","protocol":1}]}`)
		case "/openapi/v1/abc123/sites/s1/nat/one-to-one-nat":
			writeEnvelope(w, 0, "", `{"totalRows":0,"data":[]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func natCheckOpts(ts *httptest.Server) providers.ImportOptions {
	return providers.ImportOptions{Host: ts.URL, ClientID: "admin", ClientSecret: "pw", Site: "HQ", SkipTLSVerify: true}
}

func TestProviderNatCheck(t *testing.T) {
	p := &OmadaProvider{}

	t.Run("present with gateway", func(t *testing.T) {
		ts := omadaServer(t, natCheckHandlers(true))
		res, err := p.NatCheck(context.Background(), providers.NatCheckRequest{ExpectMode: "present"}, natCheckOpts(ts))
		if err != nil {
			t.Fatalf("NatCheck: %v", err)
		}
		if res.Status != "pass" || res.CheckType != "nat_check" {
			t.Errorf("status/check = %s/%s, want pass/nat_check (summary %q)", res.Status, res.CheckType, res.Summary)
		}
		if res.Observed["managed_gateway"] != true || res.Observed["port_forward_rules"] != 1 {
			t.Errorf("observed = %v", res.Observed)
		}
	})

	t.Run("present without gateway", func(t *testing.T) {
		ts := omadaServer(t, natCheckHandlers(false))
		res, err := p.NatCheck(context.Background(), providers.NatCheckRequest{ExpectMode: "present"}, natCheckOpts(ts))
		if err != nil {
			t.Fatalf("NatCheck: %v", err)
		}
		if res.Status != "fail" || len(res.Violations) == 0 {
			t.Errorf("status = %s violations = %v; want fail with violations", res.Status, res.Violations)
		}
	})

	t.Run("mode expect without gateway is warn", func(t *testing.T) {
		ts := omadaServer(t, natCheckHandlers(false))
		res, err := p.NatCheck(context.Background(), providers.NatCheckRequest{ExpectMode: "automatic"}, natCheckOpts(ts))
		if err != nil {
			t.Fatalf("NatCheck: %v", err)
		}
		if res.Status != "warn" {
			t.Errorf("status = %s, want warn (summary %q)", res.Status, res.Summary)
		}
	})

	t.Run("mode expect with gateway is warn", func(t *testing.T) {
		ts := omadaServer(t, natCheckHandlers(true))
		res, err := p.NatCheck(context.Background(), providers.NatCheckRequest{ExpectMode: "automatic"}, natCheckOpts(ts))
		if err != nil {
			t.Fatalf("NatCheck: %v", err)
		}
		if res.Status != "warn" {
			t.Errorf("status = %s, want warn (summary %q)", res.Status, res.Summary)
		}
	})
}

// A read failure must yield a StatusError result that names the broken read,
// not a bare transport error — the agent needs the check-shaped contract.
func TestProviderNatCheck_ReadFailures(t *testing.T) {
	p := &OmadaProvider{}

	t.Run("connect failure", func(t *testing.T) {
		res, err := p.NatCheck(context.Background(), providers.NatCheckRequest{ExpectMode: "present"},
			providers.ImportOptions{Host: "https://127.0.0.1:1", ClientID: "admin", ClientSecret: "pw", SkipTLSVerify: true})
		if err != nil {
			t.Fatalf("NatCheck returned error: %v", err)
		}
		if res.Status != "error" || !strings.Contains(res.Summary, "failed to connect") {
			t.Errorf("status/summary = %s/%q", res.Status, res.Summary)
		}
	})

	t.Run("token mint failure", func(t *testing.T) {
		ts := omadaServer(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/openapi/authorize/token" {
				writeEnvelope(w, -44106, "invalid credentials", `null`)
				return
			}
			w.WriteHeader(http.StatusNotFound)
		})
		res, err := p.NatCheck(context.Background(), providers.NatCheckRequest{ExpectMode: "present"}, natCheckOpts(ts))
		if err != nil {
			t.Fatalf("NatCheck: %v", err)
		}
		if res.Status != "error" || !strings.Contains(res.Summary, "token mint failed") {
			t.Errorf("status/summary = %s/%q", res.Status, res.Summary)
		}
	})

	t.Run("sites failure", func(t *testing.T) {
		ts := omadaServer(t, func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/openapi/authorize/token":
				writeEnvelope(w, 0, "", `{"accessToken":"t1"}`)
			case "/openapi/v1/abc123/sites":
				writeEnvelope(w, -1010, "no sites", `null`)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		})
		res, err := p.NatCheck(context.Background(), providers.NatCheckRequest{ExpectMode: "present"}, natCheckOpts(ts))
		if err != nil {
			t.Fatalf("NatCheck: %v", err)
		}
		if res.Status != "error" || !strings.Contains(res.Summary, "failed to fetch sites") {
			t.Errorf("status/summary = %s/%q", res.Status, res.Summary)
		}
	})

	t.Run("site selection failure", func(t *testing.T) {
		ts := omadaServer(t, natCheckHandlers(true))
		opts := natCheckOpts(ts)
		opts.Site = "missing" // no such site → SelectSite error
		res, err := p.NatCheck(context.Background(), providers.NatCheckRequest{ExpectMode: "present"}, opts)
		if err != nil {
			t.Fatalf("NatCheck: %v", err)
		}
		if res.Status != "error" || !strings.Contains(res.Summary, "HQ") {
			t.Errorf("status/summary = %s/%q, want error naming the available site", res.Status, res.Summary)
		}
	})

	for _, tc := range []struct {
		failPath, want string
	}{
		{"/openapi/v1/abc123/sites/s1/networks/devices", "fetching devices"},
		{"/openapi/v1/abc123/sites/s1/nat/port-forwardings", "fetching port-forwarding rules"},
		{"/openapi/v1/abc123/sites/s1/nat/one-to-one-nat", "fetching one-to-one NAT rules"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			ts := omadaServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == tc.failPath {
					writeEnvelope(w, -1010, "boom", `null`)
					return
				}
				natCheckHandlers(true)(w, r)
			})
			res, err := p.NatCheck(context.Background(), providers.NatCheckRequest{ExpectMode: "present"}, natCheckOpts(ts))
			if err != nil {
				t.Fatalf("NatCheck: %v", err)
			}
			if res.Status != "error" || !strings.Contains(res.Summary, tc.want) {
				t.Errorf("status/summary = %s/%q, want %q", res.Status, res.Summary, tc.want)
			}
		})
	}
}
