package omadaprovider

import (
	"context"
	"net/http"
	"net/http/httptest"
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
