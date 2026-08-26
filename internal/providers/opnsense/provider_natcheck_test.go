package opnsense

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	providers "github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/testutil"
)

// natModeServer serves the four NAT-read endpoints. mode is the value of
// general.snat_mode in /filter_base/get; an empty mode omits the key entirely
// (simulating version key drift).
func natModeServer(t *testing.T, mode string) *httptest.Server {
	t.Helper()
	base := `{"general":{`
	if mode != "" {
		base += `"snat_mode":"` + mode + `"`
	}
	base += `}}`
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/firewall/filter_base/get":
			testutil.WriteBody(w, base)
		case "/api/firewall/d_nat/search_rule":
			testutil.WriteBody(w, `{"total":0,"rows":[]}`)
		case "/api/firewall/one_to_one/search_rule":
			testutil.WriteBody(w, `{"total":0,"rows":[]}`)
		case "/api/firewall/source_nat/search_rule":
			testutil.WriteBody(w, `{"total":0,"rows":[]}`)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(ts.Close)
	return ts
}

func natOpts(ts *httptest.Server) providers.ImportOptions {
	return providers.ImportOptions{Host: ts.URL, ClientID: "k", ClientSecret: "s", SkipTLSVerify: true}
}

func TestProviderNatCheck(t *testing.T) {
	p := &Provider{}

	t.Run("disabled mode is bridge", func(t *testing.T) {
		ts := natModeServer(t, "disabled")
		res, err := p.NatCheck(context.Background(), providers.NatCheckRequest{ExpectMode: "bridge"}, natOpts(ts))
		if err != nil {
			t.Fatalf("NatCheck: %v", err)
		}
		if res.Status != "pass" {
			t.Errorf("status = %s, want pass (summary %q)", res.Status, res.Summary)
		}
		if res.Observed["outbound_nat_mode"] != "disabled" {
			t.Errorf("outbound_nat_mode = %v, want disabled", res.Observed["outbound_nat_mode"])
		}
	})

	t.Run("automatic mode is nat_router", func(t *testing.T) {
		ts := natModeServer(t, "automatic")
		res, err := p.NatCheck(context.Background(), providers.NatCheckRequest{ExpectMode: "nat_router"}, natOpts(ts))
		if err != nil {
			t.Fatalf("NatCheck: %v", err)
		}
		if res.Status != "pass" {
			t.Errorf("status = %s, want pass (summary %q)", res.Status, res.Summary)
		}
	})

	t.Run("automatic mode equality pass", func(t *testing.T) {
		ts := natModeServer(t, "automatic")
		res, err := p.NatCheck(context.Background(), providers.NatCheckRequest{ExpectMode: "automatic"}, natOpts(ts))
		if err != nil {
			t.Fatalf("NatCheck: %v", err)
		}
		if res.Status != "pass" {
			t.Errorf("status = %s, want pass (summary %q)", res.Status, res.Summary)
		}
	})

	t.Run("mode mismatch fails", func(t *testing.T) {
		ts := natModeServer(t, "automatic")
		res, err := p.NatCheck(context.Background(), providers.NatCheckRequest{ExpectMode: "disabled"}, natOpts(ts))
		if err != nil {
			t.Fatalf("NatCheck: %v", err)
		}
		if res.Status != "fail" || len(res.Violations) == 0 {
			t.Errorf("status = %s violations = %v; want fail", res.Status, res.Violations)
		}
	})

	t.Run("bridge expect on nat_router fails", func(t *testing.T) {
		ts := natModeServer(t, "automatic")
		res, err := p.NatCheck(context.Background(), providers.NatCheckRequest{ExpectMode: "bridge"}, natOpts(ts))
		if err != nil {
			t.Fatalf("NatCheck: %v", err)
		}
		if res.Status != "fail" {
			t.Errorf("status = %s, want fail (summary %q)", res.Status, res.Summary)
		}
	})

	// Key drift: the controller answered but without the snat_mode field.
	// Must report unknown, never guess.
	t.Run("missing mode is warn-unknown", func(t *testing.T) {
		ts := natModeServer(t, "")
		res, err := p.NatCheck(context.Background(), providers.NatCheckRequest{ExpectMode: "bridge"}, natOpts(ts))
		if err != nil {
			t.Fatalf("NatCheck: %v", err)
		}
		if res.Status != "warn" {
			t.Errorf("status = %s, want warn (summary %q)", res.Status, res.Summary)
		}
		if res.Observed["outbound_nat_mode"] != "unknown" {
			t.Errorf("outbound_nat_mode = %v, want unknown", res.Observed["outbound_nat_mode"])
		}
	})

	t.Run("missing mode passes expect unknown", func(t *testing.T) {
		ts := natModeServer(t, "")
		res, err := p.NatCheck(context.Background(), providers.NatCheckRequest{ExpectMode: "unknown"}, natOpts(ts))
		if err != nil {
			t.Fatalf("NatCheck: %v", err)
		}
		if res.Status != "pass" {
			t.Errorf("status = %s, want pass (summary %q)", res.Status, res.Summary)
		}
	})

	t.Run("read failure is error", func(t *testing.T) {
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		t.Cleanup(ts.Close)
		res, err := p.NatCheck(context.Background(), providers.NatCheckRequest{ExpectMode: "bridge"}, natOpts(ts))
		if err != nil {
			t.Fatalf("NatCheck: %v", err)
		}
		if res.Status != "error" {
			t.Errorf("status = %s, want error (summary %q)", res.Status, res.Summary)
		}
		if !strings.Contains(res.Summary, "outbound NAT mode") {
			t.Errorf("summary %q should name the failed read", res.Summary)
		}
	})
}

// A failure on a rule read (after the mode read succeeds) must name that
// specific read — the mode being fine does not make the verdict trustworthy.
func TestProviderNatCheck_LaterReadFailures(t *testing.T) {
	p := &Provider{}
	for _, tc := range []struct {
		failPath, want string
	}{
		{"/api/firewall/d_nat/search_rule", "reading port forward rules"},
		{"/api/firewall/one_to_one/search_rule", "reading one-to-one rules"},
		{"/api/firewall/source_nat/search_rule", "reading source NAT rules"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == tc.failPath {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				switch r.URL.Path {
				case "/api/firewall/filter_base/get":
					testutil.WriteBody(w, `{"general":{"snat_mode":"disabled"}}`)
				case "/api/firewall/d_nat/search_rule",
					"/api/firewall/one_to_one/search_rule",
					"/api/firewall/source_nat/search_rule":
					testutil.WriteBody(w, `{"total":0,"rows":[]}`)
				default:
					t.Errorf("unexpected path %s", r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			t.Cleanup(ts.Close)
			res, err := p.NatCheck(context.Background(), providers.NatCheckRequest{ExpectMode: "bridge"}, natOpts(ts))
			if err != nil {
				t.Fatalf("NatCheck: %v", err)
			}
			if res.Status != "error" || !strings.Contains(res.Summary, tc.want) {
				t.Errorf("status/summary = %s/%q, want %q", res.Status, res.Summary, tc.want)
			}
		})
	}
}
