package opnsense

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const firmwareJSON = `{"product_version":"24.1.7","product_name":"OPNsense","product_arch":"amd64"}`

// newTestClient spins up a TLS test server (skipTLSVerify client) pointing at it.
func newTestClient(t *testing.T, h http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	ts := httptest.NewTLSServer(h)
	t.Cleanup(ts.Close)
	c := NewClient(ts.URL, "key", "secret", true, "")
	return c, ts
}

func TestNewClientNormalisesHost(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(firmwareJSON))
	}))
	defer ts.Close()
	host := strings.TrimPrefix(ts.URL, "https://")

	c := NewClient("https://"+host+"/", "k", "s", true, "")
	if c.host != host {
		t.Errorf("host = %q, want %q", c.host, host)
	}
}

func TestDoRequest(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		var sawKey, sawSecret string
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/core/firmware/running" {
				t.Errorf("path = %q, want /api/core/firmware/running", r.URL.Path)
			}
			if k, s, ok := r.BasicAuth(); ok {
				sawKey, sawSecret = k, s
			}
			w.Write([]byte(firmwareJSON))
		}))
		resp, err := c.doRequest(context.Background(), "/core/firmware/running")
		if err != nil {
			t.Fatalf("doRequest: %v", err)
		}
		defer resp.Body.Close()
		if sawKey != "key" || sawSecret != "secret" {
			t.Errorf("basic auth = %q/%q, want key/secret", sawKey, sawSecret)
		}
	})

	t.Run("unauthorized", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		_, err := c.doRequest(context.Background(), "/x")
		if err == nil || !strings.Contains(err.Error(), "authentication failed") {
			t.Errorf("error = %v, want authentication failed", err)
		}
	})

	t.Run("unexpected status", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		_, err := c.doRequest(context.Background(), "/x")
		if err == nil || !strings.Contains(err.Error(), "unexpected status 500") {
			t.Errorf("error = %v, want unexpected status", err)
		}
	})

	t.Run("connection failure", func(t *testing.T) {
		c := NewClient("https://127.0.0.1:1", "k", "s", true, "")
		_, err := c.doRequest(context.Background(), "/x")
		if err == nil || !strings.Contains(err.Error(), "connecting to OPNsense") {
			t.Errorf("error = %v, want connecting-to-OPNsense", err)
		}
	})
}

func TestGetFirmwareInfo(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(firmwareJSON))
		}))
		info, err := c.GetFirmwareInfo(context.Background())
		if err != nil {
			t.Fatalf("GetFirmwareInfo: %v", err)
		}
		if info.ProductVersion != "24.1.7" || info.ProductName != "OPNsense" || info.ProductArch != "amd64" {
			t.Errorf("info = %+v", info)
		}
	})

	t.Run("bad json", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`not json`))
		}))
		_, err := c.GetFirmwareInfo(context.Background())
		if err == nil || !strings.Contains(err.Error(), "decoding firmware response") {
			t.Errorf("error = %v, want decoding firmware response", err)
		}
	})
}

func TestGetInterfaces(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"interfaces":[
				{"name":"lan","ip":"10.0.0.1","subnet":24,"gateway":""},
				{"name":"wan","ip":"203.0.113.1","subnet":24,"gateway":"203.0.113.254"}
			]}`))
		}))
		ifaces, err := c.GetInterfaces(context.Background())
		if err != nil {
			t.Fatalf("GetInterfaces: %v", err)
		}
		if len(ifaces) != 2 || ifaces[0].Name != "lan" || ifaces[1].Gateway != "203.0.113.254" {
			t.Errorf("interfaces = %+v", ifaces)
		}
	})

	t.Run("bad json", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`not json`))
		}))
		_, err := c.GetInterfaces(context.Background())
		if err == nil || !strings.Contains(err.Error(), "decoding interfaces response") {
			t.Errorf("error = %v, want decoding interfaces response", err)
		}
	})
}

func TestGetFirewallRules(t *testing.T) {
	// wan → 404 (skipped), lan → rules, opt1 → bad JSON (skipped), others → 404
	seen := map[string]int{}
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		seen[p]++
		switch p {
		case "/api/core/firewall/rules/lan":
			w.Write([]byte(`{"rules":[
				{"action":"block","label":"deny lan","source":{"address":"10.0.0.0/24"},"destination":{"address":"10.0.1.0/24"}},
				{"action":"pass","label":"allow dns","source":{"address":"any"},"destination":{"address":"any"}}
			]}`))
		case "/api/core/firewall/rules/opt1":
			w.Write([]byte(`broken`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	rules, err := c.GetFirewallRules(context.Background())
	if err != nil {
		t.Fatalf("GetFirewallRules: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("rules = %+v, want 2 (404s and bad JSON skipped)", rules)
	}
	if rules[0].Action != "block" || rules[1].Action != "pass" {
		t.Errorf("rules = %+v", rules)
	}
	if seen["/api/core/firewall/rules/wan"] != 1 || seen["/api/core/firewall/rules/opt5"] != 1 {
		t.Errorf("did not iterate all interface endpoints: %v", seen)
	}
}

func TestGetDHCPLeases(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"leases":[
				{"mac":"aa:bb:cc:dd:ee:ff","ip":"10.0.0.10","hostname":"laptop"}
			]}`))
		}))
		leases, err := c.GetDHCPLeases(context.Background())
		if err != nil {
			t.Fatalf("GetDHCPLeases: %v", err)
		}
		if len(leases) != 1 || leases[0].Hostname != "laptop" {
			t.Errorf("leases = %+v", leases)
		}
	})

	t.Run("bad json", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`not json`))
		}))
		_, err := c.GetDHCPLeases(context.Background())
		if err == nil || !strings.Contains(err.Error(), "decoding DHCP leases response") {
			t.Errorf("error = %v, want decoding DHCP leases response", err)
		}
	})
}
