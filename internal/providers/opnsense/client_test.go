package opnsense

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/testutil"
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
		testutil.WriteBody(w, firmwareJSON)
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
			testutil.WriteBody(w, firmwareJSON)
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
			testutil.WriteBody(w, firmwareJSON)
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
			testutil.WriteBody(w, `not json`)
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
			if r.URL.Path != "/api/interfaces/overview/interfaces_info" {
				t.Errorf("path = %q, want /api/interfaces/overview/interfaces_info", r.URL.Path)
			}
			testutil.WriteBody(w, `{"interfaces":{
				"lan":{"description":"LAN","dhcp":false,"ipv4":"10.0.0.1/24","ipv4_gateway":"10.0.0.254"},
				"wan":{"description":"WAN","dhcp":true,"ipv4":"203.0.113.1/24","ipv4_gateway":"203.0.113.254"},
				"no-ip":{"description":"","dhcp":false,"ipv4":"","ipv4_gateway":""}
			}}`)
		}))
		ifaces, err := c.GetInterfaces(context.Background())
		if err != nil {
			t.Fatalf("GetInterfaces: %v", err)
		}
		if len(ifaces) != 3 {
			t.Fatalf("interfaces = %+v, want 3", ifaces)
		}
		// sorted by name: lan, no-ip, wan
		if ifaces[0].Name != "lan" || ifaces[0].IP != "10.0.0.1" || ifaces[0].Subnet != 24 || ifaces[0].Gateway != "10.0.0.254" {
			t.Errorf("lan = %+v", ifaces[0])
		}
		if ifaces[1].Name != "no-ip" || ifaces[1].IP != "" || ifaces[1].Subnet != 0 {
			t.Errorf("no-ip = %+v", ifaces[1])
		}
		if ifaces[2].Name != "wan" || ifaces[2].Gateway != "203.0.113.254" || !ifaces[2].DHCP {
			t.Errorf("wan = %+v", ifaces[2])
		}
	})

	t.Run("bad json", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			testutil.WriteBody(w, `not json`)
		}))
		_, err := c.GetInterfaces(context.Background())
		if err == nil || !strings.Contains(err.Error(), "decoding interfaces response") {
			t.Errorf("error = %v, want decoding interfaces response", err)
		}
	})
}

func TestGetFirewallRules(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/firewall/filter/search_rule" {
				t.Errorf("path = %q, want /api/firewall/filter/search_rule", r.URL.Path)
			}
			testutil.WriteBody(w, `{"total":3,"rows":[
				{"uuid":"u1","enabled":"1","action":"block","description":"deny lan to iot","interface":["lan"],"source_net":"10.0.0.5","destination_net":"203.0.113.9"},
				{"uuid":"u2","enabled":"1","action":"pass","description":"allow dns","interface":["lan","wan"],"source_net":"any","destination_net":"any"},
				{"uuid":"u3","enabled":"0","action":"block","description":"disabled rule","interface":["opt1"],"source_net":"10.0.0.7","destination_net":"203.0.113.11"}
			]}`)
		}))
		rules, err := c.GetFirewallRules(context.Background())
		if err != nil {
			t.Fatalf("GetFirewallRules: %v", err)
		}
		if len(rules) != 3 {
			t.Fatalf("rules = %+v, want 3", rules)
		}
		if rules[0].Action != "block" || rules[0].Source != "10.0.0.5" || rules[0].Destination != "203.0.113.9" {
			t.Errorf("rule[0] = %+v", rules[0])
		}
		if rules[0].Disabled || rules[2].Disabled == false {
			t.Errorf("Disabled derivation wrong: %+v / %+v", rules[0], rules[2])
		}
		if len(rules[1].Interface) != 2 {
			t.Errorf("rule[1] interfaces = %v", rules[1].Interface)
		}
	})

	t.Run("errors propagate", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		_, err := c.GetFirewallRules(context.Background())
		if err == nil || !strings.Contains(err.Error(), "unexpected status 500") {
			t.Errorf("error = %v, want unexpected status 500 (errors must not be swallowed)", err)
		}
	})

	t.Run("bad json", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			testutil.WriteBody(w, `not json`)
		}))
		_, err := c.GetFirewallRules(context.Background())
		if err == nil || !strings.Contains(err.Error(), "decoding firewall rules response") {
			t.Errorf("error = %v, want decoding firewall rules response", err)
		}
	})
}

func TestGetDHCPLeases(t *testing.T) {
	t.Run("success rows shape", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/dhcpd/leases" {
				t.Errorf("path = %q, want /api/dhcpd/leases", r.URL.Path)
			}
			testutil.WriteBody(w, `{"total":1,"rows":[
				{"mac":"aa:bb:cc:dd:ee:ff","ip":"10.0.0.10","hostname":"laptop"}
			]}`)
		}))
		leases, err := c.GetDHCPLeases(context.Background())
		if err != nil {
			t.Fatalf("GetDHCPLeases: %v", err)
		}
		if len(leases) != 1 || leases[0].Hostname != "laptop" {
			t.Errorf("leases = %+v", leases)
		}
	})

	t.Run("success leases shape", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			testutil.WriteBody(w, `{"leases":[
				{"mac":"aa:bb:cc:dd:ee:ff","ip":"10.0.0.10","hostname":"laptop"}
			]}`)
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
			testutil.WriteBody(w, `not json`)
		}))
		_, err := c.GetDHCPLeases(context.Background())
		if err == nil || !strings.Contains(err.Error(), "decoding DHCP leases response") {
			t.Errorf("error = %v, want decoding DHCP leases response", err)
		}
	})
}
