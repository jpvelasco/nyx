package opnsense

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/testutil"
)

// systemInfoJSON mirrors GET /diagnostics/system/system_information: the
// product version string embeds the build number and architecture.
const systemInfoJSON = `{"name":"fw","versions":["OPNsense 24.1.7_2-amd64","FreeBSD 14.2-RELEASE-p1","OpenSSL 3.0.13"],"updates":"Click to check for updates."}`

// restoreListPageSize shrinks the production page size so a multi-page
// walk can be asserted without fabricating 500+ rows.
func restoreListPageSize(t *testing.T, n int) {
	t.Helper()
	old := listPageSize
	listPageSize = n
	t.Cleanup(func() { listPageSize = old })
}

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
		testutil.WriteBody(w, systemInfoJSON)
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
			if r.URL.Path != "/api/diagnostics/system/system_information" {
				t.Errorf("path = %q, want /api/diagnostics/system/system_information", r.URL.Path)
			}
			if k, s, ok := r.BasicAuth(); ok {
				sawKey, sawSecret = k, s
			}
			testutil.WriteBody(w, systemInfoJSON)
		}))
		resp, err := c.doRequest(context.Background(), "/diagnostics/system/system_information")
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

func TestGetSystemInformation(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/diagnostics/system/system_information" {
				t.Errorf("path = %q, want /api/diagnostics/system/system_information", r.URL.Path)
			}
			testutil.WriteBody(w, systemInfoJSON)
		}))
		info, err := c.GetSystemInformation(context.Background())
		if err != nil {
			t.Fatalf("GetSystemInformation: %v", err)
		}
		if info.ProductVersion() != "24.1.7_2" {
			t.Errorf("ProductVersion = %q, want 24.1.7_2", info.ProductVersion())
		}
		if info.Arch() != "amd64" {
			t.Errorf("Arch = %q, want amd64", info.Arch())
		}
		if info.FreeBSDVersion() != "14.2-RELEASE-p1" {
			t.Errorf("FreeBSDVersion = %q", info.FreeBSDVersion())
		}
		if info.OpenSSLVersion() != "3.0.13" {
			t.Errorf("OpenSSLVersion = %q", info.OpenSSLVersion())
		}
	})

	t.Run("version without arch suffix", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			testutil.WriteBody(w, `{"name":"fw","versions":["OPNsense 24.1.7","FreeBSD 14.2-RELEASE"],"updates":""}`)
		}))
		info, err := c.GetSystemInformation(context.Background())
		if err != nil {
			t.Fatalf("GetSystemInformation: %v", err)
		}
		if info.ProductVersion() != "24.1.7" {
			t.Errorf("ProductVersion = %q, want 24.1.7 (whole string, no arch to split)", info.ProductVersion())
		}
		if info.Arch() != "" {
			t.Errorf("Arch = %q, want empty (never guessed)", info.Arch())
		}
	})

	t.Run("bad json", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			testutil.WriteBody(w, `not json`)
		}))
		_, err := c.GetSystemInformation(context.Background())
		if err == nil || !strings.Contains(err.Error(), "decoding system information response") {
			t.Errorf("error = %v, want decoding system information response", err)
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

	t.Run("requests details=true", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("details") != "true" {
				t.Errorf("query = %q, want details=true", r.URL.RawQuery)
			}
			testutil.WriteBody(w, `{"interfaces":{}}`)
		}))
		if _, err := c.GetInterfaces(context.Background()); err != nil {
			t.Fatalf("GetInterfaces: %v", err)
		}
	})

	t.Run("26.x details populate device mac members and counters", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			testutil.WriteBody(w, `{
				"total":1,"rowCount":1,"current":1,
				"rows":[{
					"identifier":"lan","description":"LAN","enabled":true,
					"addr4":"10.0.10.1/24","device":"bridge0","macaddr":"aa:bb:cc:dd:ee:00",
					"link_type":"bridge",
					"statistics":{"rx":{"packets":11,"bytes":1100},"tx":{"packets":22,"bytes":2200}},
					"config":{"if":"bridge0","descr":"LAN","enable":"1","mtu":"1500","members":"igb0,igb1"}
				}]
			}`)
		}))
		ifaces, err := c.GetInterfaces(context.Background())
		if err != nil {
			t.Fatalf("GetInterfaces: %v", err)
		}
		if len(ifaces) != 1 {
			t.Fatalf("interfaces = %+v, want 1", ifaces)
		}
		got := ifaces[0]
		if got.Device != "bridge0" || got.MAC != "aa:bb:cc:dd:ee:00" || got.LinkType != "bridge" {
			t.Errorf("identity = %+v", got)
		}
		if !got.Enabled || got.MTU != 1500 || strings.Join(got.Members, ",") != "igb0,igb1" {
			t.Errorf("config = %+v", got)
		}
		if got.RxPackets != 11 || got.RxBytes != 1100 || got.TxPackets != 22 || got.TxBytes != 2200 {
			t.Errorf("counters = %+v", got)
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

	t.Run("26.x rows shape", func(t *testing.T) {
		// Captured field-for-field from a live 26.x interfaces_info response
		// (sanitized to the RFC5737 test range per docs/naming.md): rows carry
		// identifier + addr4 + gateways; unassigned devices (enc0, pflog0,
		// zen0) have an empty identifier and are skipped.
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			testutil.WriteBody(w, `{
				"total":4,"rowCount":4,"current":1,
				"rows":[
					{"identifier":"wan","description":"WAN","enabled":true,"addr4":"203.0.113.1/24","addr6":"","ipv4":[{"ipaddr":"203.0.113.1/24"}],"ipv6":[],"gateways":["203.0.113.254"],"config":{"if":"igb1","descr":"WAN","enable":"1","identifier":"wan"}},
					{"identifier":"lan","description":"LAN","enabled":true,"addr4":"","addr6":"","ipv4":[{"ipaddr":"198.51.100.1/24"}],"ipv6":[],"gateways":[],"config":{"if":"igb0","descr":"LAN","enable":"1","identifier":"lan"}},
					{"identifier":"opt1","description":"OPT1","enabled":true,"addr4":"198.51.100.50/24","addr6":"","ipv4":[{"ipaddr":"198.51.100.50/24"}],"ipv6":[],"gateways":[],"config":{"if":"bridge0","descr":"OPT1","enable":"1","identifier":"opt1"}},
					{"identifier":"","description":"Unassigned Interface","enabled":false,"addr4":"","addr6":"","ipv4":[],"ipv6":[],"gateways":[]}
				]
			}`)
		}))
		ifaces, err := c.GetInterfaces(context.Background())
		if err != nil {
			t.Fatalf("GetInterfaces: %v", err)
		}
		// sorted by name: lan, opt1, wan — the unassigned row is skipped
		if len(ifaces) != 3 {
			t.Fatalf("interfaces = %+v, want 3", ifaces)
		}
		if ifaces[0].Name != "lan" || ifaces[0].IP != "198.51.100.1" || ifaces[0].Subnet != 24 || ifaces[0].Gateway != "" {
			t.Errorf("lan = %+v", ifaces[0])
		}
		if ifaces[1].Name != "opt1" || ifaces[1].IP != "198.51.100.50" || ifaces[1].Description != "OPT1" {
			t.Errorf("opt1 = %+v", ifaces[1])
		}
		if ifaces[2].Name != "wan" || ifaces[2].IP != "203.0.113.1" || ifaces[2].Gateway != "203.0.113.254" {
			t.Errorf("wan = %+v", ifaces[2])
		}
	})

	t.Run("26.x rows shape takes precedence over a legacy map", func(t *testing.T) {
		// A body carrying both shapes must decode via the rows path.
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			testutil.WriteBody(w, `{
				"rows":[{"identifier":"lan","description":"LAN","addr4":"198.51.100.1/24","ipv4":[],"gateways":[]}],
				"interfaces":{"wan":{"ipv4":"203.0.113.9/24"}}
			}`)
		}))
		ifaces, err := c.GetInterfaces(context.Background())
		if err != nil {
			t.Fatalf("GetInterfaces: %v", err)
		}
		if len(ifaces) != 1 || ifaces[0].Name != "lan" {
			t.Errorf("interfaces = %+v, want only the rows-shape lan", ifaces)
		}
	})

	t.Run("200 ok with empty interfaces map decodes to zero", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			testutil.WriteBody(w, `{"interfaces":{}}`)
		}))
		ifaces, err := c.GetInterfaces(context.Background())
		if err != nil {
			t.Fatalf("GetInterfaces: %v", err)
		}
		if len(ifaces) != 0 {
			t.Errorf("interfaces = %+v, want 0 (the caller warns on empty)", ifaces)
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

	t.Run("403 privilege error is still a permission-denied", func(t *testing.T) {
		// Import degrades only this stable 403; paging must not swallow it.
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			testutil.WriteBody(w, `{"message":"Forbidden"}`)
		}))
		_, err := c.GetFirewallRules(context.Background())
		if err == nil || !isPermissionDenied(err) {
			t.Errorf("error = %v, want permission-denied 403", err)
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

	t.Run("walks every page", func(t *testing.T) {
		// Issue #86: a controller that pages at 2 must not silently
		// drop the remaining isolation rules.
		restoreListPageSize(t, 2)
		var pages []string
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			pages = append(pages, r.URL.RawQuery)
			switch r.URL.Query().Get("current") {
			case "1":
				testutil.WriteBody(w, `{"total":3,"rowCount":2,"current":1,"rows":[
					{"uuid":"u1","enabled":"1","action":"block","description":"page1a","interface":["lan"],"source_net":"any","destination_net":"any"},
					{"uuid":"u2","enabled":"1","action":"block","description":"page1b","interface":["lan"],"source_net":"any","destination_net":"any"}
				]}`)
			case "2":
				testutil.WriteBody(w, `{"total":3,"rowCount":2,"current":2,"rows":[
					{"uuid":"u3","enabled":"1","action":"block","description":"page2","interface":["lan"],"source_net":"any","destination_net":"any"}
				]}`)
			default:
				t.Errorf("unexpected query %q", r.URL.RawQuery)
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		rules, err := c.GetFirewallRules(context.Background())
		if err != nil {
			t.Fatalf("GetFirewallRules: %v", err)
		}
		if len(rules) != 3 {
			t.Fatalf("rules = %d, want 3 concatenated pages (got %+v)", len(rules), rules)
		}
		if rules[2].RuleUUID != "u3" {
			t.Errorf("last rule = %+v, want u3 from page 2", rules[2])
		}
		if len(pages) != 2 {
			t.Errorf("pages = %v, want current=1 then current=2", pages)
		}
	})
}

func TestGetDHCPLeases(t *testing.T) {
	t.Run("success rows shape on dnsmasq route", func(t *testing.T) {
		var hits []string
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits = append(hits, r.URL.Path)
			if r.URL.Path != "/api/dnsmasq/leases/search" {
				t.Errorf("path = %q, want /api/dnsmasq/leases/search", r.URL.Path)
			}
			testutil.WriteBody(w, `{"total":1,"rows":[
				{"mac":"aa:bb:cc:dd:ee:ff","ip":"10.0.0.10","hostname":"laptop"}
			]}`)
		}))
		leases, err := c.GetDHCPLeases(context.Background())
		if err != nil {
			t.Fatalf("GetDHCPLeases: %v", err)
		}
		if len(hits) != 1 {
			t.Errorf("requests = %v, want exactly 1 (dnsmasq probed first, no fallback needed)", hits)
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

	t.Run("404 on dnsmasq falls back to dhcpd", func(t *testing.T) {
		var hits []string
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits = append(hits, r.URL.Path)
			switch r.URL.Path {
			case "/api/dnsmasq/leases/search":
				w.WriteHeader(http.StatusNotFound)
			case "/api/dhcpd/leases":
				testutil.WriteBody(w, `{"leases":[
					{"mac":"aa:bb:cc:dd:ee:ff","ip":"10.0.0.10","hostname":"laptop"}
				]}`)
			default:
				t.Errorf("unexpected path %q", r.URL.Path)
			}
		}))
		leases, err := c.GetDHCPLeases(context.Background())
		if err != nil {
			t.Fatalf("GetDHCPLeases: %v", err)
		}
		if len(hits) != 2 || hits[0] != "/api/dnsmasq/leases/search" || hits[1] != "/api/dhcpd/leases" {
			t.Errorf("requests = %v, want dnsmasq then dhcpd in order", hits)
		}
		if len(leases) != 1 || leases[0].IP != "10.0.0.10" {
			t.Errorf("leases = %+v", leases)
		}
	})

	t.Run("403 on first route is stable, not masked", func(t *testing.T) {
		var hits []string
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits = append(hits, r.URL.Path)
			w.WriteHeader(http.StatusForbidden)
		}))
		_, err := c.GetDHCPLeases(context.Background())
		if len(hits) != 1 {
			t.Errorf("requests = %v, want exactly 1 (403 must not retry or fall through)", hits)
		}
		if err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Errorf("error = %v, want permission denied", err)
		}
		if !strings.Contains(err.Error(), "/dnsmasq/leases/search") {
			t.Errorf("error = %v, want the probed route named", err)
		}
	})

	t.Run("404 on all routes surfaces the last error", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		_, err := c.GetDHCPLeases(context.Background())
		if err == nil || !strings.Contains(err.Error(), "resource not found") {
			t.Errorf("error = %v, want resource not found", err)
		}
		if !strings.Contains(err.Error(), "/dhcpd/leases") {
			t.Errorf("error = %v, want the last probed route named", err)
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
