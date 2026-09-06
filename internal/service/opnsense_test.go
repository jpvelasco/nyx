package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/testutil"
)

// opnsenseTestServer spins up a TLS test server that asserts the basic-auth
// credentials on every request and delegates routing to h.
func opnsenseTestServer(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "key1" || pass != "secret1" {
			w.WriteHeader(http.StatusUnauthorized)
			testutil.WriteBody(w, `{"message":"auth required"}`)
			return
		}
		h(w, r)
	}))
	t.Cleanup(ts.Close)
	return ts
}

func opnsenseOptions(ts *httptest.Server) OpnsenseOptions {
	return OpnsenseOptions{Host: ts.URL, APIKey: "key1", APISecret: "secret1", SkipTLSVerify: true}
}

func TestOpnsenseServiceInfo(t *testing.T) {
	ts := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/diagnostics/system/system_information" {
			t.Errorf("path = %s, want /api/diagnostics/system/system_information", r.URL.Path)
		}
		testutil.WriteBody(w, `{"name":"fw","versions":["OPNsense 24.7.11_2-amd64","FreeBSD 14.2-RELEASE-p1","OpenSSL 3.0.13"],"updates":"ok"}`)
	})

	info, err := NewOpnsenseService().Info(context.Background(), opnsenseOptions(ts))
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if info.Provider != "opnsense" || info.Version != "24.7.11_2" || info.Product != "OPNsense" || info.Arch != "amd64" {
		t.Errorf("info = %+v", info)
	}
}

func TestOpnsenseServiceInfo_BadCredentials(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		testutil.WriteBody(w, `{}`)
	}))
	t.Cleanup(ts.Close)

	_, err := NewOpnsenseService().Info(context.Background(), OpnsenseOptions{
		Host: ts.URL, APIKey: "key1", APISecret: "secret1", SkipTLSVerify: true,
	})
	if err == nil || !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("Info error = %v, want authentication failed", err)
	}
	if strings.Contains(err.Error(), "secret1") {
		t.Error("error must not echo the API secret")
	}
}

func TestOpnsenseServiceListInterfaces(t *testing.T) {
	ts := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/interfaces/overview/interfaces_info" {
			t.Errorf("path = %s, want interfaces_info", r.URL.Path)
		}
		testutil.WriteBody(w, `{"interfaces":{
			"opt2": {"description":"IoT","dhcp":false,"ipv4":"10.0.20.1/24","ipv4_gateway":"10.0.20.1"},
			"lan": {"description":"LAN","dhcp":true,"ipv4":"10.0.10.1/24","ipv4_gateway":"10.0.10.1"}
		}}`)
	})

	ifaces, err := NewOpnsenseService().ListInterfaces(context.Background(), opnsenseOptions(ts))
	if err != nil {
		t.Fatalf("ListInterfaces: %v", err)
	}
	if len(ifaces) != 2 {
		t.Fatalf("got %d interfaces, want 2", len(ifaces))
	}
	if ifaces[0].Name != "lan" || ifaces[1].Name != "opt2" {
		t.Errorf("interfaces = %+v, want sorted lan, opt2", ifaces)
	}
	lan := ifaces[0]
	if lan.IP != "10.0.10.1" || lan.Subnet != 24 || lan.Gateway != "10.0.10.1" || !lan.DHCP || lan.Description != "LAN" {
		t.Errorf("lan = %+v, want parsed ip/24 with gateway", lan)
	}
}

func TestOpnsenseServiceListServicesAndGateways(t *testing.T) {
	t.Run("services", func(t *testing.T) {
		ts := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/core/service/search" {
				t.Errorf("path = %s", r.URL.Path)
			}
			testutil.WriteBody(w, `{"total":1,"rows":[{"name":"dnsmasq","running":true,"description":"Dnsmasq"}]}`)
		})
		svcs, err := NewOpnsenseService().ListServices(context.Background(), opnsenseOptions(ts))
		if err != nil {
			t.Fatalf("ListServices: %v", err)
		}
		if len(svcs) != 1 || svcs[0].Name != "dnsmasq" || !svcs[0].Running {
			t.Errorf("services = %+v", svcs)
		}
	})
	t.Run("gateways", func(t *testing.T) {
		ts := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/routes/gateway/status" {
				t.Errorf("path = %s", r.URL.Path)
			}
			testutil.WriteBody(w, `{"items":[{"name":"WAN_DHCP","status":"none","address":"203.0.113.254"}]}`)
		})
		gws, err := NewOpnsenseService().ListGateways(context.Background(), opnsenseOptions(ts))
		if err != nil {
			t.Fatalf("ListGateways: %v", err)
		}
		if len(gws) != 1 || gws[0].Name != "WAN_DHCP" || gws[0].Status != "none" {
			t.Errorf("gateways = %+v", gws)
		}
	})
	t.Run("services error", func(t *testing.T) {
		ts := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		})
		if _, err := NewOpnsenseService().ListServices(context.Background(), opnsenseOptions(ts)); err == nil {
			t.Fatal("expected ListServices error")
		}
	})
	t.Run("gateways error", func(t *testing.T) {
		ts := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		})
		if _, err := NewOpnsenseService().ListGateways(context.Background(), opnsenseOptions(ts)); err == nil {
			t.Fatal("expected ListGateways error")
		}
	})
}

func TestOpnsenseServiceListFirewallRules(t *testing.T) {
	ts := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/firewall/filter/search_rule" {
			t.Errorf("path = %s, want search_rule", r.URL.Path)
		}
		testutil.WriteBody(w, `{"total":2,"rows":[
			{"uuid":"u1","enabled":"1","action":"block","interface":["lan"],"protocol":"tcp","source_net":"10.0.20.0/24","destination_net":"10.0.10.0/24","description":"Block IoT"},
			{"uuid":"u2","enabled":"0","action":"pass","interface":["lan","wan"],"protocol":"any","source_net":"any","destination_net":"any","description":""}
		]}`)
	})

	rules, err := NewOpnsenseService().ListFirewallRules(context.Background(), opnsenseOptions(ts))
	if err != nil {
		t.Fatalf("ListFirewallRules: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("got %d rules, want 2", len(rules))
	}
	block := rules[0]
	if block.UUID != "u1" || !block.Enabled || block.Disabled || block.Action != "block" ||
		block.Source != "10.0.20.0/24" || block.Destination != "10.0.10.0/24" || block.Label != "Block IoT" {
		t.Errorf("block rule = %+v", block)
	}
	if len(block.Interfaces) != 1 || block.Interfaces[0] != "lan" || block.Protocol != "tcp" {
		t.Errorf("block rule interfaces = %+v", block.Interfaces)
	}
	pass := rules[1]
	if pass.Enabled || !pass.Disabled || pass.Action != "pass" {
		t.Errorf("pass rule = %+v, want disabled", pass)
	}
}

func TestOpnsenseServiceListClients(t *testing.T) {
	for _, shape := range []string{"leases", "rows"} {
		t.Run(shape, func(t *testing.T) {
			ts := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/dnsmasq/leases/search" {
					t.Errorf("path = %s, want dnsmasq/leases/search", r.URL.Path)
				}
				if shape == "leases" {
					testutil.WriteBody(w, `{"leases":[{"mac":"aa:bb:cc:dd:ee:ff","ip":"10.0.10.5","hostname":"nas"}]}`)
					return
				}
				testutil.WriteBody(w, `{"rows":[{"mac":"aa:bb:cc:dd:ee:ff","ip":"10.0.10.5","hostname":"nas"}]}`)
			})

			clients, err := NewOpnsenseService().ListClients(context.Background(), opnsenseOptions(ts))
			if err != nil {
				t.Fatalf("ListClients: %v", err)
			}
			if len(clients) != 1 || clients[0].MAC != "aa:bb:cc:dd:ee:ff" || clients[0].IP != "10.0.10.5" || clients[0].Hostname != "nas" {
				t.Errorf("clients = %+v", clients)
			}
		})
	}
}

func TestOpnsenseServiceInventory(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		ts := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/diagnostics/system/system_information":
				testutil.WriteBody(w, `{"name":"fw","versions":["OPNsense 24.7.11_2-amd64","FreeBSD 14.2-RELEASE-p1","OpenSSL 3.0.13"],"updates":"ok"}`)
			case "/api/interfaces/overview/interfaces_info":
				testutil.WriteBody(w, `{"interfaces":{
					"lan": {"description":"LAN","ipv4":"10.0.10.1/24","ipv4_gateway":"10.0.10.1"},
					"iot": {"description":"IoT","ipv4":"10.0.20.1/24","ipv4_gateway":"10.0.20.1"}
				}}`)
			case "/api/firewall/filter/search_rule":
				testutil.WriteBody(w, `{"total":2,"rows":[{"uuid":"u1","enabled":"1","action":"block"},{"uuid":"u2","enabled":"1","action":"pass"}]}`)
			case "/api/dnsmasq/leases/search":
				testutil.WriteBody(w, `{"leases":[{"mac":"aa","ip":"10.0.10.5","hostname":"nas"},{"mac":"bb","ip":"10.0.20.5","hostname":"cam"}]}`)
			case "/api/core/service/search":
				testutil.WriteBody(w, `{"total":1,"rows":[{"name":"dnsmasq","running":"1","description":"Dnsmasq DNS/DHCP"}]}`)
			case "/api/routes/gateway/status":
				testutil.WriteBody(w, `{"items":[{"name":"WAN_DHCP","address":"203.0.113.254","status":"none"}]}`)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		})

		inv, err := NewOpnsenseService().Inventory(context.Background(), opnsenseOptions(ts))
		if err != nil {
			t.Fatalf("Inventory: %v", err)
		}
		if inv.ControllerVersion != "24.7.11_2" || inv.Arch != "amd64" {
			t.Errorf("controller = %q/%q, want 24.7.11_2/amd64", inv.ControllerVersion, inv.Arch)
		}
		if len(inv.Devices) != 2 {
			t.Errorf("Devices = %+v, want 2", inv.Devices)
		}
		if inv.NetworkGateways["lan"] != "10.0.10.1" || inv.NetworkGateways["iot"] != "10.0.20.1" {
			t.Errorf("NetworkGateways = %v", inv.NetworkGateways)
		}
		if inv.FirewallRuleCount != 2 || !inv.FirewallRulesOK {
			t.Errorf("rule count = %d/%v, want 2/true", inv.FirewallRuleCount, inv.FirewallRulesOK)
		}
		if inv.ClientCount != 2 {
			t.Errorf("ClientCount = %d, want 2", inv.ClientCount)
		}
		if !inv.ServicesOK || len(inv.Services) != 1 || !inv.Services[0].Running {
			t.Errorf("services = %+v", inv.Services)
		}
		if !inv.GatewaysOK || len(inv.Gateways) != 1 || inv.Gateways[0].Name != "WAN_DHCP" {
			t.Errorf("gateways = %+v", inv.Gateways)
		}
		if len(inv.Warnings) != 0 {
			t.Errorf("Warnings = %v, want none", inv.Warnings)
		}
	})

	t.Run("interfaces fatal", func(t *testing.T) {
		ts := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/interfaces/overview/interfaces_info" {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			testutil.WriteBody(w, `{}`)
		})

		_, err := NewOpnsenseService().Inventory(context.Background(), opnsenseOptions(ts))
		if err == nil {
			t.Error("expected interfaces failure to be fatal")
		}
	})

	t.Run("best-effort degradation", func(t *testing.T) {
		ts := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/interfaces/overview/interfaces_info":
				testutil.WriteBody(w, `{"interfaces":{"lan":{"ipv4":"10.0.10.1/24"}}}`)
			case "/api/firewall/filter/search_rule":
				w.WriteHeader(http.StatusInternalServerError)
			case "/api/dnsmasq/leases/search":
				w.WriteHeader(http.StatusInternalServerError)
			default:
				testutil.WriteBody(w, `{}`)
			}
		})

		inv, err := NewOpnsenseService().Inventory(context.Background(), opnsenseOptions(ts))
		if err != nil {
			t.Fatalf("Inventory: %v", err)
		}
		if inv.FirewallRulesOK {
			t.Error("FirewallRulesOK = true, want false after a 5xx")
		}
		if inv.ClientCount != 0 {
			t.Errorf("ClientCount = %d, want 0 after lease failure", inv.ClientCount)
		}
		if len(inv.Warnings) != 2 {
			t.Errorf("Warnings = %v, want 2 (rules, leases)", inv.Warnings)
		}
	})
}

func TestOpnsenseService_StatusErrors(t *testing.T) {
	ts := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	_, err := NewOpnsenseService().Info(context.Background(), opnsenseOptions(ts))
	if err == nil || !strings.Contains(err.Error(), "unexpected status 500") {
		t.Fatalf("Info error = %v, want unexpected status 500", err)
	}
}

func TestOpnsenseService_DecodeError(t *testing.T) {
	ts := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		testutil.WriteBody(w, `not-json`)
	})

	_, err := NewOpnsenseService().ListInterfaces(context.Background(), opnsenseOptions(ts))
	if err == nil || !strings.Contains(err.Error(), "decoding interfaces response") {
		t.Fatalf("ListInterfaces error = %v, want decode failure", err)
	}
}

func TestOpnsenseServiceListFirewallRules_Error(t *testing.T) {
	ts := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	_, err := NewOpnsenseService().ListFirewallRules(context.Background(), opnsenseOptions(ts))
	if err == nil || !strings.Contains(err.Error(), "unexpected status 500") {
		t.Fatalf("ListFirewallRules error = %v, want unexpected status 500", err)
	}
}

func TestOpnsenseServiceListClients_Error(t *testing.T) {
	ts := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	_, err := NewOpnsenseService().ListClients(context.Background(), opnsenseOptions(ts))
	if err == nil || !strings.Contains(err.Error(), "unexpected status 500") {
		t.Fatalf("ListClients error = %v, want unexpected status 500", err)
	}
}

func TestOpnsenseService_ConnectFailure(t *testing.T) {
	_, err := NewOpnsenseService().Info(context.Background(), OpnsenseOptions{
		Host: "https://127.0.0.1:1", APIKey: "key1", APISecret: "secret1", SkipTLSVerify: true,
	})
	if err == nil || !strings.Contains(err.Error(), "connecting to OPNsense") {
		t.Fatalf("Info error = %v, want connect failure", err)
	}
}
