package service

import (
	"context"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/testutil"
	"net/http"
)

func TestOpnsenseServiceListClients(t *testing.T) {
	for _, shape := range []string{"leases", "rows"} {
		t.Run(shape, func(t *testing.T) {
			ts := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/dnsmasq/settings/get" {
					testutil.WriteBody(w, `{"dnsmasq":{"enable":"1"}}`)
					return
				}
				if r.URL.Path != "/api/dnsmasq/leases/search" {
					t.Errorf("path = %s, want dnsmasq/leases/search", r.URL.Path)
				}
				if shape == "leases" {
					testutil.WriteBody(w, `{"leases":[{"mac":"aa:bb:cc:dd:ee:ff","ip":"10.0.10.5","hostname":"nas"}]}`)
					return
				}
				testutil.WriteBody(w, `{"total":1,"rows":[{"hwaddr":"aa:bb:cc:dd:ee:ff","address":"10.0.10.5","hostname":"nas"}]}`)
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
				testutil.WriteBody(w, `{"total":2,"rows":[{"uuid":"u1","enabled":"1","action":"block","interface":"lan,wan","categories":"trusted,iot","source_net":"trusted_hosts"},{"uuid":"u2","enabled":false,"action":"pass"}]}`)
			case "/api/firewall/alias/search_item":
				testutil.WriteBody(w, `{"total":1,"rows":[{"uuid":"a1","name":"trusted_hosts","enabled":"1","type":"host","content":"192.0.2.1\r\n192.0.2.2"}]}`)
			case "/api/kea/leases4/search":
				testutil.WriteBody(w, `{"total":1,"rows":[{"hwaddr":"aa","address":"10.0.10.5","hostname":"nas","state":0}]}`)
			case "/api/kea/leases6/search":
				testutil.WriteBody(w, `{"total":1,"rows":[{"hwaddr":"bb","address":"2001:db8::10","hostname":"cam","state":0}]}`)

			case "/api/core/service/search":
				testutil.WriteBody(w, `{"total":1,"rows":[{"name":"dnsmasq","running":"1","description":"Dnsmasq DNS/DHCP"}]}`)
			case "/api/routes/gateway/status":
				testutil.WriteBody(w, `{"items":[{"name":"WAN_DHCP","address":"203.0.113.254","status":"none"}]}`)
			case "/api/interfaces/bridge_settings/search_item":
				testutil.WriteBody(w, `{"total":0,"rows":[]}`)
			case "/api/interfaces/settings/get":
				testutil.WriteBody(w, `{"interface":{}}`)
			case "/api/dnsmasq/settings/get":
				testutil.WriteBody(w, `{"dnsmasq":{"enable":"0"}}`)
			case "/api/unbound/settings/get":
				testutil.WriteBody(w, `{"unbound":{"enable":"1"}}`)
			case "/api/unbound/settings/searchHostOverride":
				testutil.WriteBody(w, `{"total":0,"rows":[]}`)
			case "/api/unbound/service/status":
				testutil.WriteBody(w, `{"running":true}`)
			case "/api/diagnostics/firewall/pf_statistics":
				testutil.WriteBody(w, `{"states":{"current":0}}`)
			case "/api/diagnostics/interface/get_routes":
				testutil.WriteBody(w, `{"rows":[]}`)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		})

		opts := opnsenseOptions(ts)
		defaultInventory, err := NewOpnsenseService().Inventory(context.Background(), opts)
		if err != nil || defaultInventory.FirewallInventory != nil || !defaultInventory.FirewallAliasesOK {
			t.Fatalf("default inventory = %+v, %v", defaultInventory, err)
		}
		opts.IncludeFirewallDetails = true
		inv, err := NewOpnsenseService().Inventory(context.Background(), opts)
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
		if !inv.UnboundOK || inv.Unbound == nil || !inv.Unbound.Enabled || !inv.Unbound.Running {
			t.Errorf("unbound = %+v", inv.Unbound)
		}
		if !inv.AliasesOK || len(inv.Aliases) != 1 || len(inv.Rules) != 2 {
			t.Fatalf("firewall inventory = %+v", inv.FirewallInventory)
		}
		row := inv.Rules[0]
		if !row.Active || inv.Rules[1].Active || len(row.Interface) != 2 || len(row.Categories) != 2 || len(row.AliasMembers["trusted_hosts"]) != 2 {
			t.Errorf("firewall rows = %+v", inv.Rules)
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
			case "/api/dnsmasq/settings/get":
				testutil.WriteBody(w, `{"dnsmasq":{"enable":"1"}}`)
			case "/api/firewall/alias/search_item":
				w.WriteHeader(http.StatusForbidden)

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
		if len(inv.Warnings) != 3 {
			t.Errorf("Warnings = %v, want 3 (rules, aliases, leases)", inv.Warnings)
		}
	})
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
