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
		if r.URL.Path != "/api/core/firmware/running" {
			t.Errorf("path = %s, want /api/core/firmware/running", r.URL.Path)
		}
		testutil.WriteBody(w, `{"product_version":"24.7.11","product_name":"OPNsense","product_arch":"amd64"}`)
	})

	info, err := NewOpnsenseService().Info(context.Background(), opnsenseOptions(ts))
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if info.Provider != "opnsense" || info.Version != "24.7.11" || info.Product != "OPNsense" || info.Arch != "amd64" {
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

func TestOpnsenseServiceListFirewallRules(t *testing.T) {
	ts := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/firewall/filter/searchRule" {
			t.Errorf("path = %s, want searchRule", r.URL.Path)
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
				if r.URL.Path != "/api/dhcpd/leases" {
					t.Errorf("path = %s, want dhcpd/leases", r.URL.Path)
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
