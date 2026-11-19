package service

import (
	"context"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/testutil"
	"net/http"
	"net/http/httptest"
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

func TestOpnsenseServiceReconReads(t *testing.T) {
	ts := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/interfaces/bridge_settings/search_item":
			testutil.WriteBody(w, `{"total":1,"rows":[{"uuid":"b1","descr":"lan-br","members":"igb0"}]}`)
		case "/api/interfaces/settings/get":
			testutil.WriteBody(w, `{"interface":{"lan":{"enable":"1","if":"bridge0"}}}`)
		case "/api/dnsmasq/settings/get":
			testutil.WriteBody(w, `{"dnsmasq":{"enable":"1"}}`)
		case "/api/unbound/settings/get":
			testutil.WriteBody(w, `{"unbound":{"enable":"1"}}`)
		case "/api/unbound/settings/searchHostOverride":
			testutil.WriteBody(w, `{"total":1,"rows":[{"uuid":"h1","hostname":"nas","domain":"home.example","server":"10.0.40.10"}]}`)
		case "/api/unbound/service/status":
			testutil.WriteBody(w, `{"running":true}`)
		case "/api/diagnostics/firewall/pf_statistics":
			testutil.WriteBody(w, `{"states":{"current":9}}`)
		case "/api/diagnostics/interface/get_routes":
			testutil.WriteBody(w, `{"rows":[{"destination":"default","gateway":"203.0.113.1"}]}`)
		default:
			t.Errorf("unexpected %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	opts := opnsenseOptions(ts)
	svc := NewOpnsenseService()
	br, err := svc.ListBridges(context.Background(), opts)
	if err != nil || len(br) != 1 || br[0].UUID != "b1" {
		t.Fatalf("bridges = %+v, %v", br, err)
	}
	ifs, err := svc.ListInterfaceSettings(context.Background(), opts)
	if err != nil || len(ifs) != 1 || ifs[0].Name != "lan" || !ifs[0].Enabled {
		t.Fatalf("ifsettings = %+v, %v", ifs, err)
	}
	dns, err := svc.GetDnsmasqSettings(context.Background(), opts)
	if err != nil || dns == nil || !dns.Enabled {
		t.Fatalf("dnsmasq = %+v, %v", dns, err)
	}
	pf, err := svc.GetPfStatistics(context.Background(), opts)
	if err != nil || pf == nil || pf.StateCount != 9 {
		t.Fatalf("pf = %+v, %v", pf, err)
	}
	rt, err := svc.ListKernelRoutes(context.Background(), opts)
	if err != nil || len(rt) != 1 || rt[0].Destination != "default" {
		t.Fatalf("routes = %+v, %v", rt, err)
	}
	unb, err := svc.GetUnboundSettings(context.Background(), opts)
	if err != nil || unb == nil || !unb.Enabled {
		t.Fatalf("unbound settings = %+v, %v", unb, err)
	}
	hosts, err := svc.ListUnboundOverrides(context.Background(), opts)
	if err != nil || len(hosts) != 1 || hosts[0].Hostname != "nas" {
		t.Fatalf("unbound hosts = %+v, %v", hosts, err)
	}
	running, err := svc.GetUnboundStatus(context.Background(), opts)
	if err != nil || !running {
		t.Fatalf("unbound status = %v, %v", running, err)
	}
}

func TestOpnsenseServiceReconReadErrors(t *testing.T) {
	ts := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	opts := opnsenseOptions(ts)
	svc := NewOpnsenseService()
	if _, err := svc.ListBridges(context.Background(), opts); err == nil {
		t.Fatal("expected ListBridges error")
	}
	if _, err := svc.ListInterfaceSettings(context.Background(), opts); err == nil {
		t.Fatal("expected ListInterfaceSettings error")
	}
	if _, err := svc.GetDnsmasqSettings(context.Background(), opts); err == nil {
		t.Fatal("expected GetDnsmasqSettings error")
	}
	if _, err := svc.GetPfStatistics(context.Background(), opts); err == nil {
		t.Fatal("expected GetPfStatistics error")
	}
	if _, err := svc.ListKernelRoutes(context.Background(), opts); err == nil {
		t.Fatal("expected ListKernelRoutes error")
	}
	if _, err := svc.GetUnboundSettings(context.Background(), opts); err == nil {
		t.Fatal("expected GetUnboundSettings error")
	}
	if _, err := svc.ListUnboundOverrides(context.Background(), opts); err == nil {
		t.Fatal("expected ListUnboundOverrides error")
	}
	if _, err := svc.GetUnboundStatus(context.Background(), opts); err == nil {
		t.Fatal("expected GetUnboundStatus error")
	}
}

func TestFlattenReconNil(t *testing.T) {
	if flattenBridges(nil) != nil || flattenIfSettings(nil) != nil || flattenRoutes(nil) != nil {
		t.Fatal("nil slices should stay nil")
	}
	if flattenDnsmasq(nil) != nil || flattenPf(nil) != nil || flattenUnbound(nil) != nil {
		t.Fatal("nil pointers should stay nil")
	}
	if flattenUnboundHosts(nil) != nil {
		t.Fatal("nil unbound hosts should stay nil")
	}
}

func TestOpnsenseServiceListWireGuard(t *testing.T) {
	ts := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "search_server"):
			testutil.WriteBody(w, `{"total":1,"rows":[{"uuid":"s1","name":"home-wg","enabled":"1","listenport":"51820"}]}`)
		case strings.Contains(r.URL.Path, "search_client"):
			testutil.WriteBody(w, `{"total":1,"rows":[{"uuid":"p1","name":"laptop","pubkey":"pub1"}]}`)
		case strings.Contains(r.URL.Path, "service/status"):
			testutil.WriteBody(w, `{"running":true}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	opts := opnsenseOptions(ts)
	svc := NewOpnsenseService()
	servers, err := svc.ListWireGuardServers(context.Background(), opts)
	if err != nil || len(servers) != 1 || servers[0].Name != "home-wg" {
		t.Fatalf("servers = %+v, %v", servers, err)
	}
	clients, err := svc.ListWireGuardClients(context.Background(), opts)
	if err != nil || len(clients) != 1 || clients[0].Pubkey != "pub1" {
		t.Fatalf("clients = %+v, %v", clients, err)
	}
	st, err := svc.GetWireGuardStatus(context.Background(), opts)
	if err != nil || st == nil || !st.Running {
		t.Fatalf("status = %+v, %v", st, err)
	}
	ts2 := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	if _, err := NewOpnsenseService().ListWireGuardServers(context.Background(), opnsenseOptions(ts2)); err == nil {
		t.Fatal("expected server error")
	}
	if _, err := NewOpnsenseService().ListWireGuardClients(context.Background(), opnsenseOptions(ts2)); err == nil {
		t.Fatal("expected client error")
	}
	if _, err := NewOpnsenseService().GetWireGuardStatus(context.Background(), opnsenseOptions(ts2)); err == nil {
		t.Fatal("expected status error")
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

func TestOpnsenseService_ConnectFailure(t *testing.T) {
	_, err := NewOpnsenseService().Info(context.Background(), OpnsenseOptions{
		Host: "https://127.0.0.1:1", APIKey: "key1", APISecret: "secret1", SkipTLSVerify: true,
	})
	if err == nil || !strings.Contains(err.Error(), "connecting to OPNsense") {
		t.Fatalf("Info error = %v, want connect failure", err)
	}
}

func TestOpnsenseServiceCheckPrivileges(t *testing.T) {
	server := opnsenseTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	rows, err := NewOpnsenseService().CheckPrivileges(t.Context(), opnsenseOptions(server))
	if err != nil || len(rows) != 8 || rows[0] != "/firewall/alias/get\tusable" {
		t.Fatalf("privilege report = %v, error = %v", rows, err)
	}
}
