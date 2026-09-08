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

func TestOpnsenseServiceListKea(t *testing.T) {
	ts := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "search_subnet"):
			testutil.WriteBody(w, `{"total":1,"rows":[{"uuid":"s1","subnet":"10.0.10.0/24"}]}`)
		case strings.Contains(r.URL.Path, "search_reservation"):
			testutil.WriteBody(w, `{"total":1,"rows":[{"uuid":"r1","ip":"10.0.10.20","mac":"aa:bb:cc:dd:ee:01"}]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	opts := opnsenseOptions(ts)
	subs, err := NewOpnsenseService().ListKeaSubnets(context.Background(), opts)
	if err != nil || len(subs) != 1 || subs[0].Subnet != "10.0.10.0/24" {
		t.Fatalf("subnets = %+v, %v", subs, err)
	}
	res, err := NewOpnsenseService().ListKeaReservations(context.Background(), opts)
	if err != nil || len(res) != 1 || res[0].IP != "10.0.10.20" {
		t.Fatalf("resv = %+v, %v", res, err)
	}
	ts2 := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	if _, err := NewOpnsenseService().ListKeaSubnets(context.Background(), opnsenseOptions(ts2)); err == nil {
		t.Fatal("expected subnet error")
	}
	if _, err := NewOpnsenseService().ListKeaReservations(context.Background(), opnsenseOptions(ts2)); err == nil {
		t.Fatal("expected reservation error")
	}
}

func TestOpnsenseServicePlanApplyDHCP(t *testing.T) {
	ts := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "dnsmasq/settings/get"):
			testutil.WriteBody(w, `{"dnsmasq":{"enable":"1","dhcp":{"range":{}}}}`)
		case strings.Contains(r.URL.Path, "kea/service/status"):
			testutil.WriteBody(w, `{"running":false}`)
		case strings.Contains(r.URL.Path, "add_range"), strings.Contains(r.URL.Path, "reconfigure"):
			testutil.WriteBody(w, `{"result":"saved","uuid":"r1"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	opts := opnsenseOptions(ts)
	svc := NewOpnsenseService()
	req := OpnsenseDHCPRequest{Kind: "range", Interface: "lan", Start: "10.0.10.100", End: "10.0.10.200"}
	plan, err := svc.PlanDHCP(context.Background(), opts, req)
	if err != nil || plan.Action != "create" || plan.Backend != "dnsmasq" {
		t.Fatalf("plan = %+v, %v", plan, err)
	}
	dry, err := svc.ApplyDHCP(context.Background(), opts, req, true)
	if err != nil || !dry.DryRun || dry.Outcome != "create" {
		t.Fatalf("dry = %+v, %v", dry, err)
	}
	live, err := svc.ApplyDHCP(context.Background(), opts, req, false)
	if err != nil || live.Outcome != "created" {
		t.Fatalf("live = %+v, %v", live, err)
	}
}

func TestOpnsenseServicePlanDHCPHostAndErrors(t *testing.T) {
	ts := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "dnsmasq/settings/get"):
			testutil.WriteBody(w, `{"dnsmasq":{"enable":"1","dhcp":{"range":{"r1":{"interface":"lan","start":"10.0.10.100","end":"10.0.10.200"}},"host":{"h1":{"host":"printer","ip":"10.0.10.20"}}}}}`)
		case strings.Contains(r.URL.Path, "kea/service/status"):
			testutil.WriteBody(w, `{"running":false}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	opts := opnsenseOptions(ts)
	svc := NewOpnsenseService()
	unchanged, err := svc.PlanDHCP(context.Background(), opts, OpnsenseDHCPRequest{Kind: "range", Interface: "lan", Start: "10.0.10.100", End: "10.0.10.200"})
	if err != nil || unchanged.Action != "unchanged" {
		t.Fatalf("range unchanged = %+v %v", unchanged, err)
	}
	host, err := svc.PlanDHCP(context.Background(), opts, OpnsenseDHCPRequest{Kind: "host", Hostname: "nas", IP: "10.0.10.30"})
	if err != nil || host.Action != "create" || host.Kind != "host" {
		t.Fatalf("host create = %+v %v", host, err)
	}
	del, err := svc.PlanDHCP(context.Background(), opts, OpnsenseDHCPRequest{Kind: "host", Hostname: "missing", IP: "10.0.10.9", Delete: true})
	if err != nil || del.Action != "unchanged" {
		t.Fatalf("host delete missing = %+v %v", del, err)
	}
	if _, err := svc.PlanDHCP(context.Background(), opts, OpnsenseDHCPRequest{Kind: "range"}); err == nil {
		t.Fatal("expected start/end required")
	}
	if _, err := svc.resolveDHCPBackend(context.Background(), opts, "bogus"); err == nil {
		t.Fatal("expected bad backend")
	}
	if _, err := svc.resolveDHCPBackend(context.Background(), opts, "kea"); err == nil || !strings.Contains(err.Error(), "running backend is dnsmasq") {
		t.Fatalf("backend mismatch = %v", err)
	}
}

func TestOpnsenseServicePlanApplyKeaReservation(t *testing.T) {
	ts := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "dnsmasq/settings/get"):
			testutil.WriteBody(w, `{"dnsmasq":{"enable":"0"}}`)
		case strings.Contains(r.URL.Path, "kea/service/status"):
			testutil.WriteBody(w, `{"running":true}`)
		case strings.Contains(r.URL.Path, "search_reservation"):
			testutil.WriteBody(w, `{"total":1,"rows":[{"uuid":"k1","ip":"10.0.10.20","mac":"aa:bb:cc:dd:ee:01"}]}`)
		case strings.Contains(r.URL.Path, "search_subnet"):
			testutil.WriteBody(w, `{"total":1,"rows":[{"uuid":"s1","subnet":"10.0.10.0/24"}]}`)
		case strings.Contains(r.URL.Path, "add_reservation"), strings.Contains(r.URL.Path, "reconfigure"):
			testutil.WriteBody(w, `{"result":"saved","uuid":"k-new"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	opts := opnsenseOptions(ts)
	svc := NewOpnsenseService()
	same, err := svc.PlanDHCP(context.Background(), opts, OpnsenseDHCPRequest{Kind: "reservation", IP: "10.0.10.20", MAC: "aa:bb:cc:dd:ee:01"})
	if err != nil || same.Action != "unchanged" || same.Backend != "kea" {
		t.Fatalf("same resv = %+v %v", same, err)
	}
	create, err := svc.PlanDHCP(context.Background(), opts, OpnsenseDHCPRequest{Kind: "reservation", IP: "10.0.10.30", MAC: "aa:bb:cc:dd:ee:02"})
	if err != nil || create.Action != "create" {
		t.Fatalf("create resv = %+v %v", create, err)
	}
	live, err := svc.ApplyDHCP(context.Background(), opts, OpnsenseDHCPRequest{Kind: "reservation", IP: "10.0.10.30", MAC: "aa:bb:cc:dd:ee:02"}, false)
	if err != nil || live.Outcome != "created" {
		t.Fatalf("apply resv = %+v %v", live, err)
	}
	sub, err := svc.PlanDHCP(context.Background(), opts, OpnsenseDHCPRequest{Kind: "range", Start: "10.0.10.0/24"})
	if err != nil || sub.Action != "unchanged" {
		t.Fatalf("subnet unchanged = %+v %v", sub, err)
	}
}

func TestOpnsenseServiceApplyDHCPDeletesAndUpdates(t *testing.T) {
	ts := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "dnsmasq/settings/get"):
			testutil.WriteBody(w, `{"dnsmasq":{"enable":"1","dhcp":{"range":{"r1":{"interface":"lan","start":"10.0.10.100","end":"10.0.10.200"}},"host":{"h1":{"host":"printer","ip":"10.0.10.20"}}}}}`)
		case strings.Contains(r.URL.Path, "kea/service/status"):
			testutil.WriteBody(w, `{"running":false}`)
		case strings.Contains(r.URL.Path, "set_range"), strings.Contains(r.URL.Path, "del_range"),
			strings.Contains(r.URL.Path, "set_host"), strings.Contains(r.URL.Path, "del_host"),
			strings.Contains(r.URL.Path, "reconfigure"):
			testutil.WriteBody(w, `{"result":"saved"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	opts := opnsenseOptions(ts)
	svc := NewOpnsenseService()
	upd, err := svc.ApplyDHCP(context.Background(), opts, OpnsenseDHCPRequest{Kind: "range", UUID: "r1", Interface: "lan", Start: "10.0.10.100", End: "10.0.10.220"}, false)
	if err != nil || upd.Outcome != "updated" {
		t.Fatalf("update range = %+v %v", upd, err)
	}
	del, err := svc.ApplyDHCP(context.Background(), opts, OpnsenseDHCPRequest{Kind: "range", UUID: "r1", Delete: true}, false)
	if err != nil || del.Outcome != "deleted" {
		t.Fatalf("delete range = %+v %v", del, err)
	}
	hostUpd, err := svc.ApplyDHCP(context.Background(), opts, OpnsenseDHCPRequest{Kind: "host", UUID: "h1", Hostname: "printer", IP: "10.0.10.21"}, false)
	if err != nil || hostUpd.Outcome != "updated" {
		t.Fatalf("update host = %+v %v", hostUpd, err)
	}
	hostDel, err := svc.ApplyDHCP(context.Background(), opts, OpnsenseDHCPRequest{Kind: "host", UUID: "h1", Delete: true}, false)
	if err != nil || hostDel.Outcome != "deleted" {
		t.Fatalf("delete host = %+v %v", hostDel, err)
	}
}

func TestOpnsenseServiceApplyKeaDeletes(t *testing.T) {
	ts := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "dnsmasq/settings/get"):
			testutil.WriteBody(w, `{"dnsmasq":{"enable":"0"}}`)
		case strings.Contains(r.URL.Path, "kea/service/status"):
			testutil.WriteBody(w, `{"running":true}`)
		case strings.Contains(r.URL.Path, "search_reservation"):
			testutil.WriteBody(w, `{"total":1,"rows":[{"uuid":"k1","ip":"10.0.10.20","mac":"aa:bb:cc:dd:ee:01"}]}`)
		case strings.Contains(r.URL.Path, "search_subnet"):
			testutil.WriteBody(w, `{"total":1,"rows":[{"uuid":"s1","subnet":"10.0.10.0/24"}]}`)
		case strings.Contains(r.URL.Path, "del_reservation"), strings.Contains(r.URL.Path, "del_subnet"),
			strings.Contains(r.URL.Path, "set_subnet"), strings.Contains(r.URL.Path, "reconfigure"):
			testutil.WriteBody(w, `{"result":"saved"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	opts := opnsenseOptions(ts)
	svc := NewOpnsenseService()
	delR, err := svc.ApplyDHCP(context.Background(), opts, OpnsenseDHCPRequest{Kind: "reservation", UUID: "k1", Delete: true}, false)
	if err != nil || delR.Outcome != "deleted" {
		t.Fatalf("delete resv = %+v %v", delR, err)
	}
	delS, err := svc.ApplyDHCP(context.Background(), opts, OpnsenseDHCPRequest{Kind: "range", UUID: "s1", Delete: true}, false)
	if err != nil || delS.Outcome != "deleted" {
		t.Fatalf("delete subnet = %+v %v", delS, err)
	}
	if _, err := svc.PlanDHCP(context.Background(), opts, OpnsenseDHCPRequest{Kind: "reservation"}); err == nil {
		t.Fatal("expected ip/mac required")
	}
	if _, err := svc.PlanDHCP(context.Background(), opts, OpnsenseDHCPRequest{Kind: "range"}); err == nil {
		t.Fatal("expected subnet required")
	}
}

func TestOpnsenseServiceApplyKeaCreatesAndHostCreate(t *testing.T) {
	ts := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "dnsmasq/settings/get"):
			testutil.WriteBody(w, `{"dnsmasq":{"enable":"1","dhcp":{"range":{},"host":{}}}}`)
		case strings.Contains(r.URL.Path, "kea/service/status"):
			testutil.WriteBody(w, `{"running":false}`)
		case strings.Contains(r.URL.Path, "add_host"), strings.Contains(r.URL.Path, "reconfigure"):
			testutil.WriteBody(w, `{"result":"saved","uuid":"h-new"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	opts := opnsenseOptions(ts)
	svc := NewOpnsenseService()
	live, err := svc.ApplyDHCP(context.Background(), opts, OpnsenseDHCPRequest{Kind: "host", Hostname: "nas", IP: "10.0.10.30"}, false)
	if err != nil || live.Outcome != "created" {
		t.Fatalf("create host = %+v %v", live, err)
	}
	ts2 := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "dnsmasq/settings/get"):
			testutil.WriteBody(w, `{"dnsmasq":{"enable":"0"}}`)
		case strings.Contains(r.URL.Path, "kea/service/status"):
			testutil.WriteBody(w, `{"running":true}`)
		case strings.Contains(r.URL.Path, "search_subnet"):
			testutil.WriteBody(w, `{"total":0,"rows":[]}`)
		case strings.Contains(r.URL.Path, "search_reservation"):
			testutil.WriteBody(w, `{"total":0,"rows":[]}`)
		case strings.Contains(r.URL.Path, "add_subnet"), strings.Contains(r.URL.Path, "reconfigure"):
			testutil.WriteBody(w, `{"result":"saved","uuid":"s-new"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	sub, err := NewOpnsenseService().ApplyDHCP(context.Background(), opnsenseOptions(ts2), OpnsenseDHCPRequest{Kind: "range", Start: "10.0.20.0/24"}, false)
	if err != nil || sub.Outcome != "created" {
		t.Fatalf("create subnet = %+v %v", sub, err)
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
		if !inv.UnboundOK || inv.Unbound == nil || !inv.Unbound.Enabled || !inv.Unbound.Running {
			t.Errorf("unbound = %+v", inv.Unbound)
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

func TestOpnsenseServicePlanApplyVLAN(t *testing.T) {
	ts := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "vlan_settings/search_item"):
			testutil.WriteBody(w, `{"total":1,"rows":[{"uuid":"v1","if":"igb0","tag":"60","descr":"iot"}]}`)
		case strings.Contains(r.URL.Path, "bridge_settings/search_item"):
			testutil.WriteBody(w, `{"total":1,"rows":[{"uuid":"b1","members":"igb0"}]}`)
		case strings.Contains(r.URL.Path, "add_item"):
			testutil.WriteBody(w, `{"result":"saved","uuid":"v-new"}`)
		default:
			testutil.WriteBody(w, `{"result":"saved"}`)
		}
	})
	svc := NewOpnsenseService()
	ctx := context.Background()
	opts := opnsenseOptions(ts)
	listed, err := svc.ListVLANs(ctx, opts)
	if err != nil || len(listed) != 1 || listed[0].Tag != 60 {
		t.Fatalf("list = %+v %v", listed, err)
	}
	unchanged, err := svc.PlanVLAN(ctx, opts, OpnsenseVLANRequest{Parent: "igb0", Tag: 60, Description: "iot"})
	if err != nil || unchanged.Action != "unchanged" {
		t.Fatalf("unchanged = %+v %v", unchanged, err)
	}
	create, err := svc.PlanVLAN(ctx, opts, OpnsenseVLANRequest{Parent: "igb0", Tag: 70})
	if err != nil || create.Action != "create" || !strings.Contains(create.Warning, "GUI") {
		t.Fatalf("create = %+v %v", create, err)
	}
	dry, err := svc.ApplyVLAN(ctx, opts, OpnsenseVLANRequest{Parent: "igb0", Tag: 70}, true)
	if err != nil || !dry.DryRun || dry.Outcome != "create" {
		t.Fatalf("dry = %+v %v", dry, err)
	}
	created, err := svc.ApplyVLAN(ctx, opts, OpnsenseVLANRequest{Parent: "igb0", Tag: 70, Description: "guest"}, false)
	if err != nil || created.Outcome != "created" || created.UUID != "v-new" {
		t.Fatalf("created = %+v %v", created, err)
	}
	br, err := svc.PlanVLAN(ctx, opts, OpnsenseVLANRequest{Kind: "bridge", UUID: "b1", Members: []string{"igb0", "igb0.60"}})
	if err != nil || br.Action != "update" {
		t.Fatalf("bridge plan = %+v %v", br, err)
	}
	applied, err := svc.ApplyVLAN(ctx, opts, OpnsenseVLANRequest{Kind: "bridge", UUID: "b1", Members: []string{"igb0", "igb0.60"}}, false)
	if err != nil || applied.Outcome != "updated" {
		t.Fatalf("bridge apply = %+v %v", applied, err)
	}
	if _, err := svc.PlanVLAN(ctx, opts, OpnsenseVLANRequest{}); err == nil {
		t.Fatal("expected parent/tag required")
	}
	upd, err := svc.PlanVLAN(ctx, opts, OpnsenseVLANRequest{Parent: "igb0", Tag: 60, Description: "iot-renamed"})
	if err != nil || upd.Action != "update" {
		t.Fatalf("update plan = %+v %v", upd, err)
	}
	updated, err := svc.ApplyVLAN(ctx, opts, OpnsenseVLANRequest{Parent: "igb0", Tag: 60, Description: "iot-renamed"}, false)
	if err != nil || updated.Outcome != "updated" {
		t.Fatalf("update apply = %+v %v", updated, err)
	}
	del, err := svc.PlanVLAN(ctx, opts, OpnsenseVLANRequest{UUID: "v1", Delete: true})
	if err != nil || del.Action != "delete" {
		t.Fatalf("delete plan = %+v %v", del, err)
	}
	deleted, err := svc.ApplyVLAN(ctx, opts, OpnsenseVLANRequest{UUID: "v1", Delete: true}, false)
	if err != nil || deleted.Outcome != "deleted" {
		t.Fatalf("delete apply = %+v %v", deleted, err)
	}
	same, err := svc.PlanVLAN(ctx, opts, OpnsenseVLANRequest{Kind: "bridge", UUID: "b1", Members: []string{"igb0"}})
	if err != nil || same.Action != "unchanged" {
		t.Fatalf("bridge unchanged = %+v %v", same, err)
	}
	if _, err := svc.PlanVLAN(ctx, opts, OpnsenseVLANRequest{Kind: "bridge"}); err == nil {
		t.Fatal("expected bridge uuid required")
	}
	if _, err := svc.PlanVLAN(ctx, opts, OpnsenseVLANRequest{Kind: "bridge", UUID: "missing", Members: []string{"igb0"}}); err == nil {
		t.Fatal("expected missing bridge")
	}
	if _, err := svc.PlanVLAN(ctx, opts, OpnsenseVLANRequest{Kind: "bridge", UUID: "b1", Delete: true}); err == nil {
		t.Fatal("expected bridge delete unsupported")
	}
	missingDel, err := svc.PlanVLAN(ctx, opts, OpnsenseVLANRequest{UUID: "nope", Delete: true})
	if err != nil || missingDel.Action != "unchanged" {
		t.Fatalf("delete missing = %+v %v", missingDel, err)
	}
}

func TestOpnsenseServicePlanApplyUnboundOverride(t *testing.T) {
	var posts []string
	ts := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			posts = append(posts, r.URL.Path)
		}
		switch {
		case strings.Contains(r.URL.Path, "searchHostOverride"):
			testutil.WriteBody(w, `{"total":1,"rows":[{"uuid":"h1","hostname":"nas","domain":"home.example","server":"10.0.40.10"}]}`)
		case strings.Contains(r.URL.Path, "addHostOverride"):
			testutil.WriteBody(w, `{"result":"saved","uuid":"h-new"}`)
		default:
			testutil.WriteBody(w, `{"result":"saved"}`)
		}
	})
	svc := NewOpnsenseService()
	ctx := context.Background()
	opts := opnsenseOptions(ts)

	unchanged, err := svc.PlanUnboundOverride(ctx, opts, OpnsenseUnboundOverrideRequest{Hostname: "nas", Domain: "home.example", IP: "10.0.40.10"})
	if err != nil || unchanged.Action != "unchanged" {
		t.Fatalf("unchanged = %+v %v", unchanged, err)
	}
	create, err := svc.PlanUnboundOverride(ctx, opts, OpnsenseUnboundOverrideRequest{Hostname: "printer", Domain: "home.example", IP: "10.0.10.20"})
	if err != nil || create.Action != "create" {
		t.Fatalf("create = %+v %v", create, err)
	}
	posts = nil
	dry, err := svc.ApplyUnboundOverride(ctx, opts, OpnsenseUnboundOverrideRequest{Hostname: "printer", Domain: "home.example", IP: "10.0.10.20"}, true)
	if err != nil || !dry.DryRun || dry.Outcome != "create" {
		t.Fatalf("dry = %+v %v", dry, err)
	}
	if len(posts) != 0 {
		t.Fatalf("dry-run posted %v", posts)
	}
	created, err := svc.ApplyUnboundOverride(ctx, opts, OpnsenseUnboundOverrideRequest{Hostname: "printer", Domain: "home.example", IP: "10.0.10.20"}, false)
	if err != nil || created.Outcome != "created" || created.UUID != "h-new" {
		t.Fatalf("created = %+v %v", created, err)
	}
	joined := strings.Join(posts, ",")
	if !strings.Contains(joined, "addHostOverride") || !strings.Contains(joined, "reconfigure") {
		t.Fatalf("real apply posts = %v, want add + reconfigure", posts)
	}
	upd, err := svc.PlanUnboundOverride(ctx, opts, OpnsenseUnboundOverrideRequest{Hostname: "nas", Domain: "home.example", IP: "10.0.40.11"})
	if err != nil || upd.Action != "update" {
		t.Fatalf("update plan = %+v %v", upd, err)
	}
	updated, err := svc.ApplyUnboundOverride(ctx, opts, OpnsenseUnboundOverrideRequest{Hostname: "nas", Domain: "home.example", IP: "10.0.40.11"}, false)
	if err != nil || updated.Outcome != "updated" {
		t.Fatalf("update apply = %+v %v", updated, err)
	}
	del, err := svc.PlanUnboundOverride(ctx, opts, OpnsenseUnboundOverrideRequest{UUID: "h1", Delete: true})
	if err != nil || del.Action != "delete" {
		t.Fatalf("delete plan = %+v %v", del, err)
	}
	deleted, err := svc.ApplyUnboundOverride(ctx, opts, OpnsenseUnboundOverrideRequest{UUID: "h1", Delete: true}, false)
	if err != nil || deleted.Outcome != "deleted" {
		t.Fatalf("delete apply = %+v %v", deleted, err)
	}
	missingDel, err := svc.PlanUnboundOverride(ctx, opts, OpnsenseUnboundOverrideRequest{Hostname: "missing", Domain: "home.example", Delete: true})
	if err != nil || missingDel.Action != "unchanged" {
		t.Fatalf("delete missing = %+v %v", missingDel, err)
	}
	if _, err := svc.PlanUnboundOverride(ctx, opts, OpnsenseUnboundOverrideRequest{}); err == nil {
		t.Fatal("expected hostname/ip required")
	}
	if _, err := svc.PlanUnboundOverride(ctx, opts, OpnsenseUnboundOverrideRequest{Delete: true}); err == nil {
		t.Fatal("expected delete identifier required")
	}
}

func TestOpnsenseServiceUnboundOverride_Errors(t *testing.T) {
	failAll := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	opts := opnsenseOptions(failAll)
	if _, err := NewOpnsenseService().PlanUnboundOverride(context.Background(), opts, OpnsenseUnboundOverrideRequest{Hostname: "nas", IP: "10.0.40.10"}); err == nil {
		t.Fatal("expected plan fetch error")
	}
	if _, err := NewOpnsenseService().ApplyUnboundOverride(context.Background(), opts, OpnsenseUnboundOverrideRequest{Hostname: "nas", IP: "10.0.40.10"}, false); err == nil {
		t.Fatal("expected apply plan error")
	}

	writeFail := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "searchHostOverride") {
			testutil.WriteBody(w, `{"total":1,"rows":[{"uuid":"h1","hostname":"nas","domain":"home.example","server":"10.0.40.10"}]}`)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	})
	wopts := opnsenseOptions(writeFail)
	if _, err := NewOpnsenseService().ApplyUnboundOverride(context.Background(), wopts, OpnsenseUnboundOverrideRequest{Hostname: "printer", Domain: "home.example", IP: "10.0.10.20"}, false); err == nil {
		t.Fatal("expected create write error")
	}
	if _, err := NewOpnsenseService().ApplyUnboundOverride(context.Background(), wopts, OpnsenseUnboundOverrideRequest{Hostname: "nas", Domain: "home.example", IP: "10.0.40.11"}, false); err == nil {
		t.Fatal("expected update write error")
	}
	if _, err := NewOpnsenseService().ApplyUnboundOverride(context.Background(), wopts, OpnsenseUnboundOverrideRequest{UUID: "h1", Delete: true}, false); err == nil {
		t.Fatal("expected delete write error")
	}

	reconfFail := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "searchHostOverride"):
			testutil.WriteBody(w, `{"total":0,"rows":[]}`)
		case strings.Contains(r.URL.Path, "reconfigure"):
			w.WriteHeader(http.StatusInternalServerError)
		default:
			testutil.WriteBody(w, `{"result":"saved","uuid":"h-new"}`)
		}
	})
	if _, err := NewOpnsenseService().ApplyUnboundOverride(context.Background(), opnsenseOptions(reconfFail), OpnsenseUnboundOverrideRequest{Hostname: "nas", Domain: "home.example", IP: "10.0.40.10"}, false); err == nil {
		t.Fatal("expected reconfigure error")
	}
}

func TestOpnsenseServiceVLAN_Errors(t *testing.T) {
	failAll := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	opts := opnsenseOptions(failAll)
	if _, err := NewOpnsenseService().ListVLANs(context.Background(), opts); err == nil {
		t.Fatal("expected list error")
	}
	if _, err := NewOpnsenseService().PlanVLAN(context.Background(), opts, OpnsenseVLANRequest{Parent: "igb0", Tag: 10}); err == nil {
		t.Fatal("expected vlan plan fetch error")
	}
	if _, err := NewOpnsenseService().PlanVLAN(context.Background(), opts, OpnsenseVLANRequest{Kind: "bridge", UUID: "b1", Members: []string{"igb0"}}); err == nil {
		t.Fatal("expected bridge plan fetch error")
	}
	if _, err := NewOpnsenseService().ApplyVLAN(context.Background(), opts, OpnsenseVLANRequest{Parent: "igb0", Tag: 10}, false); err == nil {
		t.Fatal("expected apply plan error")
	}

	writeFail := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "vlan_settings/search_item"):
			testutil.WriteBody(w, `{"total":1,"rows":[{"uuid":"v1","if":"igb0","tag":"60","descr":"iot"}]}`)
		case strings.Contains(r.URL.Path, "bridge_settings/search_item"):
			testutil.WriteBody(w, `{"total":1,"rows":[{"uuid":"b1","members":"igb0"}]}`)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	})
	wopts := opnsenseOptions(writeFail)
	if _, err := NewOpnsenseService().ApplyVLAN(context.Background(), wopts, OpnsenseVLANRequest{Parent: "igb0", Tag: 70}, false); err == nil {
		t.Fatal("expected create write error")
	}
	if _, err := NewOpnsenseService().ApplyVLAN(context.Background(), wopts, OpnsenseVLANRequest{Parent: "igb0", Tag: 60, Description: "x"}, false); err == nil {
		t.Fatal("expected update write error")
	}
	if _, err := NewOpnsenseService().ApplyVLAN(context.Background(), wopts, OpnsenseVLANRequest{UUID: "v1", Delete: true}, false); err == nil {
		t.Fatal("expected delete write error")
	}
	if _, err := NewOpnsenseService().ApplyVLAN(context.Background(), wopts, OpnsenseVLANRequest{Kind: "bridge", UUID: "b1", Members: []string{"igb0", "igb1"}}, false); err == nil {
		t.Fatal("expected bridge write error")
	}

	reconfFail := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "search_item"):
			if strings.Contains(r.URL.Path, "bridge") {
				testutil.WriteBody(w, `{"total":1,"rows":[{"uuid":"b1","members":"igb0"}]}`)
				return
			}
			testutil.WriteBody(w, `{"total":0,"rows":[]}`)
		case strings.Contains(r.URL.Path, "reconfigure"):
			w.WriteHeader(http.StatusInternalServerError)
		default:
			testutil.WriteBody(w, `{"result":"saved","uuid":"v-new"}`)
		}
	})
	ropts := opnsenseOptions(reconfFail)
	if _, err := NewOpnsenseService().ApplyVLAN(context.Background(), ropts, OpnsenseVLANRequest{Parent: "igb0", Tag: 80}, false); err == nil {
		t.Fatal("expected vlan reconfigure error")
	}
	if _, err := NewOpnsenseService().ApplyVLAN(context.Background(), ropts, OpnsenseVLANRequest{Kind: "bridge", UUID: "b1", Members: []string{"igb0", "igb1"}}, false); err == nil {
		t.Fatal("expected bridge reconfigure error")
	}
}

func TestOpnsenseServicePlanApplyFilter(t *testing.T) {
	ts := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "filter/search_rule"):
			testutil.WriteBody(w, `{"total":1,"rows":[{"uuid":"r1","enabled":"1","action":"block","description":"isolate","source_net":"lan","destination_net":"iot"}]}`)
		case strings.Contains(r.URL.Path, "alias/search_item"):
			testutil.WriteBody(w, `{"total":1,"rows":[{"uuid":"a1","name":"iot_net","type":"network","address":"10.0.60.0/24","enabled":"1"}]}`)
		case strings.Contains(r.URL.Path, "add_"):
			testutil.WriteBody(w, `{"result":"saved","uuid":"new"}`)
		default:
			testutil.WriteBody(w, `{"result":"saved"}`)
		}
	})
	svc := NewOpnsenseService()
	ctx := context.Background()
	opts := opnsenseOptions(ts)
	unchanged, err := svc.PlanFilter(ctx, opts, OpnsenseFilterRequest{Name: "isolate", Action: "block", Source: "lan", Destination: "iot", Enabled: true})
	if err != nil || unchanged.Action != "unchanged" {
		t.Fatalf("unchanged = %+v %v", unchanged, err)
	}
	create, err := svc.PlanFilter(ctx, opts, OpnsenseFilterRequest{Action: "block", Source: "guest", Destination: "iot", Enabled: true})
	if err != nil || create.Action != "create" {
		t.Fatalf("create = %+v %v", create, err)
	}
	dry, err := svc.ApplyFilter(ctx, opts, OpnsenseFilterRequest{Action: "block", Source: "guest", Destination: "iot"}, true)
	if err != nil || !dry.DryRun {
		t.Fatalf("dry = %+v %v", dry, err)
	}
	created, err := svc.ApplyFilter(ctx, opts, OpnsenseFilterRequest{Action: "block", Source: "guest", Destination: "iot", Enabled: true}, false)
	if err != nil || created.Outcome != "created" {
		t.Fatalf("created = %+v %v", created, err)
	}
	aliasCreate, err := svc.PlanFilter(ctx, opts, OpnsenseFilterRequest{Kind: "alias", Name: "guest_net", Addresses: []string{"10.0.70.0/24"}, Enabled: true})
	if err != nil || aliasCreate.Action != "create" {
		t.Fatalf("alias create = %+v %v", aliasCreate, err)
	}
	aliasApplied, err := svc.ApplyFilter(ctx, opts, OpnsenseFilterRequest{Kind: "alias", Name: "guest_net", Addresses: []string{"10.0.70.0/24"}, Enabled: true}, false)
	if err != nil || aliasApplied.Outcome != "created" {
		t.Fatalf("alias apply = %+v %v", aliasApplied, err)
	}
	if _, err := svc.PlanFilter(ctx, opts, OpnsenseFilterRequest{}); err == nil {
		t.Fatal("expected source/destination required")
	}
	upd, err := svc.PlanFilter(ctx, opts, OpnsenseFilterRequest{Name: "isolate", Action: "reject", Source: "lan", Destination: "iot", Enabled: true})
	if err != nil || upd.Action != "update" {
		t.Fatalf("update = %+v %v", upd, err)
	}
	updated, err := svc.ApplyFilter(ctx, opts, OpnsenseFilterRequest{Name: "isolate", Action: "reject", Source: "lan", Destination: "iot", Enabled: true}, false)
	if err != nil || updated.Outcome != "updated" {
		t.Fatalf("updated apply = %+v %v", updated, err)
	}
	del, err := svc.PlanFilter(ctx, opts, OpnsenseFilterRequest{Name: "isolate", Delete: true})
	if err != nil || del.Action != "delete" {
		t.Fatalf("delete = %+v %v", del, err)
	}
	deleted, err := svc.ApplyFilter(ctx, opts, OpnsenseFilterRequest{Name: "isolate", Delete: true}, false)
	if err != nil || deleted.Outcome != "deleted" {
		t.Fatalf("deleted apply = %+v %v", deleted, err)
	}
	aliasSame, err := svc.PlanFilter(ctx, opts, OpnsenseFilterRequest{Kind: "alias", Name: "iot_net", AliasType: "network", Addresses: []string{"10.0.60.0/24"}, Enabled: true})
	if err != nil || aliasSame.Action != "unchanged" {
		t.Fatalf("alias unchanged = %+v %v", aliasSame, err)
	}
	aliasUpd, err := svc.PlanFilter(ctx, opts, OpnsenseFilterRequest{Kind: "alias", Name: "iot_net", Addresses: []string{"10.0.60.0/24", "10.0.61.0/24"}, Enabled: true})
	if err != nil || aliasUpd.Action != "update" {
		t.Fatalf("alias update = %+v %v", aliasUpd, err)
	}
	aliasUpdated, err := svc.ApplyFilter(ctx, opts, OpnsenseFilterRequest{Kind: "alias", Name: "iot_net", Addresses: []string{"10.0.60.0/24", "10.0.61.0/24"}, Enabled: true}, false)
	if err != nil || aliasUpdated.Outcome != "updated" {
		t.Fatalf("alias updated apply = %+v %v", aliasUpdated, err)
	}
	aliasDel, err := svc.ApplyFilter(ctx, opts, OpnsenseFilterRequest{Kind: "alias", Name: "iot_net", Delete: true}, false)
	if err != nil || aliasDel.Outcome != "deleted" {
		t.Fatalf("alias delete = %+v %v", aliasDel, err)
	}
	if _, err := svc.PlanFilter(ctx, opts, OpnsenseFilterRequest{Kind: "alias"}); err == nil {
		t.Fatal("expected alias name required")
	}
}

func TestOpnsenseServiceFilter_Errors(t *testing.T) {
	fail := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	opts := opnsenseOptions(fail)
	if _, err := NewOpnsenseService().PlanFilter(context.Background(), opts, OpnsenseFilterRequest{Source: "lan", Destination: "iot"}); err == nil {
		t.Fatal("expected filter list error")
	}
	if _, err := NewOpnsenseService().PlanFilter(context.Background(), opts, OpnsenseFilterRequest{Kind: "alias", Name: "x"}); err == nil {
		t.Fatal("expected alias list error")
	}

	listed := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "filter/search_rule"):
			testutil.WriteBody(w, `{"total":1,"rows":[{"uuid":"r1","enabled":"1","action":"block","description":"isolate","source_net":"lan","destination_net":"iot"}]}`)
		case strings.Contains(r.URL.Path, "alias/search_item"):
			testutil.WriteBody(w, `{"total":1,"rows":[{"uuid":"a1","name":"iot_net","type":"network","address":"10.0.60.0/24","enabled":"1"}]}`)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	})
	lopts := opnsenseOptions(listed)
	svc := NewOpnsenseService()
	miss, err := svc.PlanFilter(context.Background(), lopts, OpnsenseFilterRequest{Name: "nope", Delete: true})
	if err != nil || miss.Action != "unchanged" {
		t.Fatalf("filter delete miss = %+v %v", miss, err)
	}
	amiss, err := svc.PlanFilter(context.Background(), lopts, OpnsenseFilterRequest{Kind: "alias", Name: "nope", Delete: true})
	if err != nil || amiss.Action != "unchanged" {
		t.Fatalf("alias delete miss = %+v %v", amiss, err)
	}
	if _, err := svc.ApplyFilter(context.Background(), lopts, OpnsenseFilterRequest{Name: "isolate", Action: "reject", Source: "lan", Destination: "iot", Enabled: true}, false); err == nil {
		t.Fatal("expected filter update write error")
	}
	if _, err := svc.ApplyFilter(context.Background(), lopts, OpnsenseFilterRequest{Name: "isolate", Delete: true}, false); err == nil {
		t.Fatal("expected filter delete write error")
	}
	if _, err := svc.ApplyFilter(context.Background(), lopts, OpnsenseFilterRequest{Kind: "alias", Name: "iot_net", Addresses: []string{"10.0.99.0/24"}, Enabled: true}, false); err == nil {
		t.Fatal("expected alias update write error")
	}
	if _, err := svc.ApplyFilter(context.Background(), lopts, OpnsenseFilterRequest{Kind: "alias", Name: "iot_net", Delete: true}, false); err == nil {
		t.Fatal("expected alias delete write error")
	}
	if _, err := svc.ApplyFilter(context.Background(), lopts, OpnsenseFilterRequest{Action: "block", Source: "guest", Destination: "iot", Enabled: true}, false); err == nil {
		t.Fatal("expected filter create write error")
	}
}
