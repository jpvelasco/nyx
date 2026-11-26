package service

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/testutil"
)

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

// TestOpnsenseServicePlanDHCPMacAndHostnameChanges reproduces #183: a
// MAC-only dnsmasq host change and a hostname-only Kea reservation change
// must plan as updates, not unchanged.
func TestOpnsenseServicePlanDHCPMacAndHostnameChanges(t *testing.T) {
	ts := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "dnsmasq/settings/get"):
			testutil.WriteBody(w, `{"dnsmasq":{"enable":"1","dhcp":{"range":{},"host":{"host-fixture":{"host":"nas","ip":"10.0.40.1","hwaddr":"02:00:00:00:00:01"}}}}}`)
		case strings.Contains(r.URL.Path, "kea/service/status"):
			testutil.WriteBody(w, `{"running":true}`)
		case strings.Contains(r.URL.Path, "kea/dhcpv4/search_reservation"):
			testutil.WriteBody(w, `{"total":1,"rows":[{"uuid":"res-fixture","ip":"10.0.40.1","mac":"02:00:00:00:00:01","hostname":"nas"}]}`)
		default:
			testutil.WriteBody(w, `{"result":"saved"}`)
		}
	})
	opts := opnsenseOptions(ts)
	svc := NewOpnsenseService()

	// MAC-only dnsmasq host change.
	macPlan, err := svc.PlanDHCP(context.Background(), opts, OpnsenseDHCPRequest{
		Kind: "host", UUID: "host-fixture", Hostname: "nas", IP: "10.0.40.1", MAC: "02:00:00:00:00:02",
	})
	if err != nil {
		t.Fatalf("dnsmasq mac plan: %v", err)
	}
	if macPlan.Action != "update" {
		t.Errorf("MAC-only dnsmasq change planned %q, want update", macPlan.Action)
	}

	// Same MAC with different case must still be unchanged.
	samePlan, err := svc.PlanDHCP(context.Background(), opts, OpnsenseDHCPRequest{
		Kind: "host", UUID: "host-fixture", Hostname: "nas", IP: "10.0.40.1", MAC: "02:00:00:00:00:01",
	})
	if err != nil {
		t.Fatalf("dnsmasq same-mac plan: %v", err)
	}
	if samePlan.Action != "unchanged" {
		t.Errorf("identical MAC planned %q, want unchanged (MAC comparison is normalized)", samePlan.Action)
	}

}

// TestOpnsenseServicePlanKeaHostnameChange covers the Kea reservation
// side of #183 against a Kea-only fake controller.
func TestOpnsenseServicePlanKeaHostnameChange(t *testing.T) {
	ts := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "kea/service/status"):
			testutil.WriteBody(w, `{"running":true}`)
		case strings.Contains(r.URL.Path, "kea/dhcpv4/search_reservation"):
			testutil.WriteBody(w, `{"total":1,"rows":[{"uuid":"res-fixture","ip":"10.0.40.1","mac":"02:00:00:00:00:01","hostname":"nas"}]}`)
		default:
			testutil.WriteBody(w, `{"result":"saved"}`)
		}
	})
	opts := opnsenseOptions(ts)
	svc := NewOpnsenseService()

	// Hostname-only Kea reservation change.
	namePlan, err := svc.PlanDHCP(context.Background(), opts, OpnsenseDHCPRequest{
		Kind: "reservation", UUID: "res-fixture", IP: "10.0.40.1", MAC: "02:00:00:00:00:01", Hostname: "backup",
	})
	if err != nil {
		t.Fatalf("kea hostname plan: %v", err)
	}
	if namePlan.Action != "update" {
		t.Errorf("hostname-only Kea change planned %q, want update", namePlan.Action)
	}

	// Identical hostname keeps unchanged.
	identical, err := svc.PlanDHCP(context.Background(), opts, OpnsenseDHCPRequest{
		Kind: "reservation", UUID: "res-fixture", IP: "10.0.40.1", MAC: "02:00:00:00:00:01", Hostname: "nas",
	})
	if err != nil {
		t.Fatalf("kea identical plan: %v", err)
	}
	if identical.Action != "unchanged" {
		t.Errorf("identical Kea reservation planned %q, want unchanged", identical.Action)
	}
}

func TestDHCPAndRouterAdvertisementServiceVisibility(t *testing.T) {
	for _, valid := range []bool{true, false} {
		ts := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			switch {
			case !valid:
				w.WriteHeader(http.StatusForbidden)
			case r.URL.Path == "/api/kea/service/status":
				testutil.WriteBody(w, `{"running":false}`)
			case r.URL.Path == "/api/radvd/settings/search_entry":
				testutil.WriteBody(w, `{"rows":[{"interface":"opt1","enabled":"1"}]}`)
			default:
				t.Error("unexpected DHCP service fixture request")
				w.WriteHeader(http.StatusNotFound)
			}
		})
		svc := NewOpnsenseService()
		opts := opnsenseOptions(ts)
		kea, err := svc.GetKeaStatus(t.Context(), opts)
		if (err == nil) != valid || (valid && (len(kea) != 1 || kea["running"])) {
			t.Fatalf("Kea result %+v, %v", kea, err)
		}
		ra, err := svc.ListRouterAdvertisements(t.Context(), opts)
		if (err == nil) != valid || (valid && (len(ra) != 1 || ra[0].State != "enabled")) {
			t.Fatalf("RADVD result %+v, %v", ra, err)
		}
	}
}
