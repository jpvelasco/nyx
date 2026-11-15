package service

import (
	"context"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/testutil"
	"net/http"
)

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
