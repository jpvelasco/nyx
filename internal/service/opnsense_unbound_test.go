package service

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/testutil"
	"net/http"
)

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

// TestOpnsenseServiceUnboundPartialUUIDUpdatePreservesIdentity reproduces
// #182: a UUID-only update request must resolve its effective payload from
// the existing record for BOTH plan and apply — the apply payload keeps
// the existing hostname/domain instead of sending empty strings.
func TestOpnsenseServiceUnboundPartialUUIDUpdatePreservesIdentity(t *testing.T) {
	var setBodies []string
	ts := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "setHostOverride") {
			body, _ := io.ReadAll(r.Body)
			setBodies = append(setBodies, string(body))
		}
		switch {
		case strings.Contains(r.URL.Path, "searchHostOverride"):
			testutil.WriteBody(w, `{"total":1,"rows":[{"uuid":"override-fixture","hostname":"nas","domain":"home.example","ip":"10.0.40.1"}]}`)
		default:
			testutil.WriteBody(w, `{"result":"saved"}`)
		}
	})
	svc := NewOpnsenseService()
	ctx := context.Background()
	opts := opnsenseOptions(ts)

	// Plan with only UUID + new IP: the plan must resolve the effective
	// identity and surface it.
	plan, err := svc.PlanUnboundOverride(ctx, opts, OpnsenseUnboundOverrideRequest{UUID: "override-fixture", IP: "10.0.50.1"})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if plan.Action != "update" {
		t.Fatalf("plan action = %q, want update", plan.Action)
	}
	if plan.Hostname != "nas" || plan.Domain != "home.example" {
		t.Errorf("plan surfaced identity = %q/%q, want nas/home.example", plan.Hostname, plan.Domain)
	}

	// Apply the same partial request: the posted payload must carry the
	// resolved identity, never empty hostname/domain.
	if _, err := svc.ApplyUnboundOverride(ctx, opts, OpnsenseUnboundOverrideRequest{UUID: "override-fixture", IP: "10.0.50.1"}, false); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(setBodies) == 0 {
		t.Fatal("apply issued no setHostOverride")
	}
	joined := strings.Join(setBodies, "\n")
	if !strings.Contains(joined, "\"nas\"") || !strings.Contains(joined, "\"home.example\"") {
		t.Errorf("apply payload lost the identity fields: %s", joined)
	}
	if strings.Contains(joined, `"hostname":""`) || strings.Contains(joined, `"domain":""`) {
		t.Errorf("apply payload sent an empty identity field: %s", joined)
	}
}
