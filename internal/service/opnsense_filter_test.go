package service

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/testutil"
)

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

func TestOpnsenseServiceListFirewallRules_Error(t *testing.T) {
	ts := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	_, err := NewOpnsenseService().ListFirewallRules(context.Background(), opnsenseOptions(ts))
	if err == nil || !strings.Contains(err.Error(), "unexpected status 500") {
		t.Fatalf("ListFirewallRules error = %v, want unexpected status 500", err)
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

func TestScopedDNSFilter(t *testing.T) {
	const address = "10.0.40.1"
	req := OpnsenseFilterRequest{Source: "iot", Destination: address, Interface: "opt3", Action: "pass", Protocol: "udp", DestinationPort: "53", Direction: "in", AddressFamily: "ipv4", Enabled: true}
	rules := []map[string]string{}
	writes := 0
	ts := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/firewall/filter/search_rule":
			_ = json.NewEncoder(w).Encode(map[string]any{"total": len(rules), "rows": rules})
		case "/api/firewall/filter/add_rule":
			var payload struct {
				Rule map[string]string `json:"rule"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Error(err)
			}
			rule := payload.Rule
			if rule["destination_net"] != address || rule["destination_port"] != "53" || rule["protocol"] != "udp" || rule["direction"] != "in" || rule["ipprotocol"] != "inet" {
				t.Error("DNS scope lost")
			}
			writes++
			rule["uuid"] = "dns-rule"
			rules = append(rules, rule)
			testutil.WriteBody(w, `{"result":"saved","uuid":"dns-rule"}`)
		case "/api/firewall/filter/apply":
			testutil.WriteBody(w, `{"status":"ok"}`)
		default:
			http.NotFound(w, r)
		}
	})
	s := NewOpnsenseService()
	opts := opnsenseOptions(ts)
	res, err := s.ApplyFilter(t.Context(), opts, req, false)
	if err != nil || res.Outcome != "created" {
		t.Fatalf("apply %v %v", res, err)
	}
	req.Name = "local DNS"
	again, err := s.ApplyFilter(t.Context(), opts, req, false)
	if err != nil || again.Outcome != "unchanged" || writes != 1 {
		t.Fatalf("repeat %v %v writes=%d", again, err, writes)
	}
}

func TestFilterSelectorValidation(t *testing.T) {
	base := OpnsenseFilterRequest{Source: "iot", Destination: "resolver", Interface: "opt3", Protocol: "udp", SourcePort: "1000-2000", DestinationPort: "53", Direction: "in", AddressFamily: "ipv4"}
	if err := base.validateSelectors(); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []func(*OpnsenseFilterRequest){func(r *OpnsenseFilterRequest) { r.Source = "" }, func(r *OpnsenseFilterRequest) { r.DestinationPort = "0" }, func(r *OpnsenseFilterRequest) { r.SourcePort = "2000-1000" }, func(r *OpnsenseFilterRequest) { r.DestinationPort = "65536" }, func(r *OpnsenseFilterRequest) { r.Protocol = "icmp" }, func(r *OpnsenseFilterRequest) { r.Direction = "sideways" }, func(r *OpnsenseFilterRequest) { r.AddressFamily = "v7" }, func(r *OpnsenseFilterRequest) { r.Kind = "alias" }} {
		bad := base
		invalid(&bad)
		if err := bad.validateSelectors(); err == nil {
			t.Fatal("accepted unsupported selectors")
		}
	}
}

func TestScopedFilterRequiresRestrictedSelectorsOnUpdate(t *testing.T) {
	ts := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/search_rule") {
			t.Error("unexpected write")
			http.NotFound(w, r)
			return
		}
		testutil.WriteBody(w, `{"total":1,"rows":[{"uuid":"dns","enabled":"1","action":"pass","interface":"opt3","source_net":"iot","destination_net":"resolver","protocol":"udp","source_port":"2000","destination_port":"53","direction":"in"}]}`)
	})
	req := OpnsenseFilterRequest{UUID: "dns", Action: "pass", Source: "iot", Destination: "resolver", Protocol: "udp", DestinationPort: "53", Interface: "opt3", Enabled: true}
	if _, err := NewOpnsenseService().ApplyFilter(t.Context(), opnsenseOptions(ts), req, false); err == nil || !strings.Contains(err.Error(), "omitted selector") {
		t.Fatalf("implicit widening: %v", err)
	}
	req.SourcePort = "2000"
	res, err := NewOpnsenseService().ApplyFilter(t.Context(), opnsenseOptions(ts), req, false)
	if err != nil || res.Outcome != "unchanged" {
		t.Fatalf("explicit selection: %+v %v", res, err)
	}
}
