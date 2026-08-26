package service

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/testutil"
)

// opnsenseNatHandlers serves the NAT-observation endpoints. unexpected
// records any path outside the known set.
func opnsenseNatHandlers(unexpected *strings.Builder) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/firewall/filter_base/get":
			testutil.WriteBody(w, `{"general":{"snat_mode":"disabled"}}`)
		case "/api/firewall/d_nat/search_rule":
			testutil.WriteBody(w, `{"total":1,"rows":[
				{"rule":[{"uuid":"n1","interface":["wan"],"protocol":"tcp","source":{"network":"any"},"destination":{"network":"203.0.113.1","port":"443"},"local-port":"443","disabled":false,"descr":"web-iot"}]}]}`)
		case "/api/firewall/one_to_one/search_rule":
			testutil.WriteBody(w, `{"total":1,"rows":[
				{"rule":[{"uuid":"o1","interface":["wan"],"type":"binat","source":{"network":"10.0.40.20"},"destination":{"network":"203.0.113.20"},"disabled":false,"descr":"nas passthrough"}]}]}`)
		case "/api/firewall/source_nat/search_rule":
			testutil.WriteBody(w, `{"total":1,"rows":[
				{"rule":[{"uuid":"s1","interface":["lan"],"source":{"network":"10.0.10.0/24"},"destination":{"network":"any"},"target":"203.0.113.100","disabled":false,"descr":"force snat"}]}]}`)
		case "/api/firewall/alias/search_item":
			testutil.WriteBody(w, `{"total":2,"rows":[
				{"uuid":"a1","name":"WEB","type":"host","address":"10.0.40.10","description":"web server","details":["10.0.40.10"],"enabled":"1"},
				{"uuid":"a2","name":"LAN-SERVERS","type":"net","address":"10.0.40.0/24","description":"server VLAN","details":["10.0.40.0/24"],"enabled":"0"}]}`)
		case "/api/firewall/filter/get_rule/ru":
			testutil.WriteBody(w, `{"uuid":"ru","enabled":"1","interface":["lan"],"protocol":"any","source_net":"10.0.10.0/24","destination_net":"any","description":"allow lan"}`)
		default:
			unexpected.WriteString(r.URL.Path + "\n")
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func TestOpnsenseServiceGetNAT(t *testing.T) {
	var unexpected strings.Builder
	ts := opnsenseTestServer(t, opnsenseNatHandlers(&unexpected))
	nat, err := NewOpnsenseService().GetNAT(context.Background(), opnsenseOptions(ts))
	if err != nil {
		t.Fatalf("GetNAT: %v", err)
	}
	if got := unexpected.String(); got != "" {
		t.Errorf("unexpected paths: %s", got)
	}
	if nat.OutboundNatMode != "disabled" {
		t.Errorf("outbound mode = %q, want disabled", nat.OutboundNatMode)
	}
	if len(nat.PortForwardRules) != 1 || len(nat.OneToOneRules) != 1 || len(nat.SourceNatRules) != 1 {
		t.Fatalf("rule counts = %d/%d/%d, want 1/1/1",
			len(nat.PortForwardRules), len(nat.OneToOneRules), len(nat.SourceNatRules))
	}
	pf := nat.PortForwardRules[0]
	if pf.UUID != "n1" || !pf.Enabled || pf.Protocol != "TCP" || pf.Source != "any" ||
		pf.Destination != "203.0.113.1" || pf.Port != "443" || pf.LocalPort != "443" || pf.Label != "web-iot" {
		t.Errorf("port forward = %+v", pf)
	}
	o2o := nat.OneToOneRules[0]
	if o2o.UUID != "o1" || o2o.Type != "binat" || o2o.Source != "10.0.40.20" || o2o.Destination != "203.0.113.20" {
		t.Errorf("one-to-one = %+v", o2o)
	}
	snat := nat.SourceNatRules[0]
	if snat.UUID != "s1" || snat.Target != "203.0.113.100" {
		t.Errorf("source nat = %+v", snat)
	}
}

// GetNAT must fail hard on any read failure — a partial NAT picture would
// mislead the double-NAT verdict.
func TestOpnsenseServiceGetNAT_HardError(t *testing.T) {
	ts := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/firewall/filter_base/get":
			testutil.WriteBody(w, `{"general":{"snat_mode":"disabled"}}`)
		case "/api/firewall/d_nat/search_rule":
			w.WriteHeader(http.StatusNotFound)
			testutil.WriteBody(w, `{}`)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	_, err := NewOpnsenseService().GetNAT(context.Background(), opnsenseOptions(ts))
	if err == nil {
		t.Fatal("expected d_nat 404 to propagate")
	}
	if !strings.Contains(err.Error(), "fetching port forward rules") {
		t.Errorf("error = %v, want port-forward fetch prefix", err)
	}
}

func TestOpnsenseServiceListNATRuleSets(t *testing.T) {
	var unexpected strings.Builder
	ts := opnsenseTestServer(t, opnsenseNatHandlers(&unexpected))
	svc := NewOpnsenseService()
	ctx := context.Background()
	opts := opnsenseOptions(ts)

	pf, err := svc.ListPortForwardRules(ctx, opts)
	if err != nil {
		t.Fatalf("ListPortForwardRules: %v", err)
	}
	if len(pf) != 1 || pf[0].UUID != "n1" {
		t.Errorf("pf = %+v", pf)
	}

	o2o, err := svc.ListOneToOneRules(ctx, opts)
	if err != nil {
		t.Fatalf("ListOneToOneRules: %v", err)
	}
	if len(o2o) != 1 || o2o[0].Type != "binat" {
		t.Errorf("o2o = %+v", o2o)
	}

	snat, err := svc.ListSourceNatRules(ctx, opts)
	if err != nil {
		t.Fatalf("ListSourceNatRules: %v", err)
	}
	if len(snat) != 1 || snat[0].Target != "203.0.113.100" {
		t.Errorf("snat = %+v", snat)
	}

	if got := unexpected.String(); got != "" {
		t.Errorf("unexpected paths: %s", got)
	}
}

func TestOpnsenseServiceListAliases(t *testing.T) {
	var unexpected strings.Builder
	ts := opnsenseTestServer(t, opnsenseNatHandlers(&unexpected))
	aliases, err := NewOpnsenseService().ListAliases(context.Background(), opnsenseOptions(ts))
	if err != nil {
		t.Fatalf("ListAliases: %v", err)
	}
	if len(aliases) != 2 {
		t.Fatalf("len = %d, want 2", len(aliases))
	}
	if aliases[0].Name != "WEB" || aliases[0].Addresses[0] != "10.0.40.10" || aliases[0].Disabled {
		t.Errorf("alias[0] = %+v", aliases[0])
	}
	if aliases[1].Name != "LAN-SERVERS" || !aliases[1].Disabled {
		t.Errorf("alias[1] = %+v (want enabled=0 mapped to disabled)", aliases[1])
	}
}

func TestOpnsenseServiceGetOutboundNatModeAndRule(t *testing.T) {
	var unexpected strings.Builder
	ts := opnsenseTestServer(t, opnsenseNatHandlers(&unexpected))
	svc := NewOpnsenseService()
	ctx := context.Background()
	opts := opnsenseOptions(ts)

	mode, err := svc.GetOutboundNatMode(ctx, opts)
	if err != nil {
		t.Fatalf("GetOutboundNatMode: %v", err)
	}
	if mode != "disabled" {
		t.Errorf("mode = %q, want disabled", mode)
	}

	rule, err := svc.GetFirewallRule(ctx, opts, "ru")
	if err != nil {
		t.Fatalf("GetFirewallRule: %v", err)
	}
	if rule.UUID != "ru" || !rule.Enabled || rule.Label != "allow lan" {
		t.Errorf("rule = %+v", rule)
	}
}
