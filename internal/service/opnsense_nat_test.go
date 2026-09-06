package service

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/providers"
	opnsenseprovider "github.com/jpvelasco/nyx/internal/providers/opnsense"
	"github.com/jpvelasco/nyx/internal/testutil"
)

// natProviderRegistered pins the OPNsense provider in the registry for the
// PlanNat/ApplyNat tests, which resolve the mutation surface by provider
// name (mirrors the Omada mutation rail test).
func natProviderRegistered(t *testing.T) {
	t.Helper()
	providers.Reset()
	t.Cleanup(func() {
		providers.Reset()
		_ = providers.Register(&opnsenseprovider.Provider{})
	})
	if err := providers.Register(&opnsenseprovider.Provider{}); err != nil {
		t.Fatalf("Register opnsense: %v", err)
	}
}

// opnsenseNatHandlers serves the NAT-observation endpoints. unexpected
// records any path outside the known set.
func opnsenseNatHandlers(unexpected *strings.Builder) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/firewall/source_nat/get":
			testutil.WriteBody(w, testutil.SNATModeBody("disabled"))
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
		case "/api/firewall/source_nat/get":
			testutil.WriteBody(w, testutil.SNATModeBody("disabled"))
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

// Each per-read method must wrap its failure with the fetch prefix so an
// agent can name the broken controller endpoint; GetFirewallRule passes the
// client error through unwrapped.
func TestOpnsenseServiceNatReads_Failures(t *testing.T) {
	// Every path 404s; each call fails on its own read with its own prefix.
	ts := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	svc := NewOpnsenseService()
	ctx := context.Background()
	opts := opnsenseOptions(ts)

	if _, err := svc.ListPortForwardRules(ctx, opts); err == nil || !strings.Contains(err.Error(), "fetching port forward rules") {
		t.Errorf("ListPortForwardRules error = %v", err)
	}
	if _, err := svc.ListOneToOneRules(ctx, opts); err == nil || !strings.Contains(err.Error(), "fetching one-to-one rules") {
		t.Errorf("ListOneToOneRules error = %v", err)
	}
	if _, err := svc.ListSourceNatRules(ctx, opts); err == nil || !strings.Contains(err.Error(), "fetching source NAT rules") {
		t.Errorf("ListSourceNatRules error = %v", err)
	}
	if _, err := svc.ListAliases(ctx, opts); err == nil || !strings.Contains(err.Error(), "fetching aliases") {
		t.Errorf("ListAliases error = %v", err)
	}
	if _, err := svc.GetOutboundNatMode(ctx, opts); err == nil || !strings.Contains(err.Error(), "fetching outbound NAT mode") {
		t.Errorf("GetOutboundNatMode error = %v", err)
	}
	// GetFirewallRule surfaces the client error unwrapped.
	if _, err := svc.GetFirewallRule(ctx, opts, "ru"); err == nil || !strings.Contains(err.Error(), "resource not found") {
		t.Errorf("GetFirewallRule error = %v, want resource not found", err)
	}
}

// GetNAT failures after the mode read must name the failing rule set so an
// agent can pin the broken endpoint.
func TestOpnsenseServiceGetNAT_LaterReadFailures(t *testing.T) {
	cases := []struct {
		name, failPath, want string
	}{
		{"mode", "/api/firewall/source_nat/get", "fetching outbound NAT mode"},
		{"one-to-one", "/api/firewall/one_to_one/search_rule", "fetching one-to-one rules"},
		{"source nat", "/api/firewall/source_nat/search_rule", "fetching source NAT rules"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var unexpected strings.Builder
			ts := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == tc.failPath {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				opnsenseNatHandlers(&unexpected)(w, r)
			})
			_, err := NewOpnsenseService().GetNAT(context.Background(), opnsenseOptions(ts))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("GetNAT error = %v, want %q prefix", err, tc.want)
			}
		})
	}
}

// PlanNat/ApplyNat route through the provider's NAT mutation surface; the
// httptest fixtures below exercise the service→provider→client seam end to
// end (guards pass with mode "automatic").
func TestOpnsenseServicePlanNat(t *testing.T) {
	natProviderRegistered(t)
	ts := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/firewall/source_nat/get":
			testutil.WriteBody(w, testutil.SNATModeBody("automatic"))
		default:
			testutil.WriteBody(w, `{"total":0,"rows":[]}`)
		}
	})
	plan, err := NewOpnsenseService().PlanNat(context.Background(), opnsenseOptions(ts), OpnsenseNatApplyRequest{
		Operation: "port_forward",
		Spec:      OpnsenseNatRuleSpec{Destination: "10.0.40.10", Port: "443", Target: "10.0.40.20", Label: "web"},
	})
	if err != nil {
		t.Fatalf("PlanNat: %v", err)
	}
	if plan.Provider != "opnsense" || !plan.DryRun || plan.Outcome != "would_create" {
		t.Errorf("plan = %+v", plan)
	}
	if len(plan.Endpoints) != 1 || plan.Endpoints[0] != "/firewall/d_nat/add_rule" {
		t.Errorf("endpoints = %v", plan.Endpoints)
	}
}

func TestOpnsenseServiceApplyNat(t *testing.T) {
	natProviderRegistered(t)
	var posts int
	ts := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			posts++
			if r.URL.Path == "/api/firewall/filter/apply" {
				testutil.WriteBody(w, `{"status":"ok"}`)
				return
			}
			testutil.WriteBody(w, `{"result":"saved","uuid":"new-1"}`)
			return
		}
		switch r.URL.Path {
		case "/api/firewall/source_nat/get":
			testutil.WriteBody(w, testutil.SNATModeBody("automatic"))
		default:
			testutil.WriteBody(w, `{"total":0,"rows":[]}`)
		}
	})
	res, err := NewOpnsenseService().ApplyNat(context.Background(), opnsenseOptions(ts), OpnsenseNatApplyRequest{
		Operation: "port_forward",
		DryRun:    false,
		Spec:      OpnsenseNatRuleSpec{Destination: "10.0.40.10", Port: "443", Target: "10.0.40.20", Label: "web"},
	})
	if err != nil {
		t.Fatalf("ApplyNat: %v", err)
	}
	if posts != 2 {
		t.Fatalf("posts = %d, want 2 (add_rule then filter/apply)", posts)
	}
	if res.Provider != "opnsense" || res.Outcome != "created" || res.RuleUUID != "new-1" {
		t.Errorf("result = %+v", res)
	}
}

func TestOpnsenseServiceApplyNat_DryRunZeroPosts(t *testing.T) {
	natProviderRegistered(t)
	var posts int
	ts := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			posts++
		}
		switch r.URL.Path {
		case "/api/firewall/source_nat/get":
			testutil.WriteBody(w, testutil.SNATModeBody("automatic"))
		default:
			testutil.WriteBody(w, `{"total":0,"rows":[]}`)
		}
	})
	res, err := NewOpnsenseService().ApplyNat(context.Background(), opnsenseOptions(ts), OpnsenseNatApplyRequest{
		Operation: "port_forward",
		DryRun:    true,
		Spec:      OpnsenseNatRuleSpec{Destination: "10.0.40.10", Port: "443"},
	})
	if err != nil {
		t.Fatalf("ApplyNat: %v", err)
	}
	if posts != 0 {
		t.Fatalf("posts = %d, want 0 (dry-run lock)", posts)
	}
	if res.Outcome != "unchanged" || !res.DryRun {
		t.Errorf("result = %+v", res)
	}
}

// The topology report must name the provider whose observation failed — a
// silent skip would turn a blind spot into a confidently wrong verdict.
func TestTopologyService_Report_ObservationErrors(t *testing.T) {
	t.Run("omada failure is wrapped", func(t *testing.T) {
		// Unreachable Omada host: the report must fail with an "observing
		// omada" prefix. Omada is observed first, so its failure surfaces
		// before any OPNsense read.
		svc := &TopologyService{Omada: NewOmadaService(), Opnsense: NewOpnsenseService()}
		_, err := svc.Report(context.Background(), TopologyOptions{
			Omada: &OmadaOptions{Host: "https://127.0.0.1:1", ClientID: "a", ClientSecret: "b", SkipTLSVerify: true},
		})
		if err == nil || !strings.Contains(err.Error(), "observing omada") {
			t.Fatalf("Report error = %v, want observing-omada prefix", err)
		}
	})

	t.Run("opnsense failure is wrapped", func(t *testing.T) {
		svc := &TopologyService{Opnsense: NewOpnsenseService()}
		_, err := svc.Report(context.Background(), TopologyOptions{
			Opnsense: &OpnsenseOptions{Host: "https://127.0.0.1:1", APIKey: "k", APISecret: "s", SkipTLSVerify: true},
		})
		if err == nil || !strings.Contains(err.Error(), "observing opnsense") {
			t.Fatalf("Report error = %v, want observing-opnsense prefix", err)
		}
	})

	t.Run("no providers configured", func(t *testing.T) {
		svc := &TopologyService{Omada: NewOmadaService(), Opnsense: NewOpnsenseService()}
		_, err := svc.Report(context.Background(), TopologyOptions{})
		if err == nil || !strings.Contains(err.Error(), "at least one provider") {
			t.Fatalf("Report error = %v, want no-provider guidance", err)
		}
	})
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
