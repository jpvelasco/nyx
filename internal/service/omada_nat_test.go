package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/providers"
	omadaprovider "github.com/jpvelasco/nyx/internal/providers/omada"
)

// natReads is the shared handler for the NAT-observation endpoints NatFacts
// touches. unexpected records any path outside the known set.
func natReads(unexpected *strings.Builder) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			writeOmadaEnvelope(w, 0, `{"accessToken":"tok"}`)
		case "/openapi/v1/abc123/sites":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		case "/openapi/v1/abc123/sites/s1/networks/devices":
			writeOmadaEnvelope(w, 0, `[
				{"id":"d1","name":"GW-CORE","model":"GW-CORE","type":"gateway","mac":"aa:bb:cc:dd:ee:00","ip":"10.0.0.254"},
				{"id":"d2","name":"SW-2428P","model":"SW-2428P","type":"switch","mac":"aa:bb:cc:dd:ee:01","ip":"10.0.0.253"}]`)
		case "/openapi/v1/abc123/sites/s1/nat/port-forwardings":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[
				{"id":"pf1","name":"web","status":true,"from":0,"externalPort":"443","forwardIp":"10.0.40.10","forwardPort":"443","protocol":1,"dMZ":false}]}`)
		case "/openapi/v1/abc123/sites/s1/nat/one-to-one-nat":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[
				{"id":"o1","name":"nas","status":true,"internalIp":"10.0.40.20","externalIp":"203.0.113.20","dmz":false,"description":"nas passthrough"}]}`)
		case "/openapi/v1/abc123/sites/s1/nat/alg":
			writeOmadaEnvelope(w, 0, `{"ftp":true,"h323":false,"pptp":false,"sip":true,"ipSec":false}`)
		case "/openapi/v1/abc123/sites/s1/firewall":
			writeOmadaEnvelope(w, 0, `{"icmp":30,"other":30,"tcpEstablished":86400,"udpOther":30,"broadcastPing":false,"synCookies":true}`)
		default:
			unexpected.WriteString(r.URL.Path + "\n")
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func omadaNatOptions(ts *httptest.Server) OmadaOptions {
	return OmadaOptions{Host: ts.URL, ClientID: "a", ClientSecret: "b", SkipTLSVerify: true}
}

func TestOmadaServiceNatFacts(t *testing.T) {
	var unexpected strings.Builder
	ts := omadaTestServer(t, natReads(&unexpected))
	facts, err := NewOmadaService().NatFacts(context.Background(), omadaNatOptions(ts))
	if err != nil {
		t.Fatalf("NatFacts: %v", err)
	}
	if got := unexpected.String(); got != "" {
		t.Errorf("unexpected paths: %s", got)
	}
	if facts.Site != "HQ" || !facts.HasManagedGateway {
		t.Errorf("site/gateway = %q/%v, want HQ/true", facts.Site, facts.HasManagedGateway)
	}
	if facts.PortForwardRules != 1 || facts.OneToOneRules != 1 {
		t.Errorf("rule counts = %d/%d, want 1/1", facts.PortForwardRules, facts.OneToOneRules)
	}
	if !facts.ALG.FTP || !facts.ALG.SIP || facts.ALG.H323 || facts.ALG.IPsec {
		t.Errorf("alg = %+v, want ftp+sip only", facts.ALG)
	}
	if facts.Firewall.UDPOther != 30 || facts.Firewall.TCPEstablished != 86400 || !facts.Firewall.SynCookies {
		t.Errorf("firewall = %+v", facts.Firewall)
	}
}

func TestOmadaServiceNatFacts_NoGateway(t *testing.T) {
	var unexpected strings.Builder
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/openapi/v1/abc123/sites/s1/networks/devices" {
			writeOmadaEnvelope(w, 0, `[
				{"id":"d2","name":"SW-2428P","model":"SW-2428P","type":"switch","mac":"aa:bb:cc:dd:ee:01","ip":"10.0.0.253"}]`)
			return
		}
		natReads(&unexpected)(w, r)
	})
	facts, err := NewOmadaService().NatFacts(context.Background(), omadaNatOptions(ts))
	if err != nil {
		t.Fatalf("NatFacts: %v", err)
	}
	if facts.HasManagedGateway {
		t.Error("HasManagedGateway = true, want false for switch-only site")
	}
}

// A failure on any read must surface as a hard error with the per-read fetch
// prefix, so an agent can name which controller endpoint broke.
func TestOmadaServiceNatReads_Failures(t *testing.T) {
	cases := []struct {
		name, failPath, want string
	}{
		{"devices", "/openapi/v1/abc123/sites/s1/networks/devices", "fetching devices"},
		{"port forwardings", "/openapi/v1/abc123/sites/s1/nat/port-forwardings", "fetching port forwardings"},
		{"one-to-one", "/openapi/v1/abc123/sites/s1/nat/one-to-one-nat", "fetching one-to-one NAT rules"},
		{"alg", "/openapi/v1/abc123/sites/s1/nat/alg", "fetching ALG settings"},
		{"firewall", "/openapi/v1/abc123/sites/s1/firewall", "fetching firewall settings"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var unexpected strings.Builder
			ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == tc.failPath {
					writeOmadaEnvelope(w, -1010, `null`)
					return
				}
				natReads(&unexpected)(w, r)
			})
			_, err := NewOmadaService().NatFacts(context.Background(), omadaNatOptions(ts))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("NatFacts error = %v, want %q prefix", err, tc.want)
			}
		})
	}

	// Session-establishment failure (login / site select) is returned raw.
	t.Run("session", func(t *testing.T) {
		ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/openapi/authorize/token" {
				writeOmadaEnvelope(w, -44106, `null`) // token mint failed
				return
			}
			w.WriteHeader(http.StatusNotFound)
		})
		if _, err := NewOmadaService().NatFacts(context.Background(), omadaNatOptions(ts)); err == nil {
			t.Fatal("expected session error to propagate")
		}
	})
}

// Per-read service methods must wrap their failures with the same fetch
// prefixes so error reporting is consistent across the API surface.
func TestOmadaServiceListReads_Failures(t *testing.T) {
	cases := []struct {
		name, failPath, want string
	}{
		{"port forwardings", "/openapi/v1/abc123/sites/s1/nat/port-forwardings", "fetching port forwardings"},
		{"one-to-one", "/openapi/v1/abc123/sites/s1/nat/one-to-one-nat", "fetching one-to-one NAT rules"},
		{"alg", "/openapi/v1/abc123/sites/s1/nat/alg", "fetching ALG settings"},
		{"firewall", "/openapi/v1/abc123/sites/s1/firewall", "fetching firewall settings"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/openapi/authorize/token":
					writeOmadaEnvelope(w, 0, `{"accessToken":"tok"}`)
				case "/openapi/v1/abc123/sites":
					writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
				default:
					if r.URL.Path == tc.failPath {
						writeOmadaEnvelope(w, -1010, `null`)
						return
					}
					w.WriteHeader(http.StatusNotFound)
				}
			})
			var (
				err error
				svc = NewOmadaService()
			)
			switch tc.name {
			case "port forwardings":
				_, err = svc.ListPortForwardings(context.Background(), omadaNatOptions(ts))
			case "one-to-one":
				_, err = svc.ListOneToOneNAT(context.Background(), omadaNatOptions(ts))
			case "alg":
				_, err = svc.GetALGSettings(context.Background(), omadaNatOptions(ts))
			default:
				_, err = svc.GetFirewallSettings(context.Background(), omadaNatOptions(ts))
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q prefix", err, tc.want)
			}
		})
	}
}

// A partial NAT picture would mislead the double-NAT verdict, so a failure
// on any read must surface as a hard error.
func TestOmadaServiceNatFacts_HardError(t *testing.T) {
	var unexpected strings.Builder
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/openapi/v1/abc123/sites/s1/nat/alg" {
			writeOmadaEnvelope(w, -1010, `null`)
			return
		}
		natReads(&unexpected)(w, r)
	})
	_, err := NewOmadaService().NatFacts(context.Background(), omadaNatOptions(ts))
	if err == nil {
		t.Fatal("expected ALG failure to propagate")
	}
	if !strings.Contains(err.Error(), "fetching ALG settings") {
		t.Errorf("error = %v, want ALG fetch prefix", err)
	}
}

func TestOmadaServiceListPortForwardings(t *testing.T) {
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			writeOmadaEnvelope(w, 0, `{"accessToken":"tok"}`)
		case "/openapi/v1/abc123/sites":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		case "/openapi/v1/abc123/sites/s1/nat/port-forwardings":
			writeOmadaEnvelope(w, 0, `{"totalRows":2,"data":[
				{"id":"pf1","name":"web","status":true,"from":1,"limitedAddresses":["10.0.10.0/24"],"externalPort":"443","forwardIp":"10.0.40.10","forwardPort":"443","protocol":1,"dMZ":false},
				{"id":"pf2","name":"mail","status":false,"from":0,"externalPort":"25","forwardIp":"10.0.40.11","forwardPort":"25","protocol":0}]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	pfs, err := NewOmadaService().ListPortForwardings(context.Background(), omadaNatOptions(ts))
	if err != nil {
		t.Fatalf("ListPortForwardings: %v", err)
	}
	if len(pfs) != 2 {
		t.Fatalf("len = %d, want 2", len(pfs))
	}
	if pfs[0].Protocol != "TCP" || !pfs[0].Enabled || len(pfs[0].LimitedAddresses) != 1 {
		t.Errorf("pf1 = %+v", pfs[0])
	}
	if pfs[1].Protocol != "ALL" || pfs[1].Enabled {
		t.Errorf("pf2 = %+v", pfs[1])
	}
}

func TestOmadaServiceListOneToOneNAT(t *testing.T) {
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			writeOmadaEnvelope(w, 0, `{"accessToken":"tok"}`)
		case "/openapi/v1/abc123/sites":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		case "/openapi/v1/abc123/sites/s1/nat/one-to-one-nat":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[
				{"id":"o1","name":"nas","status":true,"internalIp":"10.0.40.20","externalIp":"203.0.113.20","dmz":true}]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	rules, err := NewOmadaService().ListOneToOneNAT(context.Background(), omadaNatOptions(ts))
	if err != nil {
		t.Fatalf("ListOneToOneNAT: %v", err)
	}
	if len(rules) != 1 || !rules[0].DMZ || rules[0].InternalIP != "10.0.40.20" {
		t.Errorf("rules = %+v", rules)
	}
}

func TestOmadaServiceGetALGAndFirewall(t *testing.T) {
	var unexpected strings.Builder
	ts := omadaTestServer(t, natReads(&unexpected))
	svc := NewOmadaService()

	alg, err := svc.GetALGSettings(context.Background(), omadaNatOptions(ts))
	if err != nil {
		t.Fatalf("GetALGSettings: %v", err)
	}
	if !alg.FTP || !alg.SIP {
		t.Errorf("alg = %+v", alg)
	}

	fw, err := svc.GetFirewallSettings(context.Background(), omadaNatOptions(ts))
	if err != nil {
		t.Fatalf("GetFirewallSettings: %v", err)
	}
	if fw.ICMP != 30 || fw.UDPStream != 0 || !fw.SynCookies {
		t.Errorf("firewall = %+v", fw)
	}
}

// A login failure (bad client credentials) must surface from every NAT read
// method unchanged, before any NAT endpoint is touched.
func TestOmadaServiceNatReads_SessionFailure(t *testing.T) {
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			writeOmadaEnvelope(w, -44106, "null")
		default:
			t.Errorf("unexpected path %q after login failure", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})

	svc := NewOmadaService()
	ctx := context.Background()

	if _, err := svc.ListPortForwardings(ctx, omadaNatOptions(ts)); err == nil {
		t.Error("ListPortForwardings: want error, got nil")
	}
	if _, err := svc.ListOneToOneNAT(ctx, omadaNatOptions(ts)); err == nil {
		t.Error("ListOneToOneNAT: want error, got nil")
	}
	if _, err := svc.GetALGSettings(ctx, omadaNatOptions(ts)); err == nil {
		t.Error("GetALGSettings: want error, got nil")
	}
	if _, err := svc.GetFirewallSettings(ctx, omadaNatOptions(ts)); err == nil {
		t.Error("GetFirewallSettings: want error, got nil")
	}
}

// PlanNat/ApplyNat refuse every Omada NAT mutation with the current
// collection as evidence and issue zero writes: any request outside the
// known read set is recorded and fails the test.
func TestOmadaServicePlanApplyNat_Refused(t *testing.T) {
	cases := []struct {
		name, operation, ruleID, endpoint string
	}{
		{"port_forward", "port_forward", "pf1", "/sites/{siteId}/nat/port-forwardings"},
		{"one_to_one", "one_to_one", "o1", "/sites/{siteId}/nat/one-to-one-nat"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var unexpected strings.Builder
			ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				if (r.URL.Path == "/openapi/v1/abc123/sites/s1/nat/port-forwardings" ||
					r.URL.Path == "/openapi/v1/abc123/sites/s1/nat/one-to-one-nat") &&
					r.Method != http.MethodGet {
					unexpected.WriteString(r.Method + " " + r.URL.Path + "\n")
					writeOmadaEnvelope(w, -1, `null`)
					return
				}
				natReads(&unexpected)(w, r)
			})
			opts := omadaNatOptions(ts)
			svc := NewOmadaService()

			plan, err := svc.PlanNat(context.Background(), opts, OmadaNatApplyRequest{Operation: tc.operation, Action: "create"})
			if err != nil {
				t.Fatalf("PlanNat: %v", err)
			}
			if plan.Provider != "omada" || plan.Outcome != "refused" || !plan.DryRun {
				t.Errorf("plan outcome = %q dry_run=%v, want refused dry-run plan", plan.Outcome, plan.DryRun)
			}
			if len(plan.Endpoints) != 1 || plan.Endpoints[0] != tc.endpoint {
				t.Errorf("endpoints = %v, want [%s]", plan.Endpoints, tc.endpoint)
			}
			if !strings.Contains(plan.Before, tc.ruleID) {
				t.Errorf("plan.Before missing rule %s:\n%s", tc.ruleID, plan.Before)
			}
			if len(plan.Warnings) == 0 {
				t.Error("plan.Warnings empty, want the write-surface explanation")
			}

			res, err := svc.ApplyNat(context.Background(), opts, OmadaNatApplyRequest{Operation: tc.operation, Action: "create", DryRun: false})
			if err != nil {
				t.Fatalf("ApplyNat: %v", err)
			}
			if res.Outcome != "refused" || res.DryRun {
				t.Errorf("apply outcome = %q dry_run=%v, want refused non-dry-run result", res.Outcome, res.DryRun)
			}
			if res.Before != res.After || !strings.Contains(res.Before, tc.ruleID) {
				t.Errorf("apply evidence mismatch (Before/After %s / %s) or missing rule %s", res.Before, res.After, tc.ruleID)
			}
			if got := unexpected.String(); got != "" {
				t.Errorf("refusal issued non-read requests: %s", got)
			}
		})
	}
}

// Request-shape validation must reject before any controller contact.
func TestOmadaServicePlanApplyNat_Validation(t *testing.T) {
	svc := NewOmadaService()
	ctx := context.Background()
	opts := OmadaOptions{Host: "https://omada.local"}
	cases := []struct {
		name string
		req  OmadaNatApplyRequest
		want string
	}{
		{"source_nat refused", OmadaNatApplyRequest{Operation: "source_nat"}, "Omada has no source_nat collection"},
		{"toggle one_to_one", OmadaNatApplyRequest{Operation: "one_to_one", Action: "toggle", RuleUUID: "u1"}, "toggle is only supported for port_forward"},
		{"bogus action", OmadaNatApplyRequest{Operation: "port_forward", Action: "reboot"}, "action must be one of create, update, delete, toggle"},
		{"delete without uuid", OmadaNatApplyRequest{Operation: "port_forward", Action: "delete"}, "rule_uuid is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := svc.PlanNat(ctx, opts, tc.req); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("PlanNat error = %v, want %q", err, tc.want)
			}
			if _, err := svc.ApplyNat(ctx, opts, tc.req); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("ApplyNat error = %v, want %q", err, tc.want)
			}
		})
	}
}

// Registry safety rails: an absent or non-mutating Omada provider must fail
// the NAT plan/apply with a clear error, not a panic or a fake outcome.
func TestOmadaServicePlanApplyNat_RegistryRails(t *testing.T) {
	svc := NewOmadaService()
	ctx := context.Background()
	opts := OmadaOptions{Host: "https://omada.local"}
	req := OmadaNatApplyRequest{Operation: "port_forward", Action: "create"}

	providers.Reset()
	t.Cleanup(func() {
		providers.Reset()
		_ = providers.Register(&omadaprovider.OmadaProvider{})
	})

	if _, err := svc.PlanNat(ctx, opts, req); err == nil || !strings.Contains(err.Error(), "provider omada not registered") {
		t.Fatalf("unregistered PlanNat error = %v", err)
	}
	if _, err := svc.ApplyNat(ctx, opts, req); err == nil || !strings.Contains(err.Error(), "provider omada not registered") {
		t.Fatalf("unregistered ApplyNat error = %v", err)
	}

	if err := providers.Register(nonMutatingProvider{}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := svc.PlanNat(ctx, opts, req); err == nil || !strings.Contains(err.Error(), "does not implement NAT mutation") {
		t.Fatalf("non-mutating PlanNat error = %v", err)
	}
	if _, err := svc.ApplyNat(ctx, opts, req); err == nil || !strings.Contains(err.Error(), "does not implement NAT mutation") {
		t.Fatalf("non-mutating ApplyNat error = %v", err)
	}
}
