package opnsense

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/testutil"
)

// natApplyOpts wires the provider to a test server. The host is the raw
// "host:port" form — NewClient normalises https:// prefixes.
func natApplyOpts(t *testing.T, ts *httptest.Server) providers.ImportOptions {
	t.Helper()
	return providers.ImportOptions{
		Host:          strings.TrimPrefix(ts.URL, "https://"),
		ClientID:      "key",
		ClientSecret:  "secret",
		SkipTLSVerify: true,
	}
}

// natTestServer returns a TLS server that serves the canned read responses
// for every guard/list path (outbound mode + the three rule lists) and
// routes write POSTs to h, counting them. A nil h 404s any POST. rows is
// the canned rule list for the paged-list reads (search_rule with
// current/rowCount query params) and SNATModeBody's mode drives the
// outbound-mode read (source_nat/get, no query params).
// natTestServerOpt is an optional behavior override for natTestServer:
// failMode 400s the outbound-mode read, and failListNames 400s the named
// paged rule list reads (in order, so each guard-list error can be
// exercised individually without a bespoke server).
type natTestServerOpt struct {
	failMode      bool
	failListNames []string
}

func natTestServer(t *testing.T, mode, rows string, h http.HandlerFunc) (*httptest.Server, *int) {
	return natTestServerWithOpt(t, mode, rows, h, natTestServerOpt{})
}

func natTestServerWithOpt(t *testing.T, mode, rows string, h http.HandlerFunc, opt natTestServerOpt) (*httptest.Server, *int) {
	t.Helper()
	mux := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if h != nil {
				h(w, r)
				return
			}
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if opt.failMode && r.URL.Path == "/api/firewall/source_nat/get" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		for _, name := range opt.failListNames {
			if r.URL.Path == "/api/firewall/"+name+"/search_rule" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
		}
		switch r.URL.Path {
		case "/api/firewall/source_nat/get":
			testutil.WriteBody(w, testutil.SNATModeBody(mode))
		case "/api/firewall/d_nat/search_rule",
			"/api/firewall/one_to_one/search_rule",
			"/api/firewall/source_nat/search_rule":
			testutil.WriteBody(w, `{"total":1,"rows":[`+rows+`]}`)
		default:
			t.Errorf("unexpected GET path %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	return natFullTestServer(t, mux)
}

// natFullTestServer returns a TLS server that routes every request (GET
// and POST) to h and counts the POSTs. Use it when a test's fixture must
// change state between the pre-create reads and the post-create refetch
// — a static rows fixture cannot express "empty before, row after".
func natFullTestServer(t *testing.T, h http.HandlerFunc) (*httptest.Server, *int) {
	t.Helper()
	var posts int
	mux := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			posts++
		}
		h(w, r)
	})
	ts := httptest.NewTLSServer(mux)
	t.Cleanup(ts.Close)
	return ts, &posts
}

var natCreateReq = providers.NatApplyRequest{
	Operation: "port_forward",
	Spec: providers.NatRuleSpec{
		Interfaces:  []string{"lan"},
		Protocol:    "tcp",
		Destination: "10.0.40.10",
		Port:        "443",
		Target:      "10.0.40.20",
		Label:       "web",
	},
}

// natCreateRows is one paged row in the reader's wire shape (rows[].rule is
// an array whose first element is the rule), matching client_nat_test.go.
var natCreateRows = `{"rule":[{"uuid":"u-1","disabled":false,"interface":["lan"],"protocol":"tcp","destination":{"network":"10.0.40.10","port":"443"},"target":"10.0.40.20","descr":"web"}]}`

func TestPlanNat_CreatesWithZeroPosts(t *testing.T) {
	ts, posts := natTestServer(t, "automatic", "", nil)
	p := &Provider{}
	plan, err := p.PlanNat(context.Background(), natCreateReq, natApplyOpts(t, ts))
	if err != nil {
		t.Fatalf("PlanNat: %v", err)
	}
	if *posts != 0 {
		t.Fatalf("posts = %d, want 0 (dry-run lock)", *posts)
	}
	if plan.Provider != "opnsense" {
		t.Errorf("provider = %q", plan.Provider)
	}
	if plan.Outcome != "would_create" {
		t.Errorf("outcome = %q, want would_create", plan.Outcome)
	}
	if len(plan.Endpoints) != 1 || plan.Endpoints[0] != "/firewall/d_nat/add_rule" {
		t.Errorf("endpoints = %v", plan.Endpoints)
	}
	if !plan.DryRun {
		t.Error("dry_run = false, want true (plan is always a dry-run)")
	}
	if len(plan.Warnings) != 1 || !strings.Contains(plan.Warnings[0], "staged") {
		t.Errorf("warnings = %v, want staged warning only (nat_router device)", plan.Warnings)
	}
}

func TestPlanNat_UpdateEndpointAndOutcome(t *testing.T) {
	ts, posts := natTestServer(t, "automatic", natCreateRows, nil)
	req := natCreateReq
	req.Action = "update"
	req.RuleUUID = "u-1"
	p := &Provider{}
	plan, err := p.PlanNat(context.Background(), req, natApplyOpts(t, ts))
	if err != nil {
		t.Fatalf("PlanNat: %v", err)
	}
	if *posts != 0 {
		t.Fatalf("posts = %d, want 0", *posts)
	}
	if plan.Outcome != "would_update" || plan.RuleUUID != "u-1" {
		t.Errorf("outcome/uuid = %q/%q", plan.Outcome, plan.RuleUUID)
	}
	if len(plan.Endpoints) != 1 || plan.Endpoints[0] != "/firewall/d_nat/set_rule/u-1" {
		t.Errorf("endpoints = %v", plan.Endpoints)
	}
}

func TestPlanNat_DeleteAndToggleEndpoints(t *testing.T) {
	p := &Provider{}
	cases := []struct {
		name     string
		req      providers.NatApplyRequest
		outcome  string
		endpoint string
	}{
		{"delete", providers.NatApplyRequest{Operation: "port_forward", Action: "delete", RuleUUID: "u-1"}, "would_delete", "/firewall/d_nat/del_rule/u-1"},
		{"toggle", providers.NatApplyRequest{Operation: "port_forward", Action: "toggle", RuleUUID: "u-1"}, "would_update", "/firewall/d_nat/toggle_rule/<uuid>,<disabled>"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts, posts := natTestServer(t, "automatic", natCreateRows, nil)
			plan, err := p.PlanNat(context.Background(), tc.req, natApplyOpts(t, ts))
			if err != nil {
				t.Fatalf("PlanNat: %v", err)
			}
			if *posts != 0 {
				t.Fatalf("posts = %d, want 0", *posts)
			}
			if plan.Outcome != tc.outcome {
				t.Errorf("outcome = %q, want %q", plan.Outcome, tc.outcome)
			}
			if len(plan.Endpoints) != 1 || plan.Endpoints[0] != tc.endpoint {
				t.Errorf("endpoints = %v, want %v", plan.Endpoints, tc.endpoint)
			}
		})
	}
}

func TestPlanNat_UnknownDeviceAlwaysRefused(t *testing.T) {
	// mode "" + zero rules on all three lists → unknown classification.
	ts, posts := natTestServer(t, "", "", nil)
	p := &Provider{}
	// Even with allow_double_nat set, unknown is refused (lock 3).
	req := natCreateReq
	req.AllowDoubleNat = true
	plan, err := p.PlanNat(context.Background(), req, natApplyOpts(t, ts))
	if err != nil {
		t.Fatalf("PlanNat: %v", err)
	}
	if *posts != 0 {
		t.Fatalf("posts = %d, want 0", *posts)
	}
	if plan.Outcome != "refused" {
		t.Errorf("outcome = %q, want refused", plan.Outcome)
	}
	if len(plan.Warnings) < 2 || !strings.Contains(plan.Warnings[1], "unknown") {
		t.Errorf("warnings = %v, want staged + guard refusal", plan.Warnings)
	}
}

func TestPlanNat_BridgeRefusedWithoutFlagAndAllowedWithFlag(t *testing.T) {
	// mode "disabled" + zero rules → bridge.
	ts, posts := natTestServer(t, "disabled", "", nil)
	p := &Provider{}

	plan, err := p.PlanNat(context.Background(), natCreateReq, natApplyOpts(t, ts))
	if err != nil {
		t.Fatalf("PlanNat (no flag): %v", err)
	}
	if *posts != 0 {
		t.Fatalf("posts = %d, want 0", *posts)
	}
	if plan.Outcome != "refused" {
		t.Errorf("outcome = %q, want refused (bridge, no flag)", plan.Outcome)
	}
	if len(plan.Warnings) != 2 || !strings.Contains(plan.Warnings[1], "bridge") {
		t.Errorf("warnings = %v", plan.Warnings)
	}

	req := natCreateReq
	req.AllowDoubleNat = true
	plan, err = p.PlanNat(context.Background(), req, natApplyOpts(t, ts))
	if err != nil {
		t.Fatalf("PlanNat (flag): %v", err)
	}
	if *posts != 0 {
		t.Fatalf("posts = %d, want 0", *posts)
	}
	if plan.Outcome != "would_create" {
		t.Errorf("outcome = %q, want would_create (flag overrides bridge)", plan.Outcome)
	}
	if len(plan.Warnings) != 1 {
		t.Errorf("warnings = %v, want staged warning only", plan.Warnings)
	}
}

func TestValidateNatRequest(t *testing.T) {
	cases := []struct {
		name    string
		req     providers.NatApplyRequest
		wantErr string
	}{
		{"unknown operation", providers.NatApplyRequest{Operation: "bogus"}, "operation must be one of"},
		{"unknown action", providers.NatApplyRequest{Operation: "port_forward", Action: "explode"}, "action must be one of"},
		{"toggle non-port-forward", providers.NatApplyRequest{Operation: "one_to_one", Action: "toggle", RuleUUID: "u"}, "toggle is only supported for port_forward"},
		{"update without uuid", providers.NatApplyRequest{Operation: "port_forward", Action: "update"}, "rule_uuid is required"},
		{"delete without uuid", providers.NatApplyRequest{Operation: "source_nat", Action: "delete"}, "rule_uuid is required"},
		{"toggle without uuid", providers.NatApplyRequest{Operation: "port_forward", Action: "toggle"}, "rule_uuid is required"},
		{"empty action defaults to create", providers.NatApplyRequest{Operation: "port_forward"}, ""},
		{"create without uuid is fine", natCreateReq, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := validateNatRequest(tc.req)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestApplyNat_DryRunZeroPosts(t *testing.T) {
	ts, posts := natTestServer(t, "automatic", natCreateRows, nil)
	p := &Provider{}
	req := natCreateReq
	req.DryRun = true
	res, err := p.ApplyNat(context.Background(), req, natApplyOpts(t, ts))
	if err != nil {
		t.Fatalf("ApplyNat: %v", err)
	}
	if *posts != 0 {
		t.Fatalf("posts = %d, want 0 (dry-run lock)", *posts)
	}
	if res.Outcome != "unchanged" || !res.DryRun {
		t.Errorf("outcome/dry_run = %q/%v", res.Outcome, res.DryRun)
	}
	if res.Before != res.After {
		t.Error("before/after must be identical on dry-run")
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "staged") {
		t.Errorf("warnings = %v", res.Warnings)
	}
}

func TestApplyNat_RefusedZeroPosts(t *testing.T) {
	// unknown device: mode "" + zero rules.
	ts, posts := natTestServer(t, "", "", nil)
	p := &Provider{}
	req := natCreateReq
	req.DryRun = false
	res, err := p.ApplyNat(context.Background(), req, natApplyOpts(t, ts))
	if err != nil {
		t.Fatalf("ApplyNat: %v", err)
	}
	if *posts != 0 {
		t.Fatalf("posts = %d, want 0 (refused)", *posts)
	}
	if res.Outcome != "refused" {
		t.Errorf("outcome = %q, want refused", res.Outcome)
	}
	if res.Before != res.After {
		t.Error("before/after must be identical on refusal")
	}
	if len(res.Warnings) != 2 {
		t.Errorf("warnings = %v, want staged + refusal", res.Warnings)
	}
}

func TestApplyNat_CreatePostsAndRefetches(t *testing.T) {
	// Pre-create reads (guard + before) see an empty collection; the
	// stateful handler flips the d_nat list to the created rule only
	// after the add_rule POST, so Before and After evidence differ.
	createdRows := `{"total":1,"rows":[{"rule":[{"uuid":"new-1","disabled":false,"interface":["lan"],"protocol":"tcp","destination":{"network":"10.0.40.10","port":"443"},"target":"10.0.40.20","descr":"web"}]}]}`
	var created bool
	ts, posts := natFullTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if r.URL.Path != "/api/firewall/d_nat/add_rule" {
				t.Errorf("unexpected POST path %q", r.URL.Path)
				w.WriteHeader(http.StatusNotFound)
				return
			}
			created = true
			testutil.WriteBody(w, `{"result":"saved","uuid":"new-1"}`)
			return
		}
		switch r.URL.Path {
		case "/api/firewall/source_nat/get":
			testutil.WriteBody(w, testutil.SNATModeBody("automatic"))
		case "/api/firewall/d_nat/search_rule":
			if created {
				testutil.WriteBody(w, createdRows)
				return
			}
			testutil.WriteBody(w, `{"total":0,"rows":[]}`)
		case "/api/firewall/one_to_one/search_rule", "/api/firewall/source_nat/search_rule":
			testutil.WriteBody(w, `{"total":0,"rows":[]}`)
		default:
			t.Errorf("unexpected GET path %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	p := &Provider{}
	res, err := p.ApplyNat(context.Background(), natCreateReq, natApplyOpts(t, ts))
	if err != nil {
		t.Fatalf("ApplyNat: %v", err)
	}
	if *posts != 1 {
		t.Fatalf("posts = %d, want 1", *posts)
	}
	if res.Outcome != "created" || res.RuleUUID != "new-1" {
		t.Errorf("outcome/uuid = %q/%q", res.Outcome, res.RuleUUID)
	}
	if len(res.Endpoints) != 1 || res.Endpoints[0] != "/firewall/d_nat/add_rule" {
		t.Errorf("endpoints = %v", res.Endpoints)
	}
	if res.Before == res.After {
		t.Error("before/after must differ after a real create")
	}
	if len(res.Warnings) != 1 {
		t.Errorf("warnings = %v, want staged only", res.Warnings)
	}
}

func TestApplyNat_CreateIdempotentNoPost(t *testing.T) {
	// The collection already holds a rule matching the create's 5-tuple.
	ts, posts := natTestServer(t, "automatic", natCreateRows, nil)
	p := &Provider{}
	res, err := p.ApplyNat(context.Background(), natCreateReq, natApplyOpts(t, ts))
	if err != nil {
		t.Fatalf("ApplyNat: %v", err)
	}
	if *posts != 0 {
		t.Fatalf("posts = %d, want 0 (idempotent create)", *posts)
	}
	if res.Outcome != "unchanged" || res.RuleUUID != "u-1" {
		t.Errorf("outcome/uuid = %q/%q, want unchanged/u-1", res.Outcome, res.RuleUUID)
	}
}

func TestApplyNat_CreateUUIDFallbackToMatch(t *testing.T) {
	// add_rule saves without a uuid in the response; the refetch list shows
	// the new rule, and the unique 5-tuple match resolves it (lock 6). The
	// row must not exist before the POST — otherwise the port-forward
	// idempotency check short-circuits the create to "unchanged".
	matchRows := `{"total":1,"rows":[{"rule":[{"uuid":"match-1","disabled":false,"interface":["lan"],"protocol":"tcp","destination":{"network":"10.0.40.10","port":"443"},"target":"10.0.40.20","descr":"web"}]}]}`
	var created bool
	ts, posts := natFullTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if r.URL.Path != "/api/firewall/d_nat/add_rule" {
				t.Errorf("unexpected POST path %q", r.URL.Path)
				w.WriteHeader(http.StatusNotFound)
				return
			}
			created = true
			testutil.WriteBody(w, `{"result":"saved"}`)
			return
		}
		switch r.URL.Path {
		case "/api/firewall/source_nat/get":
			testutil.WriteBody(w, testutil.SNATModeBody("automatic"))
		case "/api/firewall/d_nat/search_rule":
			if created {
				testutil.WriteBody(w, matchRows)
				return
			}
			testutil.WriteBody(w, `{"total":0,"rows":[]}`)
		case "/api/firewall/one_to_one/search_rule", "/api/firewall/source_nat/search_rule":
			testutil.WriteBody(w, `{"total":0,"rows":[]}`)
		default:
			t.Errorf("unexpected GET path %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	p := &Provider{}
	res, err := p.ApplyNat(context.Background(), natCreateReq, natApplyOpts(t, ts))
	if err != nil {
		t.Fatalf("ApplyNat: %v", err)
	}
	if *posts != 1 {
		t.Fatalf("posts = %d, want 1", *posts)
	}
	if res.Outcome != "created" || res.RuleUUID != "match-1" {
		t.Errorf("outcome/uuid = %q/%q, want created/match-1", res.Outcome, res.RuleUUID)
	}
}

func TestApplyNat_UpdatePostsSet(t *testing.T) {
	ts, posts := natTestServer(t, "automatic", natCreateRows, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/firewall/d_nat/set_rule/u-1" {
			t.Errorf("unexpected POST path %q", r.URL.Path)
		}
		testutil.WriteBody(w, `{"result":"saved"}`)
	}))
	p := &Provider{}
	req := natCreateReq
	req.Action = "update"
	req.RuleUUID = "u-1"
	res, err := p.ApplyNat(context.Background(), req, natApplyOpts(t, ts))
	if err != nil {
		t.Fatalf("ApplyNat: %v", err)
	}
	if *posts != 1 {
		t.Fatalf("posts = %d, want 1", *posts)
	}
	if res.Outcome != "updated" || res.RuleUUID != "u-1" {
		t.Errorf("outcome/uuid = %q/%q", res.Outcome, res.RuleUUID)
	}
	if len(res.Endpoints) != 1 || res.Endpoints[0] != "/firewall/d_nat/set_rule/u-1" {
		t.Errorf("endpoints = %v", res.Endpoints)
	}
}

func TestApplyNat_DeletePostsDel(t *testing.T) {
	ts, posts := natTestServer(t, "automatic", natCreateRows, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/firewall/d_nat/del_rule/u-1" {
			t.Errorf("unexpected POST path %q", r.URL.Path)
		}
		testutil.WriteBody(w, `{"result":"deleted"}`)
	}))
	p := &Provider{}
	req := providers.NatApplyRequest{Operation: "port_forward", Action: "delete", RuleUUID: "u-1"}
	res, err := p.ApplyNat(context.Background(), req, natApplyOpts(t, ts))
	if err != nil {
		t.Fatalf("ApplyNat: %v", err)
	}
	if *posts != 1 {
		t.Fatalf("posts = %d, want 1", *posts)
	}
	if res.Outcome != "deleted" || res.RuleUUID != "u-1" {
		t.Errorf("outcome/uuid = %q/%q", res.Outcome, res.RuleUUID)
	}
	if len(res.Endpoints) != 1 || res.Endpoints[0] != "/firewall/d_nat/del_rule/u-1" {
		t.Errorf("endpoints = %v", res.Endpoints)
	}
}

func TestApplyNat_TogglePostsTogglePolarity(t *testing.T) {
	for _, tc := range []struct {
		disable bool
		path    string
	}{
		{true, "/api/firewall/d_nat/toggle_rule/u-1,1"},
		{false, "/api/firewall/d_nat/toggle_rule/u-1,0"},
	} {
		t.Run("disable_"+boolStr(tc.disable), func(t *testing.T) {
			ts, posts := natTestServer(t, "automatic", natCreateRows, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != tc.path {
					t.Errorf("path = %q, want %q", r.URL.Path, tc.path)
				}
				testutil.WriteBody(w, `{"result":"saved"}`)
			}))
			p := &Provider{}
			req := providers.NatApplyRequest{Operation: "port_forward", Action: "toggle", RuleUUID: "u-1", ToggleDisable: tc.disable}
			res, err := p.ApplyNat(context.Background(), req, natApplyOpts(t, ts))
			if err != nil {
				t.Fatalf("ApplyNat: %v", err)
			}
			if *posts != 1 {
				t.Fatalf("posts = %d, want 1", *posts)
			}
			if res.Outcome != "updated" || res.RuleUUID != "u-1" {
				t.Errorf("outcome/uuid = %q/%q", res.Outcome, res.RuleUUID)
			}
		})
	}
}

func TestApplyNat_OneToOneAndSourceNatWrites(t *testing.T) {
	// Exercises the non-port-forward create client calls at the provider
	// level (the wire payloads themselves are covered by client_nat_test.go).
	for _, tc := range []struct {
		coll   string
		add    string
		before string
	}{
		{"one_to_one", "/api/firewall/one_to_one/add_rule",
			`{"uuid":"u-1","enabled":"1","sequence":"10","interface":"wan","type":"binat","source_net":"10.0.10.0/24","destination_net":"any","external":"203.0.113.10","description":"ext"}`},
		{"source_nat", "/api/firewall/source_nat/add_rule",
			`{"uuid":"u-1","enabled":"1","sequence":"10","interface":"lan","ipprotocol":"inet","protocol":"any","source_net":"any","destination_net":"any","description":"snat"}`},
	} {
		t.Run(tc.coll, func(t *testing.T) {
			ts, posts := natTestServer(t, "automatic", tc.before, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != tc.add {
					t.Errorf("create path = %q, want %q", r.URL.Path, tc.add)
				}
				testutil.WriteBody(w, `{"result":"saved","uuid":"new-1"}`)
			}))
			p := &Provider{}
			req := providers.NatApplyRequest{Operation: tc.coll, Spec: providers.NatRuleSpec{Label: "r"}}
			res, err := p.ApplyNat(context.Background(), req, natApplyOpts(t, ts))
			if err != nil {
				t.Fatalf("create: %v", err)
			}
			if *posts != 1 || res.Outcome != "created" || res.RuleUUID != "new-1" {
				t.Fatalf("create outcome = %q, posts = %d", res.Outcome, *posts)
			}
			if len(res.Endpoints) != 1 || !strings.Contains(res.Endpoints[0], tc.coll) {
				t.Errorf("endpoints = %v", res.Endpoints)
			}
		})
	}
}

func TestApplyNat_UnknownOperationError(t *testing.T) {
	p := &Provider{}
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()
	_, err := p.PlanNat(context.Background(), providers.NatApplyRequest{Operation: "bogus"}, natApplyOpts(t, ts))
	if err == nil || !strings.Contains(err.Error(), "operation must be one of") {
		t.Fatalf("err = %v, want operation error", err)
	}
}

// TestPlanNat_MissingHostError — the host check runs before any client I/O,
// so an empty host fails fast without dialing.
func TestPlanNat_MissingHostError(t *testing.T) {
	p := &Provider{}
	_, err := p.PlanNat(context.Background(), natCreateReq, providers.ImportOptions{})
	if err == nil || !strings.Contains(err.Error(), "--host is required") {
		t.Fatalf("err = %v, want host error", err)
	}
}

func TestApplyNat_MissingHostError(t *testing.T) {
	p := &Provider{}
	_, err := p.ApplyNat(context.Background(), natCreateReq, providers.ImportOptions{})
	if err == nil || !strings.Contains(err.Error(), "--host is required") {
		t.Fatalf("err = %v, want host error", err)
	}
}

// TestPlanNat_GuardReadFailures covers every guard read failure: the
// outbound-mode read (mode=automatic → an empty snat_mode is unknown) and
// each of the three rule-list reads (mode=disabled → a read failure would
// otherwise classify as bridge).
func TestPlanNat_GuardReadFailures(t *testing.T) {
	p := &Provider{}
	cases := []struct {
		name, want, list string
		mode             string
		opt              natTestServerOpt
	}{
		{"mode read", "reading outbound NAT mode", "", "automatic", natTestServerOpt{failMode: true}},
		{"port forward list", "reading port forward rules", "d_nat", "disabled", natTestServerOpt{}},
		{"one-to-one list", "reading one-to-one rules", "one_to_one", "disabled", natTestServerOpt{}},
		{"source nat list", "reading source NAT rules", "source_nat", "disabled", natTestServerOpt{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opt := tc.opt
			if tc.list != "" {
				opt.failListNames = []string{tc.list}
			}
			ts, _ := natTestServerWithOpt(t, tc.mode, "", nil, opt)
			_, err := p.PlanNat(context.Background(), natCreateReq, natApplyOpts(t, ts))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want containing %q", err, tc.want)
			}
		})
	}
}

func TestApplyNat_GuardReadFailures(t *testing.T) {
	p := &Provider{}
	cases := []struct {
		name, want, list string
		mode             string
		opt              natTestServerOpt
	}{
		{"mode read", "reading outbound NAT mode", "", "automatic", natTestServerOpt{failMode: true}},
		{"port forward list", "reading port forward rules", "d_nat", "disabled", natTestServerOpt{}},
		{"one-to-one list", "reading one-to-one rules", "one_to_one", "disabled", natTestServerOpt{}},
		{"source nat list", "reading source NAT rules", "source_nat", "disabled", natTestServerOpt{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opt := tc.opt
			if tc.list != "" {
				opt.failListNames = []string{tc.list}
			}
			ts, _ := natTestServerWithOpt(t, tc.mode, "", nil, opt)
			_, err := p.ApplyNat(context.Background(), natCreateReq, natApplyOpts(t, ts))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want containing %q", err, tc.want)
			}
		})
	}
}

// natAfterGuardFailsHandler serves the guard reads (outbound mode + the
// three list reads) successfully, then 400s the d_nat list read — which in
// a PlanNat/ApplyNat create is exactly the Before read, fired right after
// the guard.
func natAfterGuardFailsHandler(t *testing.T) http.HandlerFunc {
	t.Helper()
	var dNatReads int
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/firewall/source_nat/get":
			testutil.WriteBody(w, testutil.SNATModeBody("automatic"))
		case "/api/firewall/one_to_one/search_rule":
			testutil.WriteBody(w, `{"total":0,"rows":[]}`)
		case "/api/firewall/source_nat/search_rule":
			testutil.WriteBody(w, `{"total":0,"rows":[]}`)
		case "/api/firewall/d_nat/search_rule":
			dNatReads++
			if dNatReads == 1 {
				testutil.WriteBody(w, `{"total":0,"rows":[]}`)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
		default:
			t.Errorf("unexpected GET path %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

// TestPlanNat_ListReadAfterGuard — the guard's list reads succeed but the
// collection list read right after the guard 400s.
func TestPlanNat_ListReadAfterGuard(t *testing.T) {
	p := &Provider{}
	ts, _ := natFullTestServer(t, natAfterGuardFailsHandler(t))
	_, err := p.PlanNat(context.Background(), natCreateReq, natApplyOpts(t, ts))
	if err == nil || !strings.Contains(err.Error(), "reading port_forward rules") {
		t.Fatalf("err = %v, want list read error", err)
	}
}

func TestApplyNat_ListReadAfterGuard(t *testing.T) {
	p := &Provider{}
	ts, _ := natFullTestServer(t, natAfterGuardFailsHandler(t))
	_, err := p.ApplyNat(context.Background(), natCreateReq, natApplyOpts(t, ts))
	if err == nil || !strings.Contains(err.Error(), "reading port_forward rules") {
		t.Fatalf("err = %v, want list read error", err)
	}
}

// TestApplyNat_ClientWriteErrors drives the failure branches of
// applyNatMutation: a validation-failed create (no retry), a set/del on a
// missing uuid for each collection (one request each), and a toggle on a
// missing uuid.
func TestApplyNat_ClientWriteErrors(t *testing.T) {
	p := &Provider{}

	collWrites := []struct {
		coll string
		set  string
		del  string
	}{
		{"one_to_one", "/api/firewall/one_to_one/set_rule/u-1", "/api/firewall/one_to_one/del_rule/u-1"},
		{"source_nat", "/api/firewall/source_nat/set_rule/u-1", "/api/firewall/source_nat/del_rule/u-1"},
	}
	for _, tc := range collWrites {
		t.Run("set_"+tc.coll, func(t *testing.T) {
			ts, posts := natTestServer(t, "automatic", "", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				testutil.WriteBody(w, `{"result":"not found"}`)
			}))
			req := providers.NatApplyRequest{Operation: tc.coll, Action: "update", RuleUUID: "u-1"}
			_, err := p.ApplyNat(context.Background(), req, natApplyOpts(t, ts))
			if err == nil || !strings.Contains(err.Error(), "setting "+tc.coll+" rule") {
				t.Fatalf("err = %v, want set error", err)
			}
			if *posts != 1 {
				t.Fatalf("posts = %d, want 1 (stable 404-style result must not retry)", *posts)
			}
		})
		t.Run("del_"+tc.coll, func(t *testing.T) {
			ts, posts := natTestServer(t, "automatic", "", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				testutil.WriteBody(w, `{"result":"not found"}`)
			}))
			req := providers.NatApplyRequest{Operation: tc.coll, Action: "delete", RuleUUID: "u-1"}
			_, err := p.ApplyNat(context.Background(), req, natApplyOpts(t, ts))
			if err == nil || !strings.Contains(err.Error(), "deleting "+tc.coll+" rule") {
				t.Fatalf("err = %v, want delete error", err)
			}
			if *posts != 1 {
				t.Fatalf("posts = %d, want 1", *posts)
			}
		})
	}

	t.Run("create_port_forward_validation_failed", func(t *testing.T) {
		var calls int
		ts, _ := natFullTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				calls++
				testutil.WriteBody(w, `{"result":"failed","validations":{"destination":"10.0.40.10 is not in the interface"}}`)
				return
			}
			switch r.URL.Path {
			case "/api/firewall/source_nat/get":
				testutil.WriteBody(w, testutil.SNATModeBody("automatic"))
			default:
				testutil.WriteBody(w, `{"total":0,"rows":[]}`)
			}
		}))
		_, err := p.ApplyNat(context.Background(), natCreateReq, natApplyOpts(t, ts))
		if err == nil || !strings.Contains(err.Error(), "creating port_forward rule") ||
			!strings.Contains(err.Error(), "validation failed") {
			t.Fatalf("err = %v, want validation error", err)
		}
		if calls != 1 {
			t.Fatalf("requests = %d, want 1 (no retry on validation failure)", calls)
		}
	})

	t.Run("toggle_port_forward_not_found", func(t *testing.T) {
		ts, posts := natTestServer(t, "automatic", "", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/firewall/d_nat/toggle_rule/u-1,1" {
				t.Errorf("path = %q", r.URL.Path)
			}
			testutil.WriteBody(w, `{"result":"not found"}`)
		}))
		req := providers.NatApplyRequest{Operation: "port_forward", Action: "toggle", RuleUUID: "u-1", ToggleDisable: true}
		_, err := p.ApplyNat(context.Background(), req, natApplyOpts(t, ts))
		if err == nil || !strings.Contains(err.Error(), `toggling port_forward rule`) {
			t.Fatalf("err = %v, want toggle error", err)
		}
		if *posts != 1 {
			t.Fatalf("posts = %d, want 1", *posts)
		}
	})
}

// TestApplyNat_RefetchFailure — the mutation succeeds, but the post-mutation
// refetch 400s. The failure must surface, not be swallowed into After.
func TestApplyNat_RefetchFailure(t *testing.T) {
	p := &Provider{}
	var posted bool
	ts, _ := natFullTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			posted = true
			testutil.WriteBody(w, `{"result":"saved","uuid":"u-1"}`)
			return
		}
		if posted {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		switch r.URL.Path {
		case "/api/firewall/source_nat/get":
			testutil.WriteBody(w, testutil.SNATModeBody("automatic"))
		case "/api/firewall/d_nat/search_rule":
			testutil.WriteBody(w, `{"total":0,"rows":[]}`)
		case "/api/firewall/one_to_one/search_rule", "/api/firewall/source_nat/search_rule":
			testutil.WriteBody(w, `{"total":0,"rows":[]}`)
		default:
			t.Errorf("unexpected GET path %q", r.URL.Path)
		}
	}))
	req := providers.NatApplyRequest{Operation: "port_forward", Action: "update", RuleUUID: "u-1"}
	_, err := p.ApplyNat(context.Background(), req, natApplyOpts(t, ts))
	if err == nil || !strings.Contains(err.Error(), "refetching port_forward rules after updated") {
		t.Fatalf("err = %v, want refetch error", err)
	}
}

func boolStr(b bool) string {
	if b {
		return "1"
	}
	return "0"
}
