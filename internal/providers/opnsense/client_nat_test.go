package opnsense

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/testutil"
)

// fullPortForwardSpec exercises every d_nat model field so the success tests
// pin the full wire shape (lock 7 field set).
var fullPortForwardSpec = natRuleSpec{
	Sequence:    "99",
	Interfaces:  []string{"lan"},
	IPProtocol:  "inet",
	Protocol:    "TCP",
	Source:      "any",
	SourcePort:  "any",
	Destination: "10.0.40.10",
	Port:        "443",
	LocalPort:   "8443",
	Target:      "10.0.40.20",
	Label:       "web-servers",
}

// fullOneToOneSpec exercises every one_to_one model field.
var fullOneToOneSpec = natRuleSpec{
	Enabled:     "1",
	Sequence:    "10",
	Interfaces:  []string{"wan"},
	Type:        "binat",
	Source:      "10.0.40.10",
	Destination: "203.0.113.10",
	Target:      "203.0.113.10",
	Label:       "nas-passthrough",
}

// fullSourceNatSpec exercises every source_nat model field.
var fullSourceNatSpec = natRuleSpec{
	Enabled:     "1",
	Sequence:    "5",
	Interfaces:  []string{"lan"},
	IPProtocol:  "inet",
	Protocol:    "UDP",
	Source:      "10.0.60.0/24",
	SourcePort:  "any",
	Destination: "any",
	Port:        "any",
	Target:      "203.0.113.1",
	LocalPort:   "443",
	Label:       "iot-outbound",
}

// ruleEnvelope wraps a rule object in the write envelope and marshals it to
// the JSON bytes the tests compare key-for-key.
func ruleEnvelope(t *testing.T, coll string, spec natRuleSpec) []byte {
	t.Helper()
	body, err := natWirePayload(coll, spec)
	if err != nil {
		t.Fatalf("natWirePayload: %v", err)
	}
	return body
}

// expectPost pins the mutation invariants every write method must hold:
// POST method, the exact path, and JSON content type.
func expectPost(t *testing.T, r *http.Request, wantPath string) {
	t.Helper()
	if r.Method != http.MethodPost {
		t.Errorf("method = %s, want POST", r.Method)
	}
	if r.URL.Path != wantPath {
		t.Errorf("path = %q, want %q", r.URL.Path, wantPath)
	}
	if ct := r.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

// expectBody reads the request body and pins the exact wire payload. The
// match is key-based (order-insensitive): the wire contract is the set of
// fields, not their JSON ordering.
func expectBody(t *testing.T, r *http.Request, wantBody string) []byte {
	t.Helper()
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("reading request body: %v", err)
	}
	var got, want map[string]interface{}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("request body is not JSON: %v (%s)", err, raw)
	}
	if err := json.Unmarshal([]byte(wantBody), &want); err != nil {
		t.Fatalf("want body is not JSON: %v", err)
	}
	if !jsonEqual(t, got, want) {
		gotJSON, _ := json.Marshal(got)
		t.Errorf("body = %s, want %s", gotJSON, wantBody)
	}
	return raw
}

// jsonEqual compares two JSON values recursively (maps and arrays; scalars
// compare with ==).
func jsonEqual(t *testing.T, a, b interface{}) bool {
	t.Helper()
	switch va := a.(type) {
	case map[string]interface{}:
		vb, ok := b.(map[string]interface{})
		if !ok || len(va) != len(vb) {
			return false
		}
		for k, av := range va {
			bv, ok := vb[k]
			if !ok || !jsonEqual(t, av, bv) {
				return false
			}
		}
		return true
	case []interface{}:
		vb, ok := b.([]interface{})
		if !ok || len(va) != len(vb) {
			return false
		}
		for i := range va {
			if !jsonEqual(t, va[i], vb[i]) {
				return false
			}
		}
		return true
	default:
		return a == b
	}
}

// expectExactlyOneRequest asserts the handler was hit exactly once — the
// stable 4xx cases must never retry.
func expectExactlyOneRequest(t *testing.T, calls int) {
	t.Helper()
	if calls != 1 {
		t.Errorf("requests = %d, want exactly 1 (stable 4xx must not retry)", calls)
	}
}

// expectRetryBudget asserts a transient failure exhausted the retry budget:
// 1 initial attempt + 3 retries.
func expectRetryBudget(t *testing.T, calls int) {
	t.Helper()
	if calls != 4 {
		t.Errorf("requests = %d, want 4 (1 + 3 retries)", calls)
	}
}

// --- S3.1 — Create port forward ---

func TestCreatePortForwardRule(t *testing.T) {
	want := ruleEnvelope(t, "port_forward", fullPortForwardSpec)

	t.Run("success posts the full rule object envelope", func(t *testing.T) {
		var body []byte
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			expectPost(t, r, "/api/firewall/d_nat/add_rule")
			body = expectBody(t, r, string(want))
			testutil.WriteBody(w, `{"result":"saved","uuid":"pf-1"}`)
		}))
		uuid, err := c.CreatePortForwardRule(context.Background(), fullPortForwardSpec)
		if err != nil {
			t.Fatalf("CreatePortForwardRule: %v", err)
		}
		if uuid != "pf-1" {
			t.Errorf("uuid = %q, want pf-1 (the add_rule response uuid)", uuid)
		}
		// Round-trip: the posted envelope must be an object under "rule".
		var env map[string]json.RawMessage
		if err := json.Unmarshal(body, &env); err != nil {
			t.Fatalf("body is not an object envelope: %v", err)
		}
		if _, ok := env["rule"]; !ok {
			t.Errorf("body = %s, want an object envelope with key rule", body)
		}
	})

	t.Run("validation failure surfaces validations and does not retry", func(t *testing.T) {
		var calls int
		c, _ := fastTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			expectPost(t, r, "/api/firewall/d_nat/add_rule")
			expectBody(t, r, `{"rule":{"interface":"lan"}}`)
			testutil.WriteBody(w, `{"result":"failed","validations":{"sequence":"Required"}}`)
		}))
		_, err := c.CreatePortForwardRule(context.Background(), natRuleSpec{Interfaces: []string{"lan"}})
		if err == nil || !strings.Contains(err.Error(), "validation failed") || !strings.Contains(err.Error(), "sequence") {
			t.Errorf("error = %v, want a validation error naming the failing field", err)
		}
		expectExactlyOneRequest(t, calls)
	})

	t.Run("403 is stable single-shot", func(t *testing.T) {
		var calls int
		c, _ := fastTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			expectPost(t, r, "/api/firewall/d_nat/add_rule")
			expectBody(t, r, `{"rule":{"descr":"x"}}`)
			w.WriteHeader(http.StatusForbidden)
		}))
		_, err := c.CreatePortForwardRule(context.Background(), natRuleSpec{Label: "x"})
		if err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Errorf("error = %v, want permission denied", err)
		}
		expectExactlyOneRequest(t, calls)
	})

	t.Run("5xx is retried then surfaces", func(t *testing.T) {
		var calls int
		c, _ := fastTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		_, err := c.CreatePortForwardRule(context.Background(), natRuleSpec{Label: "x"})
		if err == nil || !strings.Contains(err.Error(), "unexpected status 503") {
			t.Errorf("error = %v, want unexpected status 503", err)
		}
		expectRetryBudget(t, calls)
	})

	t.Run("404 on add is stable", func(t *testing.T) {
		var calls int
		c, _ := fastTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			w.WriteHeader(http.StatusNotFound)
		}))
		_, err := c.CreatePortForwardRule(context.Background(), natRuleSpec{Label: "x"})
		if err == nil || !strings.Contains(err.Error(), "resource not found") {
			t.Errorf("error = %v, want resource not found", err)
		}
		expectExactlyOneRequest(t, calls)
	})
}

// --- S3.2 — Update port forward ---

func TestSetPortForwardRule(t *testing.T) {
	want := ruleEnvelope(t, "port_forward", fullPortForwardSpec)

	t.Run("success posts the full payload to the uuid path", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			expectPost(t, r, "/api/firewall/d_nat/set_rule/pf-1")
			expectBody(t, r, string(want))
			testutil.WriteBody(w, `{"result":"saved"}`)
		}))
		if err := c.SetPortForwardRule(context.Background(), "pf-1", fullPortForwardSpec); err != nil {
			t.Fatalf("SetPortForwardRule: %v", err)
		}
	})

	t.Run("failed result for a missing uuid is a stable error", func(t *testing.T) {
		var calls int
		c, _ := fastTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			expectPost(t, r, "/api/firewall/d_nat/set_rule/missing")
			expectBody(t, r, `{"rule":{"descr":"x"}}`)
			testutil.WriteBody(w, `{"result":"failed"}`)
		}))
		err := c.SetPortForwardRule(context.Background(), "missing", natRuleSpec{Label: "x"})
		if err == nil || !strings.Contains(err.Error(), `returned "failed"`) {
			t.Errorf("error = %v, want a failed-result error", err)
		}
		expectExactlyOneRequest(t, calls)
	})

	t.Run("5xx is retried then surfaces", func(t *testing.T) {
		var calls int
		c, _ := fastTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			w.WriteHeader(http.StatusInternalServerError)
		}))
		err := c.SetPortForwardRule(context.Background(), "pf-1", natRuleSpec{Label: "x"})
		if err == nil || !strings.Contains(err.Error(), "unexpected status 500") {
			t.Errorf("error = %v, want unexpected status 500", err)
		}
		expectRetryBudget(t, calls)
	})
}

// --- S3.3 — Delete port forward ---

func TestDeletePortForwardRule(t *testing.T) {
	t.Run("success posts an empty body to the uuid path", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			expectPost(t, r, "/api/firewall/d_nat/del_rule/pf-1")
			if body := expectBody(t, r, `{}`); len(body) != 2 {
				t.Errorf("body = %q, want empty JSON object {}", body)
			}
			testutil.WriteBody(w, `{"result":"deleted"}`)
		}))
		if err := c.DeletePortForwardRule(context.Background(), "pf-1"); err != nil {
			t.Fatalf("DeletePortForwardRule: %v", err)
		}
	})

	t.Run("not found for a missing uuid is a stable error", func(t *testing.T) {
		var calls int
		c, _ := fastTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			expectPost(t, r, "/api/firewall/d_nat/del_rule/missing")
			expectBody(t, r, `{}`)
			testutil.WriteBody(w, `{"result":"not found"}`)
		}))
		err := c.DeletePortForwardRule(context.Background(), "missing")
		if err == nil || !strings.Contains(err.Error(), `returned "not found"`) {
			t.Errorf("error = %v, want a not-found-result error", err)
		}
		expectExactlyOneRequest(t, calls)
	})
}

// --- S3.4 — Enable/disable port forward ---

func TestTogglePortForwardRule(t *testing.T) {
	t.Run("disable uses the disabled=1 suffix", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			expectPost(t, r, "/api/firewall/d_nat/toggle_rule/pf-1,1")
			expectBody(t, r, `{}`)
			testutil.WriteBody(w, `{"result":"saved"}`)
		}))
		if err := c.TogglePortForwardRule(context.Background(), "pf-1", true); err != nil {
			t.Fatalf("TogglePortForwardRule: %v", err)
		}
	})

	t.Run("enable uses the disabled=0 suffix", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			expectPost(t, r, "/api/firewall/d_nat/toggle_rule/pf-1,0")
			expectBody(t, r, `{}`)
			testutil.WriteBody(w, `{"result":"saved"}`)
		}))
		if err := c.TogglePortForwardRule(context.Background(), "pf-1", false); err != nil {
			t.Fatalf("TogglePortForwardRule: %v", err)
		}
	})

	t.Run("404 on toggle is stable and names the route", func(t *testing.T) {
		var calls int
		c, _ := fastTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			w.WriteHeader(http.StatusNotFound)
		}))
		err := c.TogglePortForwardRule(context.Background(), "missing", true)
		if err == nil || !strings.Contains(err.Error(), "resource not found") || !strings.Contains(err.Error(), "/d_nat/toggle_rule/missing,1") {
			t.Errorf("error = %v, want resource not found naming the toggle route", err)
		}
		expectExactlyOneRequest(t, calls)
	})
}

// --- S3.5 — One-to-one NAT CRUD ---

func TestCreateOneToOneRule(t *testing.T) {
	want := ruleEnvelope(t, "one_to_one", fullOneToOneSpec)

	t.Run("success posts the full one_to_one rule object", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			expectPost(t, r, "/api/firewall/one_to_one/add_rule")
			expectBody(t, r, string(want))
			testutil.WriteBody(w, `{"result":"saved","uuid":"o1"}`)
		}))
		uuid, err := c.CreateOneToOneRule(context.Background(), fullOneToOneSpec)
		if err != nil {
			t.Fatalf("CreateOneToOneRule: %v", err)
		}
		if uuid != "o1" {
			t.Errorf("uuid = %q, want o1", uuid)
		}
	})

	t.Run("validation failure does not retry", func(t *testing.T) {
		var calls int
		c, _ := fastTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			testutil.WriteBody(w, `{"result":"failed","validations":{"type":"Required"}}`)
		}))
		_, err := c.CreateOneToOneRule(context.Background(), natRuleSpec{Interfaces: []string{"wan"}})
		if err == nil || !strings.Contains(err.Error(), "validation failed") {
			t.Errorf("error = %v, want a validation error", err)
		}
		expectExactlyOneRequest(t, calls)
	})

	t.Run("5xx is retried then surfaces", func(t *testing.T) {
		var calls int
		c, _ := fastTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			w.WriteHeader(http.StatusInternalServerError)
		}))
		_, err := c.CreateOneToOneRule(context.Background(), fullOneToOneSpec)
		if err == nil || !strings.Contains(err.Error(), "unexpected status 500") {
			t.Errorf("error = %v, want unexpected status 500", err)
		}
		expectRetryBudget(t, calls)
	})
}

func TestSetOneToOneRule(t *testing.T) {
	want := ruleEnvelope(t, "one_to_one", fullOneToOneSpec)

	t.Run("success posts the full payload to the uuid path", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			expectPost(t, r, "/api/firewall/one_to_one/set_rule/o1")
			expectBody(t, r, string(want))
			testutil.WriteBody(w, `{"result":"saved"}`)
		}))
		if err := c.SetOneToOneRule(context.Background(), "o1", fullOneToOneSpec); err != nil {
			t.Fatalf("SetOneToOneRule: %v", err)
		}
	})

	t.Run("not found for a missing uuid is a stable error", func(t *testing.T) {
		var calls int
		c, _ := fastTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			expectPost(t, r, "/api/firewall/one_to_one/set_rule/missing")
			expectBody(t, r, `{"rule":{"description":"x"}}`)
			testutil.WriteBody(w, `{"result":"not found"}`)
		}))
		err := c.SetOneToOneRule(context.Background(), "missing", natRuleSpec{Label: "x"})
		if err == nil || !strings.Contains(err.Error(), `returned "not found"`) {
			t.Errorf("error = %v, want a not-found-result error", err)
		}
		expectExactlyOneRequest(t, calls)
	})
}

func TestDeleteOneToOneRule(t *testing.T) {
	t.Run("success posts an empty body to the uuid path", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			expectPost(t, r, "/api/firewall/one_to_one/del_rule/o1")
			expectBody(t, r, `{}`)
			testutil.WriteBody(w, `{"result":"deleted"}`)
		}))
		if err := c.DeleteOneToOneRule(context.Background(), "o1"); err != nil {
			t.Fatalf("DeleteOneToOneRule: %v", err)
		}
	})

	t.Run("not found for a missing uuid is a stable error", func(t *testing.T) {
		var calls int
		c, _ := fastTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			testutil.WriteBody(w, `{"result":"not found"}`)
		}))
		err := c.DeleteOneToOneRule(context.Background(), "missing")
		if err == nil || !strings.Contains(err.Error(), `returned "not found"`) {
			t.Errorf("error = %v, want a not-found-result error", err)
		}
		expectExactlyOneRequest(t, calls)
	})
}

// --- S3.6 — Source NAT CRUD ---

func TestCreateSourceNatRule(t *testing.T) {
	want := ruleEnvelope(t, "source_nat", fullSourceNatSpec)

	t.Run("success posts the full source_nat rule object", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			expectPost(t, r, "/api/firewall/source_nat/add_rule")
			expectBody(t, r, string(want))
			testutil.WriteBody(w, `{"result":"saved","uuid":"sn1"}`)
		}))
		uuid, err := c.CreateSourceNatRule(context.Background(), fullSourceNatSpec)
		if err != nil {
			t.Fatalf("CreateSourceNatRule: %v", err)
		}
		if uuid != "sn1" {
			t.Errorf("uuid = %q, want sn1", uuid)
		}
	})

	t.Run("validation failure does not retry", func(t *testing.T) {
		var calls int
		c, _ := fastTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			testutil.WriteBody(w, `{"result":"failed","validations":{"interface":"Required"}}`)
		}))
		_, err := c.CreateSourceNatRule(context.Background(), natRuleSpec{Label: "x"})
		if err == nil || !strings.Contains(err.Error(), "validation failed") {
			t.Errorf("error = %v, want a validation error", err)
		}
		expectExactlyOneRequest(t, calls)
	})

	t.Run("403 is stable single-shot", func(t *testing.T) {
		var calls int
		c, _ := fastTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			w.WriteHeader(http.StatusForbidden)
		}))
		_, err := c.CreateSourceNatRule(context.Background(), fullSourceNatSpec)
		if err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Errorf("error = %v, want permission denied", err)
		}
		expectExactlyOneRequest(t, calls)
	})
}

func TestSetSourceNatRule(t *testing.T) {
	want := ruleEnvelope(t, "source_nat", fullSourceNatSpec)

	t.Run("success posts the full payload to the uuid path", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			expectPost(t, r, "/api/firewall/source_nat/set_rule/sn1")
			expectBody(t, r, string(want))
			testutil.WriteBody(w, `{"result":"saved"}`)
		}))
		if err := c.SetSourceNatRule(context.Background(), "sn1", fullSourceNatSpec); err != nil {
			t.Fatalf("SetSourceNatRule: %v", err)
		}
	})

	t.Run("404 on set is stable and names the route", func(t *testing.T) {
		var calls int
		c, _ := fastTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			w.WriteHeader(http.StatusNotFound)
		}))
		err := c.SetSourceNatRule(context.Background(), "missing", natRuleSpec{Label: "x"})
		if err == nil || !strings.Contains(err.Error(), "resource not found") || !strings.Contains(err.Error(), "/source_nat/set_rule/missing") {
			t.Errorf("error = %v, want resource not found naming the set route", err)
		}
		expectExactlyOneRequest(t, calls)
	})
}

func TestDeleteSourceNatRule(t *testing.T) {
	t.Run("success posts an empty body to the uuid path", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			expectPost(t, r, "/api/firewall/source_nat/del_rule/sn1")
			expectBody(t, r, `{}`)
			testutil.WriteBody(w, `{"result":"deleted"}`)
		}))
		if err := c.DeleteSourceNatRule(context.Background(), "sn1"); err != nil {
			t.Fatalf("DeleteSourceNatRule: %v", err)
		}
	})

	t.Run("failed result is a stable error", func(t *testing.T) {
		var calls int
		c, _ := fastTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			testutil.WriteBody(w, `{"result":"failed"}`)
		}))
		err := c.DeleteSourceNatRule(context.Background(), "missing")
		if err == nil || !strings.Contains(err.Error(), `returned "failed"`) {
			t.Errorf("error = %v, want a failed-result error", err)
		}
		expectExactlyOneRequest(t, calls)
	})
}

// S3.1 — unknown collections are rejected before any request is made.
func TestNatWirePayloadUnknownCollection(t *testing.T) {
	_, err := natWirePayload("alias", natRuleSpec{})
	if err == nil || !strings.Contains(err.Error(), "unknown NAT collection") {
		t.Errorf("error = %v, want unknown NAT collection", err)
	}
}
