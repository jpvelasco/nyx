package omada

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func readBody(t *testing.T, r *http.Request) string {
	t.Helper()
	data, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("reading request body: %v", err)
	}
	return string(data)
}

func sampleSwitchRule() ACLRule {
	return ACLRule{
		Name:       "block-iot",
		Type:       ACLTypeSwitch,
		Status:     true,
		Policy:     ACLPolicyDeny,
		Protocols:  []int{ProtocolAll},
		SourceType: EndpointNetwork,
		SourceIDs:  []string{"n2"},
		SourceName: "IoT",
		DestType:   EndpointNetwork,
		DestIDs:    []string{"n1"},
		DestName:   "Trusted",
	}
}

// BDD S4.1: switch-scope create POSTs the per-scope collection, carries the
// writable body without a rule type, and tolerates a create response with no
// payload (the controller does not return the new rule id).
func TestCreateACLRule_Switch(t *testing.T) {
	var gotMethod, gotCT, gotBody string
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/openapi/v1/abc123/sites/s1/acls/osw-acls" {
			t.Errorf("path = %q, want switch create path", r.URL.Path)
		}
		gotMethod = r.Method
		gotCT = r.Header.Get("Content-Type")
		gotBody = readBody(t, r)
		writeEnvelope(w, 0, "", "null")
	}))

	if err := c.CreateACLRule(context.Background(), "s1", sampleSwitchRule()); err != nil {
		t.Fatalf("CreateACLRule: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if !strings.Contains(gotCT, "application/json") {
		t.Errorf("content-type = %q, want application/json", gotCT)
	}

	var body aclRuleWrite
	if err := json.Unmarshal([]byte(gotBody), &body); err != nil {
		t.Fatalf("request body %q not valid JSON: %v", gotBody, err)
	}
	if body.Name != "block-iot" || !body.Status || body.Policy != ACLPolicyDeny {
		t.Errorf("body = %+v, want name/status/deny", body)
	}
	if len(body.Protocols) != 1 || body.Protocols[0] != ProtocolAll {
		t.Errorf("body protocols = %v, want [256]", body.Protocols)
	}
	if body.SourceType != EndpointNetwork || len(body.SourceIDs) != 1 || body.SourceIDs[0] != "n2" {
		t.Errorf("body source = %+v, want network n2", body)
	}
	if body.DestType != EndpointNetwork || len(body.DestIDs) != 1 || body.DestIDs[0] != "n1" {
		t.Errorf("body dest = %+v, want network n1", body)
	}
	if !strings.Contains(gotBody, `"sourceType":0`) {
		t.Errorf("body = %q, want sourceType encoded as 0", gotBody)
	}
	if !strings.Contains(gotBody, `"bindingType":0`) {
		t.Errorf("body = %q, want bindingType 0 (all ports) on switch-scope create", gotBody)
	}
	if !strings.Contains(gotBody, `"etherType":{"enable":false}`) {
		t.Errorf("body = %q, want etherType disabled", gotBody)
	}
	if !strings.Contains(gotBody, `"biDirectional":false`) {
		t.Errorf("body = %q, want biDirectional false", gotBody)
	}
	if strings.Contains(gotBody, `"type"`) {
		t.Errorf("body = %q, must not include a rule type field", gotBody)
	}
	if strings.Contains(gotBody, `"srcName"`) || strings.Contains(gotBody, `"sourceName"`) {
		t.Errorf("body = %q, must not include resolved names", gotBody)
	}
}

// BDD S4.2: gateway-scope create POSTs osg-acls with syslog, stateMode,
// states, and direction; it omits bindingType.
func TestCreateACLRule_Gateway(t *testing.T) {
	var gotBody string
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/openapi/v1/abc123/sites/s1/acls/osg-acls" {
			t.Errorf("path = %q, want gateway create path", r.URL.Path)
		}
		gotBody = readBody(t, r)
		writeEnvelope(w, 0, "", "null")
	}))

	rule := ACLRule{
		Name:       "deny-iot",
		Type:       ACLTypeGateway,
		Status:     true,
		Policy:     ACLPolicyDeny,
		Protocols:  []int{ProtocolAll},
		SourceType: EndpointNetwork,
		SourceIDs:  []string{"n2"},
		DestType:   EndpointNetwork,
		DestIDs:    []string{"n1"},
		Direction:  ACLDirection{LANToLAN: true},
	}
	if err := c.CreateACLRule(context.Background(), "s1", rule); err != nil {
		t.Fatalf("CreateACLRule: %v", err)
	}
	if !strings.Contains(gotBody, `"syslog":true`) {
		t.Errorf("body = %q, want syslog true", gotBody)
	}
	if !strings.Contains(gotBody, `"stateMode":0`) {
		t.Errorf("body = %q, want stateMode 0", gotBody)
	}
	for _, key := range []string{"stateNew", "established", "related", "invalid"} {
		if !strings.Contains(gotBody, key) {
			t.Errorf("body = %q, want %s in states", gotBody, key)
		}
	}
	if !strings.Contains(gotBody, `"lanToLan":true`) {
		t.Errorf("body = %q, want direction lanToLan", gotBody)
	}
	if strings.Contains(gotBody, `"bindingType"`) {
		t.Errorf("body = %q, must not include bindingType on gateway scope", gotBody)
	}
	if strings.Contains(gotBody, `"type"`) {
		t.Errorf("body = %q, must not include a rule type field", gotBody)
	}
}

func TestRuleToWrite_BindingTypePerScope(t *testing.T) {
	gw := ruleToWrite(ACLRule{Name: "g", Type: ACLTypeGateway})
	if gw.BindingType != nil {
		t.Errorf("gateway body bindingType = %v, want omitted (nil)", *gw.BindingType)
	}

	sw := ruleToWrite(sampleSwitchRule())
	if sw.BindingType == nil || *sw.BindingType != 0 {
		t.Errorf("switch create bindingType = %v, want 0 (all ports)", sw.BindingType)
	}

	// Updates must preserve a non-zero read value (e.g. custom ports).
	custom := sampleSwitchRule()
	custom.BindingType = 1
	got := ruleToWrite(custom)
	if got.BindingType == nil || *got.BindingType != 1 {
		t.Errorf("switch update bindingType = %v, want preserved 1", got.BindingType)
	}
}

func TestCreateACLRule_ControllerError(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, -1005, "no permission", "null")
	}))
	err := c.CreateACLRule(context.Background(), "s1", ACLRule{Name: "x", Type: ACLTypeSwitch})
	if err == nil || !strings.Contains(err.Error(), "creating ACL rule") {
		t.Fatalf("CreateACLRule error = %v, want wrapping error", err)
	}
}

func TestCreateACLRule_DefaultsEmptyProtocolsToAll(t *testing.T) {
	var gotBody string
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody = readBody(t, r)
		writeEnvelope(w, 0, "", "null")
	}))
	rule := sampleSwitchRule()
	rule.Protocols = nil
	if err := c.CreateACLRule(context.Background(), "s1", rule); err != nil {
		t.Fatalf("CreateACLRule: %v", err)
	}
	var body aclRuleWrite
	if err := json.Unmarshal([]byte(gotBody), &body); err != nil {
		t.Fatalf("body: %v", err)
	}
	if len(body.Protocols) != 1 || body.Protocols[0] != ProtocolAll {
		t.Errorf("protocols = %v, want [256] default", body.Protocols)
	}
}

// BDD S4.3: update PUTs the full writable payload to the per-scope item
// path and tolerates a payload-less response.
func TestUpdateACLRule(t *testing.T) {
	var gotMethod, gotBody string
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/openapi/v1/abc123/sites/s1/acls/osw-acls/a1" {
			t.Errorf("path = %q, want per-scope ACL update path", r.URL.Path)
		}
		gotMethod = r.Method
		gotBody = readBody(t, r)
		writeEnvelope(w, 0, "", "null")
	}))

	rule := sampleSwitchRule()
	rule.ID = "a1"
	rule.Status = false
	if err := c.UpdateACLRule(context.Background(), "s1", "a1", rule); err != nil {
		t.Fatalf("UpdateACLRule: %v", err)
	}
	if gotMethod != http.MethodPut {
		t.Errorf("method = %q, want PUT", gotMethod)
	}

	var body aclRuleWrite
	if err := json.Unmarshal([]byte(gotBody), &body); err != nil {
		t.Fatalf("request body %q not valid JSON: %v", gotBody, err)
	}
	if body.Status {
		t.Errorf("body status = true, want false (full payload with new status)")
	}
	if body.Name != "block-iot" || body.Policy != ACLPolicyDeny || body.SourceIDs[0] != "n2" || body.DestIDs[0] != "n1" {
		t.Errorf("body = %+v, want full writable payload", body)
	}
	if strings.Contains(gotBody, `"id"`) {
		t.Errorf("body = %q, must not include the rule id", gotBody)
	}
	if strings.Contains(gotBody, `"type"`) {
		t.Errorf("body = %q, must not include a rule type field", gotBody)
	}
}

func TestUpdateACLRule_ControllerError(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, -1005, "no permission", "null")
	}))
	err := c.UpdateACLRule(context.Background(), "s1", "a1", ACLRule{Name: "x"})
	if err == nil || !strings.Contains(err.Error(), "updating ACL rule") {
		t.Fatalf("UpdateACLRule error = %v, want wrapping error", err)
	}
}

// BDD S4.4: delete uses the scope-agnostic item path.
func TestDeleteACLRule(t *testing.T) {
	var gotMethod, gotPath string
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		writeEnvelope(w, 0, "", "null")
	}))
	if err := c.DeleteACLRule(context.Background(), "s1", "a1"); err != nil {
		t.Fatalf("DeleteACLRule: %v", err)
	}
	if gotMethod != http.MethodDelete {
		t.Errorf("method = %q, want DELETE", gotMethod)
	}
	if gotPath != "/openapi/v1/abc123/sites/s1/acls/a1" {
		t.Errorf("path = %q, want scope-agnostic delete path", gotPath)
	}
}

func TestDeleteACLRule_ControllerError(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, -1005, "no permission", "null")
	}))
	err := c.DeleteACLRule(context.Background(), "s1", "a1")
	if err == nil || !strings.Contains(err.Error(), "deleting ACL rule") {
		t.Fatalf("DeleteACLRule error = %v, want wrapping error", err)
	}
}

func TestPut_MarshalError(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("no request must be sent when marshaling fails")
	}))
	err := c.put(context.Background(), "x", func() {}, nil)
	if err == nil || !strings.Contains(err.Error(), "marshaling request body") {
		t.Fatalf("put error = %v, want marshal error", err)
	}
}
