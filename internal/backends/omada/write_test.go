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
		SourceType: "network",
		SourceIDs:  []string{"n2"},
		SourceName: "IoT",
		DestType:   "network",
		DestIDs:    []string{"n1"},
		DestName:   "Trusted",
	}
}

func TestCreateACLRule(t *testing.T) {
	var gotMethod, gotCT, gotBody string
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/abc123/api/v2/sites/s1/setting/firewall/acls" {
			t.Errorf("path = %q, want ACL create path", r.URL.Path)
		}
		gotMethod = r.Method
		gotCT = r.Header.Get("Content-Type")
		gotBody = readBody(t, r)
		writeEnvelope(w, 0, "", `{"id":"a9","name":"block-iot","status":true,"type":1,"policy":0,"protocols":[256],"sourceType":"network","sourceIds":["n2"],"destinationType":"network","destinationIds":["n1"],"index":4}`)
	}))

	created, err := c.CreateACLRule(context.Background(), "s1", sampleSwitchRule())
	if err != nil {
		t.Fatalf("CreateACLRule: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if !strings.Contains(gotCT, "application/json") {
		t.Errorf("content-type = %q, want application/json", gotCT)
	}
	if created == nil || created.ID != "a9" || created.Policy != ACLPolicyDeny || created.Index != 4 {
		t.Fatalf("created = %+v, want decoded rule a9", created)
	}

	var body aclRuleWrite
	if err := json.Unmarshal([]byte(gotBody), &body); err != nil {
		t.Fatalf("request body %q not valid JSON: %v", gotBody, err)
	}
	if body.Name != "block-iot" || !body.Status || body.Policy != ACLPolicyDeny || body.Type != ACLTypeSwitch {
		t.Errorf("body = %+v, want name/status/deny/switch", body)
	}
	if len(body.Protocols) != 1 || body.Protocols[0] != ProtocolAll {
		t.Errorf("body protocols = %v, want [256]", body.Protocols)
	}
	if body.SourceType != "network" || len(body.SourceIDs) != 1 || body.SourceIDs[0] != "n2" {
		t.Errorf("body source = %+v, want network n2", body)
	}
	if body.DestType != "network" || len(body.DestIDs) != 1 || body.DestIDs[0] != "n1" {
		t.Errorf("body dest = %+v, want network n1", body)
	}
	if strings.Contains(gotBody, `"srcName"`) || strings.Contains(gotBody, `"sourceName"`) {
		t.Errorf("body = %q, must not include resolved names", gotBody)
	}
}

func TestCreateACLRule_ControllerError(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, -1005, "no permission", "null")
	}))
	_, err := c.CreateACLRule(context.Background(), "s1", ACLRule{Name: "x", Type: ACLTypeSwitch})
	if err == nil || !strings.Contains(err.Error(), "creating ACL rule") {
		t.Fatalf("CreateACLRule error = %v, want wrapping error", err)
	}
}

func TestCreateACLRule_DefaultsEmptyProtocolsToAll(t *testing.T) {
	var gotBody string
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody = readBody(t, r)
		writeEnvelope(w, 0, "", `{"id":"a1"}`)
	}))
	rule := sampleSwitchRule()
	rule.Protocols = nil
	if _, err := c.CreateACLRule(context.Background(), "s1", rule); err != nil {
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

func TestUpdateACLRule(t *testing.T) {
	var gotMethod, gotBody string
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/abc123/api/v2/sites/s1/setting/firewall/acls/a1" {
			t.Errorf("path = %q, want ACL update path with rule id", r.URL.Path)
		}
		gotMethod = r.Method
		gotBody = readBody(t, r)
		writeEnvelope(w, 0, "", `{"id":"a1","name":"block-iot","status":false,"type":1,"policy":0,"protocols":[256],"sourceType":"network","sourceIds":["n2"],"destinationType":"network","destinationIds":["n1"],"index":4}`)
	}))

	rule := sampleSwitchRule()
	rule.ID = "a1"
	rule.Status = false
	updated, err := c.UpdateACLRule(context.Background(), "s1", "a1", rule)
	if err != nil {
		t.Fatalf("UpdateACLRule: %v", err)
	}
	if gotMethod != http.MethodPut {
		t.Errorf("method = %q, want PUT", gotMethod)
	}
	if updated == nil || updated.ID != "a1" || updated.Status {
		t.Fatalf("updated = %+v, want disabled rule a1", updated)
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
}

func TestUpdateACLRule_ControllerError(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, -1005, "no permission", "null")
	}))
	_, err := c.UpdateACLRule(context.Background(), "s1", "a1", ACLRule{Name: "x"})
	if err == nil || !strings.Contains(err.Error(), "updating ACL rule") {
		t.Fatalf("UpdateACLRule error = %v, want wrapping error", err)
	}
}

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
	if gotPath != "/abc123/api/v2/sites/s1/setting/firewall/acls/a1" {
		t.Errorf("path = %q, want delete item path", gotPath)
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
