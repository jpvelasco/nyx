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

func TestCreateACLRule(t *testing.T) {
	var gotMethod, gotCT, gotBody string
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/abc123/api/v2/sites/s1/setting/firewall/acl" {
			t.Errorf("path = %q, want ACL create path", r.URL.Path)
		}
		gotMethod = r.Method
		gotCT = r.Header.Get("Content-Type")
		gotBody = readBody(t, r)
		writeEnvelope(w, 0, "", `{"id":"a9","name":"block-iot","status":true,"policy":"drop","protocols":"all","srcType":"network","srcId":"n2","srcName":"IoT","dstType":"network","dstId":"n1","dstName":"Trusted","index":4}`)
	}))

	rule := ACLRule{
		Name:       "block-iot",
		Status:     true,
		Policy:     "drop",
		Protocols:  "all",
		SourceType: "network",
		SourceID:   "n2",
		SourceName: "IoT",
		DestType:   "network",
		DestID:     "n1",
		DestName:   "Trusted",
	}
	created, err := c.CreateACLRule(context.Background(), "s1", rule)
	if err != nil {
		t.Fatalf("CreateACLRule: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if !strings.Contains(gotCT, "application/json") {
		t.Errorf("content-type = %q, want application/json", gotCT)
	}
	if created == nil || created.ID != "a9" || created.Policy != "drop" || created.Index != 4 {
		t.Fatalf("created = %+v, want decoded rule a9", created)
	}

	var body aclRuleWrite
	if err := json.Unmarshal([]byte(gotBody), &body); err != nil {
		t.Fatalf("request body %q not valid JSON: %v", gotBody, err)
	}
	if body.Name != "block-iot" || !body.Status || body.Policy != "drop" || body.Protocols != "all" {
		t.Errorf("body = %+v, want name/status/policy/protocols", body)
	}
	if body.SourceType != "network" || body.SourceID != "n2" || body.SourceName != "IoT" {
		t.Errorf("body source = %+v, want network n2 IoT", body)
	}
	if body.DestType != "network" || body.DestID != "n1" || body.DestName != "Trusted" {
		t.Errorf("body dest = %+v, want network n1 Trusted", body)
	}
}

func TestCreateACLRule_ControllerError(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, -1005, "no permission", "null")
	}))
	_, err := c.CreateACLRule(context.Background(), "s1", ACLRule{Name: "x"})
	if err == nil || !strings.Contains(err.Error(), "creating ACL rule") {
		t.Fatalf("CreateACLRule error = %v, want wrapping error", err)
	}
}

func TestUpdateACLRule(t *testing.T) {
	var gotMethod, gotBody string
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/abc123/api/v2/sites/s1/setting/firewall/acl/a1" {
			t.Errorf("path = %q, want ACL update path with rule id", r.URL.Path)
		}
		gotMethod = r.Method
		gotBody = readBody(t, r)
		writeEnvelope(w, 0, "", `{"id":"a1","name":"block-iot","status":false,"policy":"drop","protocols":"all","srcType":"network","srcId":"n2","srcName":"IoT","dstType":"network","dstId":"n1","dstName":"Trusted","index":4}`)
	}))

	rule := ACLRule{
		ID:         "a1",
		Name:       "block-iot",
		Status:     false,
		Policy:     "drop",
		Protocols:  "all",
		SourceType: "network",
		SourceID:   "n2",
		SourceName: "IoT",
		DestType:   "network",
		DestID:     "n1",
		DestName:   "Trusted",
	}
	updated, err := c.UpdateACLRule(context.Background(), "s1", "a1", rule)
	if err != nil {
		t.Fatalf("UpdateACLRule: %v", err)
	}
	if gotMethod != http.MethodPatch {
		t.Errorf("method = %q, want PATCH", gotMethod)
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
	if body.Name != "block-iot" || body.Policy != "drop" || body.SourceID != "n2" || body.DestID != "n1" {
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

func TestPatch_MarshalError(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("no request must be sent when marshaling fails")
	}))
	err := c.patch(context.Background(), "x", func() {}, nil)
	if err == nil || !strings.Contains(err.Error(), "marshaling request body") {
		t.Fatalf("patch error = %v, want marshal error", err)
	}
}
