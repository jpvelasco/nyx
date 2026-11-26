package omada

import (
	"encoding/json"
	"net/http"
	"slices"
	"testing"
)

func TestACLOrderWire(t *testing.T) {
	rows := `{"totalRows":2,"data":[{"id":"b","index":7},{"id":"a","index":2}]}`
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeEnvelope(w, 0, "", rows)
		case http.MethodPost:
			var order struct {
				Type    string
				Indexes map[string]int
			}
			if err := json.NewDecoder(r.Body).Decode(&order); err != nil || order.Type != "eap" || order.Indexes["b"] != 2 || order.Indexes["a"] != 7 {
				t.Errorf("unexpected order: %+v %v", order, err)
			}
			writeEnvelope(w, 0, "", `{}`)
		default:
			t.Error("unexpected method")
		}
	}))
	got, err := c.ACLOrder(t.Context(), "site", ACLTypeEAP)
	if err != nil || !slices.Equal(got, []ACLPosition{{ID: "a", Index: 2}, {ID: "b", Index: 7}}) {
		t.Fatalf("read: %+v %v", got, err)
	}
	if err := c.SetACLOrder(t.Context(), "site", ACLTypeEAP, []ACLPosition{{ID: "b", Index: 2}, {ID: "a", Index: 7}}); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{`{"totalRows":1,"data":[{"id":"a"}]}`, `{"totalRows":2,"data":[{"id":"a","index":1},{"id":"a","index":2}]}`} {
		rows = invalid
		if _, err := c.ACLOrder(t.Context(), "site", ACLTypeEAP); err == nil {
			t.Error("accepted ambiguous order")
		}
	}
}

func TestEAPRuleContentWritesRemainUnavailable(t *testing.T) {
	c := new(Client)
	rule := ACLRule{Type: ACLTypeEAP}
	if err := c.CreateACLRule(t.Context(), "site", rule); err == nil {
		t.Error("EAP rule creation accepted")
	}
	if err := c.UpdateACLRule(t.Context(), "site", "rule", rule); err == nil {
		t.Error("EAP rule edit accepted")
	}
}
