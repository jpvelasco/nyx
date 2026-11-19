package opnsense

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

type stateTestTransport func(*http.Request) (*http.Response, error)

func (f stateTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestStateDiagnostics(t *testing.T) {
	c := NewClient("firewall.example", "fixture-key", "fixture-secret", false, "")
	calls := 0
	c.httpClient.Transport = stateTestTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		body := `{"result":"ok"}`
		status := http.StatusOK
		switch strings.TrimPrefix(r.URL.Path, "/api"+stateDiagnostics) {
		case "query_states":
			var q StateQuery
			if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&q) != nil || q.Search != "192.0.2.0/24" || q.Sort["age"] != "desc" || q.Page != 2 || q.PageSize != 1 {
				t.Fatalf("invalid query: %+v", q)
			}
			body = `{"total":2,"current":2,"rowCount":1,"rows":[{"id":"abcd/1234","state":"ESTABLISHED"}]}`
		case "del_state/1234/abcd":
			body = `{"result":"killed 1 states\n"}`
		case "kill_states":
			body = `{"result":"ok","dropped_states":1}`
		case "flush_states":
			status = http.StatusBadGateway
		case "flush_sources":
		case "list_rule_ids":
			body = `{"items":[]}`
		case "pf_states":
			body = `{"current":"1","limit":"100"}`
		default:
			t.Fatalf("unexpected endpoint %s", r.URL.Path)
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})
	ctx := t.Context()
	page, err := c.QueryStates(ctx, StateQuery{Search: "192.0.2.0/24", Sort: map[string]string{"age": "desc"}, Page: 2, PageSize: 1})
	if err != nil || page.Total != 2 || len(page.Rows) != 1 {
		t.Fatalf("page=%+v err=%v", page, err)
	}
	if _, err = c.DeleteState(ctx, "abcd/1234"); err != nil {
		t.Fatal(err)
	}
	killed, err := c.KillStates(ctx, "192.0.2.1", "")
	if err != nil || killed.Dropped == nil || *killed.Dropped != 1 {
		t.Fatalf("killed=%+v err=%v", killed, err)
	}
	before := calls
	if _, err = c.KillStates(ctx, "192.0.2.0/24", ""); err == nil || calls != before {
		t.Fatal("lossy selector must fail locally")
	}
	if _, err = c.FlushStates(ctx); err == nil || calls != before+1 {
		t.Fatal("failed flush must not replay")
	}
	if _, err = c.FlushSources(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = c.StateRuleIDs(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = c.StateCapacity(ctx); err != nil {
		t.Fatal(err)
	}
}
