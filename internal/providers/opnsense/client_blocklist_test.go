package opnsense

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/testutil"
)

func TestBlocklistOperations(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/firewall/alias_util/aliases":
			testutil.WriteBody(w, `["sshlockout"]`)
		case "/api/firewall/alias_util/list/sshlockout":
			var query map[string]any
			if err := json.NewDecoder(r.Body).Decode(&query); err != nil || query["searchPhrase"] != "192.0.2" {
				t.Errorf("query = %+v, %v", query, err)
			}
			testutil.WriteBody(w, `{"total":1,"rows":[{"ip":"192.0.2.1"}]}`)
		case "/api/firewall/alias_util/list/empty":
			testutil.WriteBody(w, `{"total":0,"rows":[]}`)
		case "/api/firewall/alias_util/find_references":
			testutil.WriteBody(w, `{"status":"done","matches":[]}`)
		case "/api/firewall/alias_util/delete/sshlockout":
			testutil.WriteBody(w, `{"status":"done"}`)
		case "/api/firewall/alias_util/flush/sshlockout":
			testutil.WriteBody(w, `{"status":"failed"}`)
		case "/api/firewall/alias_util/flush/denied":
			w.WriteHeader(http.StatusForbidden)
		default:
			t.Errorf("unexpected operation %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	})
	ctx := t.Context()
	if tables, err := c.ListBlocklistTables(ctx); err != nil || len(tables) != 1 || tables[0] != "sshlockout" {
		t.Fatalf("tables = %v, %v", tables, err)
	}
	if rows, err := c.ListBlocklist(ctx, "sshlockout", "192.0.2"); err != nil || len(rows) != 1 {
		t.Fatalf("rows = %v, %v", rows, err)
	}
	if rows, err := c.ListBlocklist(ctx, "empty", ""); err != nil || rows == nil || len(rows) != 0 {
		t.Fatalf("empty rows = %v, %v", rows, err)
	}
	if _, err := c.ListBlocklist(ctx, "../bad", ""); err == nil {
		t.Error("accepted invalid table")
	}
	if refs, err := c.BlocklistReferences(ctx, "192.0.2.1"); err != nil || !strings.Contains(string(refs), "matches") {
		t.Fatalf("references = %s, %v", refs, err)
	}
	if _, err := c.BlocklistReferences(ctx, "invalid"); err == nil {
		t.Error("accepted invalid reference input")
	}
	for _, tc := range []struct {
		action, table, address, want string
		confirmed                    bool
	}{
		{"unblock", "sshlockout", "192.0.2.1", "dry_run", false},
		{"unblock", "sshlockout", "192.0.2.1", "acknowledged", true},
		{"unblock", "sshlockout", "ALL", "", true},
		{"unknown", "sshlockout", "", "", true},
		{"flush", "../bad", "", "", true},
		{"flush", "sshlockout", "", "", true},
		{"flush", "denied", "", "", true},
	} {
		got, err := c.UpdateBlocklist(ctx, tc.action, tc.table, tc.address, tc.confirmed)
		if tc.want == "" && err == nil || tc.want != "" && (err != nil || got.Status != tc.want) {
			t.Errorf("update %s %s = %+v, %v; want status %q", tc.action, tc.table, got, err, tc.want)
		}
	}
}
