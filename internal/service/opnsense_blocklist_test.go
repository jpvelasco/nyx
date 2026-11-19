package service

import (
	"net/http"
	"testing"

	"github.com/jpvelasco/nyx/internal/testutil"
)

func TestOpnsenseServiceBlocklist(t *testing.T) {
	ts := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/firewall/alias_util/aliases":
			testutil.WriteBody(w, `["sshlockout"]`)
		case "/api/firewall/alias_util/list/sshlockout":
			testutil.WriteBody(w, `{"total":1,"rows":[{"ip":"192.0.2.1"}]}`)
		case "/api/firewall/alias_util/find_references":
			testutil.WriteBody(w, `{"status":"done","matches":[]}`)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	})
	svc, opts := NewOpnsenseService(), opnsenseOptions(ts)
	ctx := t.Context()
	if tables, err := svc.ListBlocklistTables(ctx, opts); err != nil || len(tables) != 1 {
		t.Fatalf("tables = %v, %v", tables, err)
	}
	if entries, err := svc.ListBlocklist(ctx, opts, "sshlockout", ""); err != nil || len(entries) != 1 {
		t.Fatalf("entries = %v, %v", entries, err)
	}
	if references, err := svc.BlocklistReferences(ctx, opts, "192.0.2.1"); err != nil || len(references) == 0 {
		t.Fatalf("references = %s, %v", references, err)
	}
	if got, err := svc.UpdateBlocklist(ctx, opts, "flush", "sshlockout", "", false); err != nil || got.Status != "dry_run" {
		t.Fatalf("preview = %+v, %v", got, err)
	}
}
