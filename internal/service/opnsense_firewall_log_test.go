package service

import (
	"net/http"
	"testing"

	"github.com/jpvelasco/nyx/internal/testutil"
)

func TestOpnsenseServiceFirewallLogs(t *testing.T) {
	ts := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/diagnostics/firewall/log":
			testutil.WriteBody(w, `[{"action":"pass","__digest__":"0123456789abcdef0123456789abcdef"}]`)
		case "/api/diagnostics/firewall/stats":
			testutil.WriteBody(w, `[{"label":"lan","value":3}]`)
		default:
			t.Errorf("unexpected endpoint: %s", r.URL.Path)
			http.NotFound(w, r)
		}
	})
	svc := NewOpnsenseService()
	opts := opnsenseOptions(ts)
	page, err := svc.FirewallLog(t.Context(), opts, OpnsenseFirewallLogQuery{})
	if err != nil || len(page.Rows) != 1 || page.Rows[0].Action != "pass" {
		t.Fatalf("firewall log = %+v, %v", page, err)
	}
	stats, err := svc.FirewallLogStats(t.Context(), opts, 0, "")
	if err != nil || len(stats) != 1 || stats[0].Value != 3 {
		t.Fatalf("firewall stats = %+v, %v", stats, err)
	}
}
