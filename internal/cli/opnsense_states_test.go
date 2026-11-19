package cli

import (
	"github.com/jpvelasco/nyx/internal/testutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOpnsenseStatesConfirmation(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"list", "--sort", "invalid"}, "requires field:asc"},
		{[]string{"kill", "--state", "abcd/1234"}, "requires --confirm"},
		{[]string{"kill", "--confirm"}, "supply --state"},
		{[]string{"kill", "--state", "abcd/1234", "--filter", "fixture", "--confirm"}, "supply --state"},
		{[]string{"flush-states"}, "requires --confirm"},
		{[]string{"flush-sources", "--confirm=false"}, "requires --confirm"},
	} {
		cmd := buildOpnsenseStatesCmd()
		cmd.SetArgs(tc.args)
		if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v returned %v", tc.args, err)
		}
	}
}

func TestOpnsenseStatesCommands(t *testing.T) {
	saveRestoreGlobals(t)
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body string
		switch r.Method + " " + r.URL.Path {
		case "POST /api/diagnostics/firewall/query_states":
			body = `{"current":1,"rowCount":1,"total":1,"rows":[{"id":"abcd/1234"}]}`
		case "POST /api/diagnostics/firewall/del_state/1234/abcd":
			body = `{"result":"killed 1 states"}`
		case "POST /api/diagnostics/firewall/kill_states":
			body = `{"result":"ok","dropped_states":1}`
		case "POST /api/diagnostics/firewall/flush_states", "POST /api/diagnostics/firewall/flush_sources":
			body = `{"result":"ok"}`
		case "GET /api/diagnostics/firewall/list_rule_ids":
			body = `{"items":[]}`
		case "GET /api/diagnostics/firewall/pf_states":
			body = `{"current":"1","limit":"100"}`
		default:
			t.Errorf("unexpected endpoint %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		if _, err := testutil.WriteBody(w, body); err != nil {
			t.Errorf("writing fixture: %v", err)
		}
	}))
	t.Cleanup(ts.Close)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"list", "--sort", "age:desc"}, `"id": "abcd/1234"`},
		{[]string{"kill", "--state", "abcd/1234", "--confirm"}, `"result": "killed 1 states"`},
		{[]string{"kill", "--filter", "192.0.2.1", "--confirm"}, `"dropped_states": 1`},
		{[]string{"flush-states", "--confirm"}, `"result": "ok"`},
		{[]string{"flush-sources", "--confirm"}, `"result": "ok"`},
		{[]string{"rule-ids"}, `"items": []`},
		{[]string{"capacity"}, `"limit": "100"`},
	} {
		cmd := buildOpnsenseStatesCmd()
		cmd.SetArgs(append(tc.args, "--host", ts.URL, "--api-key", "fixture-key", "--api-secret", "fixture-secret", "--skip-tls-verify"))
		out := captureStdout(func() {
			if err := cmd.Execute(); err != nil {
				t.Error(err)
			}
		})
		if !strings.Contains(out, tc.want) {
			t.Errorf("%v output=%q missing %q", tc.args, out, tc.want)
		}
	}
}
