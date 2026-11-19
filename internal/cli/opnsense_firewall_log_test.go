package cli

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/testutil"
	"github.com/spf13/cobra"
)

func TestOpnsenseFirewallLogCommands(t *testing.T) {
	for _, tc := range []struct {
		name, path, query, response, want string
		command                           func() *cobra.Command
		args                              []string
	}{
		{"logs", "/api/diagnostics/firewall/log", "limit=50", `[{"action":"pass","__digest__":"0123456789abcdef0123456789abcdef"}]`, `"action": "pass"`, buildOpnsenseFirewallLogCmd, []string{"--limit", "50"}},
		{"stats", "/api/diagnostics/firewall/stats", "group_by=action&limit=50", `[{"label":"pass","value":3}]`, `"label": "pass"`, buildOpnsenseFirewallLogStatsCmd, []string{"--limit", "50", "--group-by", "action"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			saveRestoreGlobals(t)
			ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != tc.path || r.URL.RawQuery != tc.query {
					t.Errorf("unexpected request %s %s", r.Method, r.URL)
				}
				testutil.WriteBody(w, tc.response)
			}))
			t.Cleanup(ts.Close)
			cmd := tc.command()
			cmd.SetArgs(tc.args)
			providerHost, providerSkipTLS = ts.URL, true
			var err error
			out := captureStdout(func() { err = cmd.Execute() })
			if err != nil || !strings.Contains(out, tc.want) {
				t.Fatalf("output = %q, %v; want %q", out, err, tc.want)
			}
		})
	}
}
