package cli

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/testutil"
)

func TestOpnsenseFirewallListCommands(t *testing.T) {
	for _, tc := range []struct {
		command string
		path    string
		body    string
		want    string
	}{
		{"dnsmasq-settings", "/api/dnsmasq/settings/get", `{"dnsmasq":{"enable":"1","dhcp":{"enable_ra":"0"},"dhcp_ranges":{"media":{"start_addr":"10.0.50.1","end_addr":"10.0.50.5","interface":{"opt1":{"selected":1}}}}}}`, `"interface": "opt1"`},
		{"kea-status", "/api/kea/service/status", `{"running":false}`, `"running": false`},
		{"list-router-advertisements", "/api/radvd/settings/search_entry", `{"total":1,"rows":[{"interface":"opt1","enabled":"0","mode":"managed"}]}`, `"state": "disabled"`},
		{"list-aliases", "/api/firewall/alias/search_item", `{"total":1,"rows":[{"uuid":"alias-1","name":"servers","enabled":"1"}]}`, `"name": "servers"`},
		{"list-firewall-rules", "/api/firewall/filter/search_rule", `{"total":1,"rows":[{"uuid":"rule-1","description":"Allow servers","enabled":"1"}]}`, `Allow servers`},
	} {
		t.Run(tc.command, func(t *testing.T) {
			saveRestoreGlobals(t)
			t.Setenv("NYX_CREDENTIALS_FILE", t.TempDir()+"/credentials.json")
			controller := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != tc.path {
					t.Errorf("request = %s %s, want GET %s", r.Method, r.URL.Path, tc.path)
				}
				testutil.WriteBody(w, tc.body)
			}))
			defer controller.Close()
			for _, cmd := range buildOpnsenseExtraCommands() {
				if cmd.Name() != tc.command {
					continue
				}
				providerHost = controller.URL
				providerClientID = "fixture-key"
				providerClientSecret = "fixture-secret"
				providerSkipTLS = true
				var err error
				output := captureStdout(func() { err = cmd.RunE(cmd, nil) })
				if err != nil || !strings.Contains(output, tc.want) {
					t.Fatalf("output = %q, error = %v; want %q", output, err, tc.want)
				}
				return
			}
			t.Fatalf("command %q was not registered", tc.command)
		})
	}
}
