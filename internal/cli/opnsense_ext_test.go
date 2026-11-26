package cli

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/testutil"
	"github.com/spf13/cobra"
)

func TestOpnsenseFirewallListCommands(t *testing.T) {
	for _, tc := range []struct {
		command string
		path    string
		body    string
		want    string
	}{
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

func TestRoutedVLANManualHandoffCommands(t *testing.T) {
	saveRestoreGlobals(t)
	controller := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Error("manual handoff must only read")
		}
		if strings.HasSuffix(r.URL.Path, "/vlan_settings/search_item") {
			testutil.WriteBody(w, `{"total":1,"rows":[{"uuid":"v1","if":"igb0","tag":"30","vlanif":"vlan30"}]}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer controller.Close()
	t.Setenv("NYX_CREDENTIALS_FILE", t.TempDir()+"/credentials.json")
	for _, cmd := range []*cobra.Command{buildOpnsensePlanVLANCmd(), buildOpnsenseApplyVLANCmd()} {
		providerHost = controller.URL
		providerClientID = "fixture"
		providerClientSecret = "fixture"
		providerSkipTLS = true
		jsonOutput = false
		cmd.SetArgs([]string{"--kind", "assignment", "--tag", "30", "--parent", "igb0", "--description", "gaming", "--address", "10.0.30.1/24"})
		var err error
		out := captureStdout(func() { err = cmd.Execute() })
		if strings.Contains(out, "(dry-run)") != (cmd.Name() == "apply-vlan") {
			t.Errorf("%s preview label: %q", cmd.Name(), out)
		}
		if err != nil || !strings.Contains(out, "manual gaming") || !strings.Contains(out, "GUI") {
			t.Fatalf("%s: %s %v", cmd.Name(), out, err)
		}
	}
}
