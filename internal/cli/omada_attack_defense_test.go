package cli

import (
	"github.com/jpvelasco/nyx/internal/testutil"
	"github.com/spf13/cobra"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestOmadaUnblockConfirmation(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--mac", "00:00:00:00:00:01"}, "requires --confirm"},
		{[]string{"--confirm"}, "requires --mac"},
	} {
		cmd := buildOmadaUnblockClientCmd()
		cmd.SetArgs(tc.args)
		if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v returned %v", tc.args, err)
		}
	}
}

func TestOmadaAttackDefenseCommands(t *testing.T) {
	saveRestoreOmadaExtGlobals(t)
	var rejectSettings atomic.Bool
	const prefix = "/openapi/v1/controller/sites/site/"
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body string
		switch r.Method + " " + r.URL.Path {
		case "GET /api/info":
			body = `{"errorCode":0,"result":{"omadacId":"controller","controllerVer":"6.3.0"}}`
		case "POST /openapi/authorize/token":
			body = `{"errorCode":0,"result":{"accessToken":"fixture"}}`
		case "GET /openapi/v1/controller/sites":
			body = `{"errorCode":0,"result":{"totalRows":1,"data":[{"id":"site","name":"example"}]}}`
		case "GET " + prefix + "attack-defense":
			if rejectSettings.Load() {
				body = `{"errorCode":-1005,"msg":"raw controller details"}`
				break
			}
			body = `{"errorCode":0,"result":{"tcpScanReject":true}}`
		case "GET " + prefix + "clients/00-00-00-00-00-01":
			body = `{"errorCode":0,"result":{"blocked":false}}`
		case "POST " + prefix + "clients/00-00-00-00-00-01/unblock":
			body = `{"errorCode":0}`
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
	t.Setenv("OMADA_HOST", ts.URL)
	t.Setenv("OMADA_CLIENT_ID", "fixture-id")
	t.Setenv("OMADA_CLIENT_SECRET", "fixture-secret")
	for _, tc := range []struct {
		build func() *cobra.Command
		args  []string
		json  bool
		want  string
	}{
		{buildOmadaAttackDefenseCmd, nil, false, `"tcpScanReject": true`},
		{buildOmadaAttackDefenseCmd, []string{"--mac", "00:00:00:00:00:01"}, true, `"controller_client_blocked": false`},
		{buildOmadaUnblockClientCmd, []string{"--mac", "00:00:00:00:00:01", "--confirm"}, true, `"status": "accepted"`},
		{buildOmadaUnblockClientCmd, []string{"--mac", "00:00:00:00:00:01", "--confirm"}, false, "Inspect the gateway"},
	} {
		cmd := tc.build()
		providerSkipTLS = true
		jsonOutput = tc.json
		cmd.SetArgs(tc.args)
		out := captureStdout(func() {
			if err := cmd.Execute(); err != nil {
				t.Error(err)
			}
		})
		if !strings.Contains(out, tc.want) {
			t.Errorf("output=%q missing %q", out, tc.want)
		}
	}
	for _, build := range []func() *cobra.Command{buildOmadaAttackDefenseCmd, buildOmadaUnblockClientCmd} {
		cmd := build()
		providerSkipTLS = true
		cmd.SetArgs([]string{"--mac", "bad-mac"})
		if cmd.Flags().Lookup("confirm") != nil {
			cmd.SetArgs([]string{"--mac", "bad-mac", "--confirm"})
		}
		if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "48-bit") {
			t.Errorf("invalid MAC error=%v", err)
		}
	}
	rejectSettings.Store(true)
	cmd := buildOmadaAttackDefenseCmd()
	providerSkipTLS = true
	if err := cmd.RunE(cmd, nil); err == nil || !strings.Contains(err.Error(), "-1005") || strings.Contains(err.Error(), "raw controller details") {
		t.Errorf("settings error=%v", err)
	}

}
