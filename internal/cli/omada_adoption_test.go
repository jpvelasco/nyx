package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/testutil"
	"github.com/spf13/cobra"
)

func TestOmadaPendingCLIProjection(t *testing.T) {
	saveRestoreOmadaExtGlobals(t)
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var data string
		switch {
		case r.URL.Path == "/api/info":
			data = `{"controllerVer":"6.3.0","omadacId":"fixture"}`
		case r.URL.Path == "/openapi/authorize/token":
			data = `{"accessToken":"fixture"}`
		case strings.HasSuffix(r.URL.Path, "/sites"):
			data = `[{"id":"site","name":"management"}]`
		case strings.HasSuffix(r.URL.Path, "/site/networks/devices"):
			data = `[{"mac":"AA-BB-CC-DD-EE-00","model":"fixture-model","firmwareVersion":"current"}]`
		case strings.HasSuffix(r.URL.Path, "/site/grid/devices/pending"):
			data = `{"totalRows":1,"currentPage":1,"data":[{"mac":"AA-BB-CC-DD-EE-00","name":"private.example","type":"switch","detailStatus":20}]}`
		default:
			t.Error("unexpected endpoint")
			http.NotFound(w, r)
			return
		}
		testutil.WriteBody(w, `{"errorCode":0,"result":`+data+`}`)
	}))
	defer ts.Close()
	for _, private := range []bool{false, true} {
		cmd := buildOmadaPendingDevicesCmd()
		args := []string{"--host", ts.URL, "--site", "management", "--client-id", "fixture", "--client-secret", "fixture", "--skip-tls-verify"}
		if private {
			args = append(args, "--include-private-details")
		}
		cmd.SetArgs(args)
		out := captureStdout(func() {
			if err := cmd.Execute(); err != nil {
				t.Fatal(err)
			}
		})
		if strings.Contains(out, "AA-BB-CC-DD-EE-00") != private || strings.Contains(out, "private.example") || !strings.Contains(out, "switch") {
			t.Fatal("incorrect pending device projection")
		}
	}
	dir := t.TempDir()
	t.Setenv("NYX_CREDENTIALS_FILE", filepath.Join(dir, "credentials.json"))
	file := filepath.Join(dir, "fixture.bin")
	if err := os.WriteFile(file, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	base := []string{"--host", ts.URL, "--site", "management", "--client-id", "fixture", "--client-secret", "secret", "--skip-tls-verify"}
	cmd := buildStageFirmwareCmd()
	cmd.SetArgs(append(base, "--file", file, "--mac", "AA-BB-CC-DD-EE-00", "--expected-version", "next"))
	var runErr error
	out := captureStdout(func() { runErr = cmd.Execute() })
	var stored struct{ Reference string }
	if runErr != nil || json.Unmarshal([]byte(out), &stored) != nil || stored.Reference == "" {
		t.Fatal("staging", runErr)
	}
	cmd = buildStagedFirmwareCmd()
	cmd.SetArgs(append(base, "--reference", stored.Reference))
	out = captureStdout(func() { runErr = cmd.Execute() })
	if runErr != nil || !strings.Contains(out, "dry_run") {
		t.Fatal("preview", runErr)
	}
	cmd = buildOmadaAdoptionStatusCmd()
	cmd.SetArgs(append(base, "--mac", "AA-BB-CC-DD-EE-00"))
	out = captureStdout(func() { runErr = cmd.Execute() })
	if runErr != nil || !strings.Contains(out, "verified_complete") {
		t.Fatal("selected readback", runErr)
	}
	for _, tc := range []struct {
		command func() *cobra.Command
		args    []string
	}{
		{buildOmadaPendingDevicesCmd, []string{"--page-size", "101"}},
		{buildOmadaAdoptionStatusCmd, []string{"--mac", "invalid"}},
		{buildStageFirmwareCmd, []string{"--file", filepath.Join(dir, "absent.bin")}},
		{buildStageFirmwareCmd, []string{"--file", file, "--mac", "invalid", "--expected-version", "next"}},
		{buildStagedFirmwareCmd, []string{"--reference", strings.Repeat("A", 26), "--confirm-reboot"}},
	} {
		cmd := tc.command()
		cmd.SilenceErrors, cmd.SilenceUsage = true, true
		cmd.SetArgs(append(base, tc.args...))
		out := captureStdout(func() { runErr = cmd.ExecuteContext(t.Context()) })
		if runErr == nil || out != "" {
			t.Errorf("%s accepted invalid maintenance input or emitted a successful result", cmd.Name())
		}
	}
}
