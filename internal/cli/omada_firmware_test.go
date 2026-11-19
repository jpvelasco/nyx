package cli

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/testutil"
)

func TestOmadaFirmwareUpgradeCommand(t *testing.T) {
	dir := t.TempDir()
	image := filepath.Join(dir, "fixture.bin")
	empty := filepath.Join(dir, "empty.bin")
	for path, content := range map[string]string{image: "fixture", empty: ""} {
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name, file, mac, want string
		json, fail            bool
	}{
		{"human preview", image, "aa:bb:cc:dd:ee:00", "dry_run", false, false},
		{"json preview", image, "aa:bb:cc:dd:ee:00", `"status": "dry_run"`, true, false},
		{"wrong file type", filepath.Join(dir, "fixture.zip"), "", "must point to", false, true},
		{"missing image", filepath.Join(dir, "missing.bin"), "", "missing.bin", false, true},
		{"empty image", empty, "", "nonempty regular", false, true},
		{"missing device", image, "aa:bb:cc:dd:ee:99", "target device was not found", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			saveRestoreOmadaExtGlobals(t)
			ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var result string
				switch r.URL.Path {
				case "/api/info":
					result = `{"controllerVer":"6.4.5.1","omadacId":"abc123"}`
				case "/openapi/authorize/token":
					result = `{"accessToken":"tok"}`
				case "/openapi/v1/abc123/sites":
					result = `[{"id":"site","name":"HQ"}]`
				case "/openapi/v1/abc123/sites/site/networks/devices":
					result = `[{"mac":"AA-BB-CC-DD-EE-00","firmwareVersion":"1.0.0"}]`
				default:
					t.Errorf("unexpected path %s", r.URL.Path)
					http.NotFound(w, r)
					return
				}
				testutil.WriteBody(w, `{"errorCode":0,"result":`+result+`}`)
			}))
			t.Cleanup(ts.Close)
			cmd := buildOmadaFirmwareCmd()
			cmd.SilenceErrors, cmd.SilenceUsage = true, true
			cmd.SetArgs([]string{"upgrade", "--file", tc.file, "--mac", tc.mac, "--expected-version", "2.0.0"})
			providerHost, providerSkipTLS, jsonOutput = ts.URL, true, tc.json
			var err error
			out := captureStdout(func() { err = cmd.Execute() })
			if tc.fail {
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("error = %v, want %q", err, tc.want)
				}
			} else if err != nil || !strings.Contains(out, tc.want) {
				t.Fatalf("output = %q, %v; want %q", out, err, tc.want)
			}
		})
	}
}
