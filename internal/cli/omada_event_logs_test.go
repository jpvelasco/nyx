package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	omadabackend "github.com/jpvelasco/nyx/internal/backends/omada"
	"github.com/jpvelasco/nyx/internal/testutil"
)

func TestOmadaEventLogsCmd(t *testing.T) {
	saveRestoreOmadaExtGlobals(t)
	controller := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/info":
			testutil.WriteBody(w, `{"errorCode":0,"result":{"controllerVer":"6.4.5.1","omadacId":"abc123"}}`)
		case "/openapi/authorize/token":
			testutil.WriteBody(w, `{"errorCode":0,"result":{"accessToken":"fixture-token"}}`)
		case "/openapi/v1/abc123/sites":
			testutil.WriteBody(w, `{"errorCode":0,"result":{"totalRows":1,"data":[{"id":"s1","name":"Example"}]}}`)
		case "/openapi/v1/abc123/sites/s1/logs/events":
			if got := r.URL.Query().Get("filters.module"); got != "Device" {
				t.Errorf("module = %q, want Device", got)
			}
			testutil.WriteBody(w, `{"errorCode":0,"result":{"totalRows":1,"currentPage":1,"currentSize":1,"data":[{"id":"event-1","content":"Optimization completed"}]}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer controller.Close()
	cmd := buildOmadaLogsCmd()
	cmd.SetArgs([]string{"--host", controller.URL, "--client-id", "fixture-client", "--client-secret", "fixture-secret", "--skip-tls-verify", "--module", "Device", "--since", "30d"})
	var err error
	out := captureStdout(func() { err = cmd.Execute() })
	if err != nil || !strings.Contains(out, "Optimization completed") {
		t.Fatalf("logs output = %q, error = %v", out, err)
	}
}

func TestOmadaLogsExportCmd(t *testing.T) {
	cases := []struct {
		format   string
		wantCode int
	}{
		{"csv", omadabackend.LogExportCSV},
		{"xlsx", omadabackend.LogExportXLSX},
	}
	for _, tc := range cases {
		t.Run(tc.format, func(t *testing.T) {
			saveRestoreOmadaExtGlobals(t)
			outPath := filepath.Join(t.TempDir(), "logs.zip")
			var exportBody []byte
			controller := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/info":
					testutil.WriteBody(w, `{"errorCode":0,"result":{"controllerVer":"6.4.5.1","omadacId":"abc123"}}`)
				case "/openapi/authorize/token":
					testutil.WriteBody(w, `{"errorCode":0,"result":{"accessToken":"fixture-token"}}`)
				case "/openapi/v1/abc123/sites":
					testutil.WriteBody(w, `{"errorCode":0,"result":{"totalRows":1,"data":[{"id":"s1","name":"Example"}]}}`)
				case "/openapi/v1/abc123/logs/export":
					exportBody, _ = io.ReadAll(r.Body)
					w.Header().Set("Content-Type", "application/zip")
					w.Header().Set("Content-Disposition", "attachment; filename=LogList_fixture.zip")
					_, _ = w.Write([]byte("PK\x03\x04zipdata"))
				default:
					http.NotFound(w, r)
				}
			}))
			defer controller.Close()

			cmd := buildOmadaLogsCmd()
			cmd.SetArgs([]string{"export", "--format", tc.format, "--out", outPath, "--host", controller.URL, "--client-id", "fixture-client", "--client-secret", "fixture-secret", "--skip-tls-verify"})
			var err error
			out := captureStdout(func() { err = cmd.Execute() })
			if err != nil {
				t.Fatalf("logs export: %v (out=%q)", err, out)
			}

			var req struct {
				SiteIDs []string `json:"siteIds"`
				Format  int      `json:"format"`
			}
			if err := json.Unmarshal(exportBody, &req); err != nil {
				t.Fatalf("export request body = %q: %v", exportBody, err)
			}
			if req.Format != tc.wantCode || len(req.SiteIDs) != 1 || req.SiteIDs[0] != "s1" {
				t.Errorf("export request = %+v, want %d for site s1", req, tc.wantCode)
			}

			var res map[string]any
			if err := json.Unmarshal([]byte(out), &res); err != nil {
				t.Fatalf("result is not JSON: %q", out)
			}
			if res["filename"] != "LogList_fixture.zip" || res["path"] != outPath || res["bytes"] != float64(len("PK\x03\x04zipdata")) {
				t.Errorf("result = %v", res)
			}
			data, err := os.ReadFile(outPath) // nosemgrep: go_filesystem_rule-fileread — path is under t.TempDir()
			if err != nil || string(data) != "PK\x03\x04zipdata" {
				t.Errorf("saved archive = %q, error = %v", data, err)
			}
		})
	}
}

// A controller envelope error on the export path must surface through the
// session wrap instead of being swallowed.
func TestOmadaLogsExportCmd_ControllerError(t *testing.T) {
	saveRestoreOmadaExtGlobals(t)
	controller := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/info":
			testutil.WriteBody(w, `{"errorCode":0,"result":{"controllerVer":"6.4.5.1","omadacId":"abc123"}}`)
		case "/openapi/authorize/token":
			testutil.WriteBody(w, `{"errorCode":0,"result":{"accessToken":"fixture-token"}}`)
		case "/openapi/v1/abc123/sites":
			testutil.WriteBody(w, `{"errorCode":0,"result":{"totalRows":1,"data":[{"id":"s1","name":"Example"}]}}`)
		case "/openapi/v1/abc123/logs/export":
			testutil.WriteBody(w, `{"errorCode":-1,"msg":"export disabled","result":null}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer controller.Close()

	cmd := buildOmadaLogsCmd()
	cmd.SetArgs([]string{"export", "--format", "csv", "--host", controller.URL, "--client-id", "fixture-client", "--client-secret", "fixture-secret", "--skip-tls-verify"})
	var err error
	captureStdout(func() { err = cmd.Execute() })
	if err == nil || !strings.Contains(err.Error(), "exporting logs") {
		t.Fatalf("controller error = %v, want the wrapped export failure", err)
	}
}

func TestOmadaLogsExportCmd_InvalidFormat(t *testing.T) {
	saveRestoreOmadaExtGlobals(t)
	cmd := buildOmadaLogsCmd()
	cmd.SetArgs([]string{"export", "--format", "pdf", "--host", "https://omada.invalid", "--client-id", "fixture-client", "--client-secret", "fixture-secret"})
	var err error
	captureStdout(func() { err = cmd.Execute() })
	if err == nil || !strings.Contains(err.Error(), "--format must be csv or xlsx") {
		t.Fatalf("invalid format = %v, want format validation error", err)
	}
}
