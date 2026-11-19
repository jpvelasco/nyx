package service

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/backends/omada"
)

const omadaLogExportZip = "PK\x03\x04fakelog"

// omadaLogExportHandler answers the token, sites, and logs/export paths. When
// disposition is empty, the export response carries no Content-Disposition
// header, exercising the default base-name fallback.
func omadaLogExportHandler(disposition string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			writeOmadaEnvelope(w, 0, `{"accessToken":"tok"}`)
		case "/openapi/v1/abc123/sites":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		case "/openapi/v1/abc123/logs/export":
			if r.Method != http.MethodPost {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/zip")
			if disposition != "" {
				w.Header().Set("Content-Disposition", disposition)
			}
			_, _ = w.Write([]byte(omadaLogExportZip))
		default:
			http.NotFound(w, r)
		}
	}
}

func TestOmadaServiceExportLogs(t *testing.T) {
	ts := omadaTestServer(t, omadaLogExportHandler("attachment; filename=LogList_1.zip"))
	opts := OmadaOptions{Host: ts.URL, ClientID: "a", ClientSecret: "b", SkipTLSVerify: true}
	ctx := t.Context()

	out := filepath.Join(t.TempDir(), "out.zip")
	res, err := NewOmadaService().ExportLogs(ctx, opts, omada.LogExportCSV, out)
	if err != nil {
		t.Fatalf("ExportLogs: %v", err)
	}
	if res.Path != out || res.Filename != "LogList_1.zip" || res.Bytes != len(omadaLogExportZip) {
		t.Errorf("result = %+v", res)
	}
	data, err := os.ReadFile(out) // nosemgrep: go_filesystem_rule-fileread — path is under t.TempDir()
	if err != nil {
		t.Fatalf("reading saved export: %v", err)
	}
	if string(data) != omadaLogExportZip {
		t.Errorf("saved bytes = %q", data)
	}
}

func TestOmadaServiceExportLogs_FilenameFallback(t *testing.T) {
	cases := []struct {
		name        string
		disposition string
		wantFile    string
		forbid      string // file that must not appear in the workdir
	}{
		{
			name:        "attachment filename wins over default",
			disposition: "attachment; filename=LogList_2.zip",
			wantFile:    "LogList_2.zip",
		},
		{
			name:        "missing header falls back to default",
			disposition: "",
			wantFile:    "omada-log-export.zip",
		},
		{
			name:        "dotfile attachment name falls back to default",
			disposition: "attachment; filename=.bashrc",
			wantFile:    "omada-log-export.zip",
			forbid:      ".bashrc",
		},
		{
			name:        "build file attachment name falls back to default",
			disposition: "attachment; filename=go.mod",
			wantFile:    "omada-log-export.zip",
			forbid:      "go.mod",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			t.Chdir(dir)
			ts := omadaTestServer(t, omadaLogExportHandler(tc.disposition))
			opts := OmadaOptions{Host: ts.URL, ClientID: "a", ClientSecret: "b", SkipTLSVerify: true}

			res, err := NewOmadaService().ExportLogs(t.Context(), opts, omada.LogExportXLSX, "")
			if err != nil {
				t.Fatalf("ExportLogs: %v", err)
			}
			if filepath.Base(res.Path) != tc.wantFile {
				t.Errorf("Path base = %q, want %q", res.Path, tc.wantFile)
			}
			if _, err := os.Stat(filepath.Join(dir, tc.wantFile)); err != nil {
				t.Errorf("expected %q in workdir: %v", tc.wantFile, err)
			}
			if tc.forbid != "" {
				if _, err := os.Stat(filepath.Join(dir, tc.forbid)); err == nil {
					t.Errorf("hostile file %q was created", tc.forbid)
				}
			}
		})
	}
}

func TestOmadaServiceExportLogs_DefaultNoClobber(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	existing := "LogList_2.zip"
	if err := os.WriteFile(existing, []byte("original"), 0o600); err != nil {
		t.Fatalf("seeding existing file: %v", err)
	}

	ts := omadaTestServer(t, omadaLogExportHandler("attachment; filename=LogList_2.zip"))
	opts := OmadaOptions{Host: ts.URL, ClientID: "a", ClientSecret: "b", SkipTLSVerify: true}
	_, err := NewOmadaService().ExportLogs(t.Context(), opts, omada.LogExportCSV, "")
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("error = %v, want the existing-file refusal", err)
	}
	data, err := os.ReadFile(existing) // nosemgrep: go_filesystem_rule-fileread — path is under t.TempDir()
	if err != nil {
		t.Fatalf("reading existing file: %v", err)
	}
	if string(data) != "original" {
		t.Errorf("existing file content = %q, want it untouched", data)
	}
}

func TestOmadaServiceExportLogs_ExplicitOutOverwrites(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out.zip")
	if err := os.WriteFile(out, []byte("original"), 0o600); err != nil {
		t.Fatalf("seeding existing file: %v", err)
	}

	ts := omadaTestServer(t, omadaLogExportHandler("attachment; filename=LogList_1.zip"))
	opts := OmadaOptions{Host: ts.URL, ClientID: "a", ClientSecret: "b", SkipTLSVerify: true}
	if _, err := NewOmadaService().ExportLogs(t.Context(), opts, omada.LogExportCSV, out); err != nil {
		t.Fatalf("ExportLogs: %v", err)
	}
	data, err := os.ReadFile(out) // nosemgrep: go_filesystem_rule-fileread — path is under t.TempDir()
	if err != nil {
		t.Fatalf("reading saved export: %v", err)
	}
	if string(data) != omadaLogExportZip {
		t.Errorf("explicit --out content = %q, want the new export", data)
	}
}

func TestOmadaServiceExportLogs_WriteError(t *testing.T) {
	ts := omadaTestServer(t, omadaLogExportHandler("attachment; filename=LogList_1.zip"))
	opts := OmadaOptions{Host: ts.URL, ClientID: "a", ClientSecret: "b", SkipTLSVerify: true}
	missing := filepath.Join(t.TempDir(), "no-such-dir", "logs.zip")
	_, err := NewOmadaService().ExportLogs(t.Context(), opts, omada.LogExportCSV, missing)
	if err == nil || !strings.Contains(err.Error(), "saving log export") {
		t.Fatalf("write error = %v, want the wrapped save failure", err)
	}
}

func TestOmadaServiceExportLogs_Errors(t *testing.T) {
	// invalid format is rejected before the export request is made
	ts := omadaTestServer(t, omadaLogExportHandler("attachment; filename=x.zip"))
	opts := OmadaOptions{Host: ts.URL, ClientID: "a", ClientSecret: "b", SkipTLSVerify: true}
	if _, err := NewOmadaService().ExportLogs(t.Context(), opts, 7, filepath.Join(t.TempDir(), "x.zip")); err == nil || !strings.Contains(err.Error(), "export format must be") {
		t.Fatalf("invalid format = %v, want format validation error", err)
	}

	// a controller envelope error must surface through the export wrap
	down := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			writeOmadaEnvelope(w, 0, `{"accessToken":"tok"}`)
		case "/openapi/v1/abc123/sites":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		default:
			writeOmadaEnvelope(w, -1600, `null`)
		}
	})
	_, err := NewOmadaService().ExportLogs(t.Context(), OmadaOptions{Host: down.URL, ClientID: "a", ClientSecret: "b", SkipTLSVerify: true}, omada.LogExportCSV, filepath.Join(t.TempDir(), "x.zip"))
	if err == nil || !strings.Contains(err.Error(), "exporting logs") || !strings.Contains(err.Error(), "unsupported request path") {
		t.Fatalf("controller error = %v, want wrapped unsupported-path error", err)
	}
}
