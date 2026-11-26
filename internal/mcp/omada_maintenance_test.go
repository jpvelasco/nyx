package mcp

import (
	"encoding/pem"
	"github.com/jpvelasco/nyx/internal/service"
	"github.com/jpvelasco/nyx/internal/testutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestMaintenanceToolsUseConfiguredTarget(t *testing.T) {
	hermeticCreds(t)
	s := NewServerWithLogger(nil)
	for _, name := range []string{"omada_pending_devices", "omada_adoption_status", "omada_staged_firmware"} {
		if !slices.Contains(ToolNames(), name) {
			t.Fatal("missing", name)
		}
		for _, key := range []string{"host", "password", "url", "file", "skip_tls_verify"} {
			out, failed := s.dispatchTool(t.Context(), name, map[string]interface{}{key: "private.example"})
			if !failed || !strings.Contains(out, "unsupported maintenance argument") || strings.Contains(out, "private.example") {
				t.Errorf("%s accepted override %s", name, key)
			}
		}
		if _, failed := s.dispatchTool(t.Context(), name, nil); !failed {
			t.Fatal("accepted unconfigured target")
		}
	}
	for _, tc := range []struct {
		name, key string
		value     any
	}{{"omada_pending_devices", "page", 0.5}, {"omada_staged_firmware", "confirm_reboot", "true"}, {"omada_adoption_status", "mac", true}} {
		if _, failed := s.dispatchTool(t.Context(), tc.name, map[string]any{tc.key: tc.value}); !failed {
			t.Errorf("accepted malformed %s", tc.key)
		}
	}
}

func TestMaintenanceReadsWithOperatorCA(t *testing.T) {
	hermeticCreds(t)
	s := NewServerWithLogger(nil)
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var data string
		switch {
		case r.URL.Path == "/api/info":
			data = `{"controllerVer":"6.3.0","omadacId":"fixture"}`
		case r.URL.Path == "/openapi/authorize/token":
			data = `{"accessToken":"fixture"}`
		case strings.HasSuffix(r.URL.Path, "/sites"):
			data = `[{"id":"site","name":"management"}]`
		case strings.HasSuffix(r.URL.Path, "/networks/devices"):
			data = `[{"mac":"AA-BB-CC-DD-EE-00","model":"fixture-model","firmwareVersion":"current"}]`
		case strings.HasSuffix(r.URL.Path, "/grid/devices/pending"):
			data = `{"totalRows":1,"currentPage":1,"data":[{"mac":"AA-BB-CC-DD-EE-01","detailStatus":20,"type":"switch"}]}`
		default:
			t.Error("unexpected maintenance call")
			http.NotFound(w, r)
			return
		}
		testutil.WriteBody(w, `{"errorCode":0,"result":`+data+`}`)
	}))
	defer ts.Close()
	dir := t.TempDir()
	ca := filepath.Join(dir, "fixture.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	opts := service.OmadaOptions{Host: ts.URL, Site: "management", ClientID: "fixture", ClientSecret: "secret", CACertPath: ca}
	t.Setenv("OMADA_HOST", opts.Host)
	t.Setenv("OMADA_CLIENT_ID", opts.ClientID)
	t.Setenv("OMADA_CLIENT_SECRET", opts.ClientSecret)
	t.Setenv("OMADA_SITE", opts.Site)
	t.Setenv("NYX_OMADA_MAINTENANCE_CA", ca)
	t.Setenv("NYX_CREDENTIALS_FILE", filepath.Join(dir, "store.json"))
	ref, err := service.NewOmadaService().StageFirmware(t.Context(), opts, service.FirmwareStageDir(), "AA-BB-CC-DD-EE-00", "next", strings.NewReader("synthetic image"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		args map[string]any
		want string
		bad  bool
	}{{"omada_pending_devices", nil, "switch", false}, {"omada_adoption_status", map[string]any{"mac": "AA-BB-CC-DD-EE-00"}, "verified_complete", false}, {"omada_adoption_status", map[string]any{"mac": "bad", "wait_seconds": float64(150)}, "not verified", true}, {"omada_staged_firmware", map[string]any{"reference": ref}, "dry_run", false}, {"omada_staged_firmware", map[string]any{"reference": ref, "confirm_reboot": true}, "hardware_support_unverified", false}} {
		out, bad := s.dispatchTool(t.Context(), tc.name, tc.args)
		if bad != tc.bad || !strings.Contains(out, tc.want) || strings.Contains(out, "synthetic image") {
			t.Fatal(tc.name, out)
		}
	}
}
