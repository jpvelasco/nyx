package service

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestOmadaServiceUpgradeDeviceDryRun(t *testing.T) {
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			writeOmadaEnvelope(w, 0, `{"accessToken":"tok"}`)
		case "/openapi/v1/abc123/sites":
			writeOmadaEnvelope(w, 0, `[{"id":"site","name":"HQ"}]`)
		case "/openapi/v1/abc123/sites/site/networks/devices":
			writeOmadaEnvelope(w, 0, `[{"mac":"AA-BB-CC-DD-EE-00","firmwareVersion":"1.0.0"}]`)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			http.NotFound(w, r)
		}
	})
	got, err := NewOmadaService().UpgradeDevice(context.Background(), OmadaOptions{Host: ts.URL, SkipTLSVerify: true}, "aa:bb:cc:dd:ee:00", "2.0.0", strings.NewReader("fixture"), false)
	if err != nil || got.Status != "dry_run" || got.ObservedFirmware != "1.0.0" {
		t.Fatalf("upgrade preview = %+v, %v", got, err)
	}
}
