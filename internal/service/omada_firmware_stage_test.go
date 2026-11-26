package service

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestStagedFirmwareBindingAndReboot(t *testing.T) {
	var started atomic.Bool
	var uploaded atomic.Int32
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/openapi/authorize/token":
			writeOmadaEnvelope(w, 0, `{"accessToken":"fixture"}`)
		case strings.HasSuffix(r.URL.Path, "/sites"):
			writeOmadaEnvelope(w, 0, `[{"id":"site","name":"management"},{"id":"other","name":"trusted"}]`)
		case strings.HasSuffix(r.URL.Path, "/networks/devices"):
			v := "fixture-current"
			if started.Load() {
				v = "fixture-next"
			}
			writeOmadaEnvelope(w, 0, `[{"mac":"AA-BB-CC-DD-EE-00","model":"fixture-model","showModel":"fixture-rev","firmwareVersion":"`+v+`"}]`)
		case strings.HasSuffix(r.URL.Path, "/devices/upgrade-file"):
			uploaded.Add(1)
			writeOmadaEnvelope(w, 0, `{"fileId":"image"}`)
		case strings.HasSuffix(r.URL.Path, "/start-manually-upgrade"):
			started.Store(true)
			writeOmadaEnvelope(w, 0, `{"taskId":"task"}`)
		case strings.HasSuffix(r.URL.Path, "/manually-upgrade-tasks/task"):
			writeOmadaEnvelope(w, 0, `{"finished":true}`)
		default:
			t.Error("unexpected endpoint")
			http.NotFound(w, r)
		}
	})
	svc := NewOmadaService()
	dir := t.TempDir()
	opts := OmadaOptions{Host: ts.URL, Site: "management", SkipTLSVerify: true}
	id, err := svc.StageFirmware(t.Context(), opts, dir, "AA-BB-CC-DD-EE-00", "fixture-next", strings.NewReader("synthetic image"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		o       OmadaOptions
		ref     string
		confirm bool
		want    string
	}{{"dry run", opts, id, false, "dry_run"}, {"model unverified", opts, id, true, "hardware_support_unverified"}, {"bad ref", opts, "../image", true, ""}, {"other host", OmadaOptions{Host: "other.example", Site: "management"}, id, true, ""}, {"other site", OmadaOptions{Host: ts.URL, Site: "trusted", SkipTLSVerify: true}, id, true, ""}} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := svc.UpgradeStagedFirmware(t.Context(), tc.o, dir, tc.ref, tc.confirm)
			if (err != nil) != (tc.want == "") || out.Status != tc.want || uploaded.Load() != 0 {
				t.Fatalf("result %+v, %v", out, err)
			}
			b, _ := json.Marshal(out)
			if strings.Contains(string(b), "fixture-model") || strings.Contains(string(b), id) {
				t.Error("private stage evidence in result")
			}
		})
	}
	out, err := svc.upgradeStaged(t.Context(), opts, dir, id, true, func(model, rev string) bool { return model == "fixture-model" && rev == "fixture-rev" })
	if err != nil || out.Status != "verified" || out.Observed != "fixture-next" || uploaded.Load() != 1 {
		t.Fatalf("readback %+v, %v", out, err)
	}
	file := filepath.Join(dir, id)
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)-1] ^= 1
	if err := os.WriteFile(file, b, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.UpgradeStagedFirmware(t.Context(), opts, dir, id, true); err == nil {
		t.Fatal("changed image accepted")
	}
}
