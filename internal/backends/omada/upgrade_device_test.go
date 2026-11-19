package omada

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

func TestUpgradeDevice(t *testing.T) {
	for _, confirmed := range []bool{false, true} {
		name := "dry run"
		if confirmed {
			name = "confirmed"
		}
		t.Run(name, func(t *testing.T) {
			var uploaded, started atomic.Bool
			client, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasSuffix(r.URL.Path, "/networks/devices"):
					version := "1.0.0"
					if started.Load() {
						version = "1.1.0"
					}
					writeEnvelope(w, 0, "", `[{"mac":"AA-BB-CC-DD-EE-00","firmwareVersion":"`+version+`"}]`)
				case strings.HasSuffix(r.URL.Path, "/devices/upgrade-file"):
					file, _, err := r.FormFile("file")
					if err != nil {
						t.Error(err)
						return
					}
					defer file.Close()
					data, err := io.ReadAll(file)
					if r.Method != http.MethodPost || !confirmed || uploaded.Swap(true) || err != nil || string(data) != "synthetic image" {
						t.Error("invalid firmware upload")
					}
					writeEnvelope(w, 0, "", `{"fileId":"image"}`)
				case strings.HasSuffix(r.URL.Path, "/start-manually-upgrade"):
					var request struct {
						MACs   []string `json:"macs"`
						FileID string   `json:"fileId"`
					}
					if !uploaded.Load() || started.Swap(true) || json.NewDecoder(r.Body).Decode(&request) != nil || request.FileID != "image" || len(request.MACs) != 1 || request.MACs[0] != "AA-BB-CC-DD-EE-00" {
						t.Error("invalid firmware start")
					}
					writeEnvelope(w, 0, "", `{"taskId":"task"}`)
				case strings.HasSuffix(r.URL.Path, "/manually-upgrade-tasks/task"):
					writeEnvelope(w, 0, "", `{"finished":true,"unfinishedCount":0}`)
				case r.URL.Path == "/api/info":
					writeEnvelope(w, 0, "", `{"controllerVer":"6.4.5.1","omadacId":"abc123"}`)
				default:
					t.Errorf("unexpected path %s", r.URL.Path)
				}
			}))
			result, err := client.UpgradeDevice(context.Background(), "s1", "AA:BB:CC:DD:EE:00", "1.1.0", strings.NewReader("synthetic image"), confirmed)
			if err != nil || (confirmed && (result.Status != "verified" || result.ObservedFirmware != "1.1.0" || result.TaskID != "task")) || (!confirmed && (result.Status != "dry_run" || uploaded.Load() || started.Load())) {
				t.Fatalf("upgrade = %+v, %v", result, err)
			}
		})
	}
}
