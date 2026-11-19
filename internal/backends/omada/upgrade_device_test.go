package omada

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"github.com/jpvelasco/nyx/internal/testutil"
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

func TestUpgradeDeviceFailures(t *testing.T) {
	for _, tc := range []struct{ name, mac, observed, image, failPath, failResponse, want string }{
		{name: "invalid target", mac: "invalid", want: "requires a MAC"},
		{name: "missing device", want: "target device was not found"},
		{name: "already current", observed: "2.0.0", want: ""},
		{name: "empty image", observed: "1.0.0", want: "image must contain"},
		{name: "upload rejected", observed: "1.0.0", image: "fixture", failPath: "upgrade-file", failResponse: `{"errorCode":-39021}`, want: "uploading device image"},
		{name: "missing image ID", observed: "1.0.0", image: "fixture", failPath: "upgrade-file", failResponse: `{"errorCode":0,"result":{}}`, want: "did not return an image ID"},
		{name: "start rejected", observed: "1.0.0", image: "fixture", failPath: "start-manually-upgrade", failResponse: `{"errorCode":-39020}`, want: "starting device firmware upgrade"},
		{name: "missing task ID", observed: "1.0.0", image: "fixture", failPath: "start-manually-upgrade", failResponse: `{"errorCode":0,"result":{}}`, want: "did not return an upgrade task ID"},
		{name: "wrong verified version", observed: "1.0.0", image: "fixture", want: "last observed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.failPath != "" && strings.HasSuffix(r.URL.Path, "/"+tc.failPath) {
					testutil.WriteBody(w, tc.failResponse)
					return
				}
				switch {
				case strings.HasSuffix(r.URL.Path, "/networks/devices"):
					if tc.observed == "" {
						writeEnvelope(w, 0, "", `[]`)
						return
					}
					writeEnvelope(w, 0, "", `[{"mac":"AA-BB-CC-DD-EE-00","firmwareVersion":"`+tc.observed+`"}]`)
				case strings.HasSuffix(r.URL.Path, "/devices/upgrade-file"):
					writeEnvelope(w, 0, "", `{"fileId":"image"}`)
				case strings.HasSuffix(r.URL.Path, "/start-manually-upgrade"):
					writeEnvelope(w, 0, "", `{"taskId":"task"}`)
				case strings.HasSuffix(r.URL.Path, "/manually-upgrade-tasks/task"):
					writeEnvelope(w, 0, "", `{"finished":true}`)
				default:
					t.Errorf("unexpected path %s", r.URL.Path)
				}
			}))
			mac := tc.mac
			if mac == "" {
				mac = "AA:BB:CC:DD:EE:00"
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			got, err := client.UpgradeDevice(ctx, "s1", mac, "2.0.0", strings.NewReader(tc.image), true)
			if tc.want == "" {
				if err != nil || got.Status != "already_current" {
					t.Fatalf("upgrade = %+v, %v; want already current", got, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("upgrade = %+v, %v; want %q", got, err, tc.want)
			}
		})
	}
}

func TestUpgradeDeviceReadFailures(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/networks/devices") {
			writeEnvelope(w, -1005, "forbidden", `null`)
			return
		}
		t.Errorf("unexpected path %s", r.URL.Path)
	})
	readErr := errors.New("fixture read failure")
	if _, err := client.uploadDeviceFirmware(t.Context(), "s1", iotest.ErrReader(readErr)); !errors.Is(err, readErr) {
		t.Fatalf("upload error = %v, want %v", err, readErr)
	}
	result := DeviceUpgrade{Device: "aa:bb:cc:dd:ee:00"}
	if client.verifyDeviceFirmware(t.Context(), "s1", &result) {
		t.Fatal("verified firmware despite denied inventory")
	}
}
