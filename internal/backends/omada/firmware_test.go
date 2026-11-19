package omada

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestClassifyDeviceFirmware(t *testing.T) {
	for _, tc := range []struct {
		name   string
		device Device
		info   firmwareInfo
		now    time.Time
		want   string
	}{
		{"current only", Device{}, firmwareInfo{Current: "1.0"}, time.Now(), firmwareUnknown},
		{"same versions", Device{}, firmwareInfo{Current: "1.0", Latest: "1.0"}, time.Now(), firmwareCurrent},
		{"newer version", Device{}, firmwareInfo{Current: "1.0", Latest: "2.0"}, time.Now(), firmwareUpdate},
		{"controller upgrade flag", Device{NeedUpgrade: true}, firmwareInfo{}, time.Now(), firmwareUpdate},
		{"US v1 after end of maintenance", Device{ShowModel: "EAP620 HD(US) v1.0"}, firmwareInfo{Current: "1.0"}, eap620HDUSV1MaintenanceEnd, firmwareEOL},
		{"US v1 before end of maintenance", Device{ShowModel: "EAP620 HD(US) v1.0"}, firmwareInfo{Current: "1.0"}, eap620HDUSV1MaintenanceEnd.Add(-time.Second), firmwareUnknown},
		{"unknown region", Device{ShowModel: "EAP620 HD v1.0"}, firmwareInfo{Current: "1.0"}, time.Now(), firmwareUnknown},
		{"different revision", Device{ShowModel: "EAP620 HD(US) v3.0"}, firmwareInfo{Current: "1.0"}, time.Now(), firmwareUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, advisory := classifyDeviceFirmware(tc.device, tc.info, tc.now)
			if status != tc.want || (advisory != "") != (tc.want == firmwareEOL) {
				t.Fatalf("firmware = %q, %q; want %q with advisory only for EOL", status, advisory, tc.want)
			}
		})
	}
}

func TestObserveDeviceFirmware(t *testing.T) {
	client, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/openapi/v1/abc123/sites/s1/devices/AA-BB-CC-DD-EE-00/latest-firmware-info" {
			t.Errorf("unexpected method or path: %s %s", r.Method, r.URL.Path)
		}
		writeEnvelope(w, 0, "", `{"curFwVer":"1.0","lastFwVer":"2.0"}`)
	}))
	devices := []Device{{MAC: "aa:bb:cc:dd:ee:00", FirmwareVersion: "1.0", FirmwareStatus: firmwareUnknown}}
	client.observeDeviceFirmware(context.Background(), "s1", devices)
	snap := &InventorySnapshot{Devices: devices}
	got := BuildSpecInventory(snap).Devices[0]
	if got.FirmwareStatus != firmwareUpdate || !got.Upgrade || !strings.Contains(RenderInventory(snap, "HQ"), "[upgrade available]") {
		t.Fatalf("inventory device = %+v; want update available in both renderers", got)
	}
}
