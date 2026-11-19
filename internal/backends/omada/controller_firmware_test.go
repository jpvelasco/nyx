package omada

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestControllerFirmware(t *testing.T) {
	for _, tc := range []struct{ name, live, model, current, want, source string }{
		{"live current", `{"update":false,"currentVersion":"3.4.25","latestVersion":"3.4.25"}`, "", "", "up_to_date", "controller"},
		{"live newer", `{"update":true,"currentVersion":"3.4.11","latestVersion":"3.4.25"}`, "", "", "newer_available", "controller"},
		{"known published upgrade", "", "OC200(UN)", "3.4.11 Build 20260904", "newer_available", "published_reference"},
		{"matching reference insufficient", "", "OC200(UN)", "3.4.25", "check_unreachable", "published_reference"},
		{"incomplete live unqualified hardware", `{}`, "OC200", "3.4.11", "check_unreachable", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasSuffix(r.URL.Path, "/hardware/check-firmware"):
					if tc.live == "" {
						writeEnvelope(w, -1, "unavailable", `null`)
						return
					}
					writeEnvelope(w, 0, "", tc.live)
				case strings.HasSuffix(r.URL.Path, "/controller-status"):
					writeEnvelope(w, 0, "", `{"model":"`+tc.model+`","modelVersion":"3.6","firmwareVersion":"`+tc.current+`"}`)
				default:
					t.Error("unexpected operation")
				}
			}))
			got := client.CheckControllerFirmware(context.Background())
			if got.Status != tc.want || got.Source != tc.source {
				t.Fatalf("check = %+v, want %s from %s", got, tc.want, tc.source)
			}
		})
	}
}

func TestFirmwareVersionOlder(t *testing.T) {
	for _, version := range []string{"3.4", "3.4.11-preview", "3.4.25", "3.4.26", "4.0.0"} {
		if firmwareVersionOlder(version, "3.4.25") {
			t.Errorf("%q must not be classified older", version)
		}
	}
}
