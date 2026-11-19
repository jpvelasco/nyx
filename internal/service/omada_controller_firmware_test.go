package service

import (
	"context"
	"net/http"
	"testing"
)

func TestOmadaServiceControllerFirmware(t *testing.T) {
	for _, tc := range []struct {
		name      string
		failInfo  bool
		failLogin bool
	}{
		{name: "current"},
		{name: "unavailable controller", failInfo: true},
		{name: "denied credentials", failLogin: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/openapi/authorize/token":
					if tc.failLogin {
						writeOmadaEnvelope(w, -1005, `null`)
						return
					}
					writeOmadaEnvelope(w, 0, `{"accessToken":"tok"}`)
				case "/openapi/v1/abc123/system/setting/hardware/check-firmware":
					writeOmadaEnvelope(w, 0, `{"update":false,"currentVersion":"3.4.25","latestVersion":"3.4.25"}`)
				default:
					t.Errorf("unexpected path %s", r.URL.Path)
				}
			})
			opts := OmadaOptions{Host: ts.URL, SkipTLSVerify: !tc.failInfo}
			got, err := NewOmadaService().ControllerFirmware(context.Background(), opts)
			if tc.failInfo || tc.failLogin {
				if err == nil {
					t.Fatal("expected provider session error")
				}
				return
			}
			if err != nil || got.Status != "up_to_date" {
				t.Fatalf("firmware = %+v, %v", got, err)
			}
		})
	}
}
