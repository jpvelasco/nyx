package omada

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestObserveAdoption(t *testing.T) {
	const selected = "AA-BB-CC-DD-EE-00"
	for _, tc := range []struct {
		name, managed string
		detail        int
		result, want  string
		wait          time.Duration
	}{
		{"already adopted", selected, 20, `{}`, "verified_complete", 0}, {"selected pending", "", 20, `{}`, "pending", 0}, {"other result", "", 20, `{"deviceMac":"AA-BB-CC-DD-EE-01","adoptErrorCode":-39004}`, "pending", 0}, {"missing code", "", 20, `{"deviceMac":"AA-BB-CC-DD-EE-00"}`, "pending", 0}, {"wireless adopting", "", 23, `{}`, "started", 0}, {"failed detail", "", 24, `{}`, "failed", 0}, {"failed result", "", 20, `{"deviceMac":"AA-BB-CC-DD-EE-00","adoptErrorCode":-39003}`, "failed", 0}, {"unverified success", "", 20, `{"deviceMac":"AA-BB-CC-DD-EE-00","adoptErrorCode":0}`, "unverified", 0}, {"deadline", "", 20, `{}`, "timed_out", 100 * time.Millisecond}, {"uncertain start", "", 26, `{}`, "unknown", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Error("unexpected mutation")
					http.Error(w, "method", http.StatusMethodNotAllowed)
					return
				}
				switch {
				case strings.HasSuffix(r.URL.Path, "/site/networks/devices"):
					rows := `[]`
					if tc.managed != "" {
						rows = `[{"mac":"` + tc.managed + `"}]`
					}
					writeEnvelope(w, 0, "", rows)
				case strings.HasSuffix(r.URL.Path, "/site/grid/devices/pending"):
					if r.URL.Query().Get("searchKey") != selected {
						t.Error("missing exact search")
					}
					writeEnvelope(w, 0, "", fmt.Sprintf(`{"data":[{"mac":"%s","detailStatus":%d}],"totalRows":1,"currentPage":1}`, selected, tc.detail))
				case strings.HasSuffix(r.URL.Path, "/site/devices/"+selected+"/adopt-result"):
					writeEnvelope(w, 0, "", tc.result)
				default:
					t.Error("unexpected endpoint")
					http.NotFound(w, r)
				}
			})
			r, err := c.ObserveAdoption(t.Context(), "site", selected, tc.wait)
			if err != nil || r.Status != tc.want {
				t.Fatalf("result %+v, %v", r, err)
			}
		})
	}
}
func TestManagedTransportRejectsCrossOriginRedirect(t *testing.T) {
	var sent atomic.Bool
	dest := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { sent.Store(true); writeEnvelope(w, 0, "", `{}`) }))
	defer dest.Close()
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, dest.URL, http.StatusTemporaryRedirect)
	})
	_, err := c.uploadDeviceFirmware(t.Context(), "site", strings.NewReader("fixture"))
	if err == nil || sent.Load() {
		t.Fatal("cross-controller firmware redirect")
	}
}
