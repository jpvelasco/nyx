package omada

import (
	"context"
	"errors"
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

func TestAdoptionReadBoundaries(t *testing.T) {
	const mac = "AA-BB-CC-DD-EE-00"
	grid := `{"totalRows":0,"currentPage":0,"data":[]}`
	managed := true
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/networks/devices"):
			if !managed {
				http.Error(w, "denied", http.StatusForbidden)
				return
			}
			writeEnvelope(w, 0, "", `[]`)
		case strings.HasSuffix(r.URL.Path, "/pending"):
			writeEnvelope(w, 0, "", grid)
		default:
			http.NotFound(w, r)
		}
	})
	if _, err := c.PendingDevices(t.Context(), "site", 0, 1, ""); err == nil {
		t.Fatal("bad page")
	}
	if _, err := c.ObserveAdoption(t.Context(), "site", "invalid", 0); err == nil {
		t.Fatal("invalid MAC")
	}
	if _, err := c.ObserveAdoption(t.Context(), "site", mac, 3*time.Minute); err == nil {
		t.Fatal("invalid wait")
	}
	r, err := c.ObserveAdoption(t.Context(), "site", mac, 0)
	if err != nil || r.Status != "unknown" || !strings.Contains(r.Evidence, "unavailable") {
		t.Fatal(r, err)
	}
	grid = `{"totalRows":2,"currentPage":1}`
	if _, err = c.ObserveAdoption(t.Context(), "site", mac, 0); err == nil {
		t.Fatal("invalid page")
	}
	managed = false
	if _, err = c.ObserveAdoption(t.Context(), "site", mac, 0); err == nil {
		t.Fatal("managed inventory inaccessible")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err = c.ObserveAdoption(ctx, "site", mac, time.Second); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
