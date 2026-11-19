package omadaprovider

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

// wlanScheduleHandlers serves the RF planning and planning-history
// endpoints with two rows: an older successful scheduled run and a
// newer skipped one (apNum=0, msgType=7).
func wlanScheduleHandlers() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			writeEnvelope(w, 0, "", `{"accessToken":"t1"}`)
		case "/openapi/v1/abc123/sites":
			writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		case "/openapi/v1/abc123/sites/s1/rfPlanning":
			writeEnvelope(w, 0, "", `{"scheduleEnable":true,"occurrence":{"timingType":1,"hour":10,"minute":0}}`)
		case "/openapi/v1/abc123/sites/s1/planningHistory":
			writeEnvelope(w, 0, "", `{"totalRows":2,"data":[
				{"planningHistroyId":"old","apNum":1,"isScanSuccess":true,"msgType":-1,"time":1763446618000,"mode":0},
				{"planningHistroyId":"new","apNum":0,"isScanSuccess":false,"msgType":7,"time":1763533200501,"mode":0}]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func TestProviderObserveWLANSchedule(t *testing.T) {
	p := &OmadaProvider{}
	ts := omadaServer(t, wlanScheduleHandlers())
	obs, err := p.ObserveWLANSchedule(context.Background(), natCheckOpts(ts))
	if err != nil {
		t.Fatalf("ObserveWLANSchedule: %v", err)
	}
	if !obs.ScheduleEnabled || obs.TimingType != 1 || obs.OccurrenceHour != 10 || obs.OccurrenceMinute != 0 {
		t.Errorf("planning = %+v", obs)
	}
	if !obs.LastRunTime.Equal(time.UnixMilli(1763533200501).UTC()) || obs.LastRunAPCount != 0 || obs.LastRunMessageType != 7 {
		t.Errorf("newest row = %+v", obs)
	}
	if obs.LastRunReason != "No APs available for WLAN Optimization." {
		t.Errorf("reason = %q", obs.LastRunReason)
	}
	if obs.ControllerNow.IsZero() {
		t.Error("controller now is zero; the test server sends a Date header")
	}
}

func TestProviderObserveWLANScheduleErrors(t *testing.T) {
	p := &OmadaProvider{}
	for _, tc := range []struct {
		name, failPath, want string
	}{
		{"rf planning failure", "/openapi/v1/abc123/sites/s1/rfPlanning", "reading rf planning"},
		{"history failure", "/openapi/v1/abc123/sites/s1/planningHistory", "reading optimization history"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts := omadaServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == tc.failPath {
					writeEnvelope(w, -1010, "boom", `null`)
					return
				}
				wlanScheduleHandlers()(w, r)
			})
			if _, err := p.ObserveWLANSchedule(context.Background(), natCheckOpts(ts)); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}
