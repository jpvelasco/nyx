package service

import (
	"net/http"
	"strings"
	"testing"
)

func TestAdoptionObservationPreservesSelectedSite(t *testing.T) {
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		var data string
		switch {
		case strings.HasSuffix(r.URL.Path, "/token"):
			data = `{"accessToken":"fixture"}`
		case strings.HasSuffix(r.URL.Path, "/sites"):
			data = `[{"id":"site","name":"management"}]`
		case strings.HasSuffix(r.URL.Path, "/site/networks/devices"):
			data = `[{"mac":"AA-BB-CC-DD-EE-00"}]`
		case strings.HasSuffix(r.URL.Path, "/site/grid/devices/pending"):
			data = `{"totalRows":1,"currentPage":1,"data":[{"mac":"AA-BB-CC-DD-EE-01","type":"ap"}]}`
		default:
			t.Error("unexpected endpoint")
			http.NotFound(w, r)
			return
		}
		writeOmadaEnvelope(w, 0, data)
	})
	svc := NewOmadaService()
	opts := OmadaOptions{Host: ts.URL, SkipTLSVerify: true}
	if _, err := svc.PendingDevices(t.Context(), opts, 1, 1, false); err == nil {
		t.Fatal("no explicit site")
	}
	if _, err := svc.ObserveAdoption(t.Context(), opts, "AA-BB-CC-DD-EE-00", 0); err == nil {
		t.Fatal("no explicit site")
	}
	opts.Site = "management"
	for _, private := range []bool{true, false} {
		p, err := svc.PendingDevices(t.Context(), opts, 1, 1, private)
		if err != nil || len(p.Devices) != 1 || (p.Devices[0].MAC != "") != private {
			t.Fatal(p, err)
		}
	}
	r, err := svc.ObserveAdoption(t.Context(), opts, "AA-BB-CC-DD-EE-00", 0)
	if err != nil || r.Status != "verified_complete" {
		t.Fatal(r, err)
	}
}
