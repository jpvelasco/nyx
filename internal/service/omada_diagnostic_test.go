package service

import (
	"net/http"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/backends/omada"
)

func TestDiagnosticRadioProjections(t *testing.T) {
	runs := WLANRunDiagnostics([]omada.WLANOptimizationRun{{ID: "run", APCount: 0, MessageType: -34806, Failed2G: "first;second,third", Failed5G: "second\nthird"}, {ID: "empty"}})
	if len(runs) != 2 || runs[0].Failed2G != 3 || runs[0].Failed5G != 2 || runs[0].Failed6G != 0 || runs[0].Guidance == "" || runs[1].Guidance != "" {
		t.Fatal(runs)
	}
	n := 1
	aps := WLANAPDiagnostics(omada.WLANOptimizationDetail{Devices: []omada.WLANOptimizationAP{{Radio2G: &omada.WLANOptimizationRadio{ErrorCode: &n}, Radio5G: &omada.WLANOptimizationRadio{LegacyErrorCode: &n}}, {Name: "private.example"}}})
	if len(aps) != 2 || aps[0].RadioCodes["2.4 GHz"] != n || aps[0].RadioCodes["5 GHz"] != n || len(aps[1].RadioCodes) != 0 || aps[1].AP != 2 {
		t.Fatal(aps)
	}
}
func TestDiagnosticAPPagePrivacy(t *testing.T) {
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		var data string
		switch {
		case strings.HasSuffix(r.URL.Path, "/token"):
			data = `{"accessToken":"fixture"}`
		case strings.HasSuffix(r.URL.Path, "/sites"):
			data = `[{"id":"site","name":"management"}]`
		case strings.HasSuffix(r.URL.Path, "/networks/devices"):
			data = `[{"type":"ap","name":"private.example","mac":"AA-BB-CC-DD-EE-00"}]`
		case strings.HasSuffix(r.URL.Path, "/radios"):
			data = `{"radio5g":{"actualChannel":"36"}}`
		case strings.HasSuffix(r.URL.Path, "/available-channel"):
			data = `{"radio5g":[36]}`
		default:
			t.Error("unexpected request")
			http.NotFound(w, r)
			return
		}
		writeOmadaEnvelope(w, 0, data)
	})
	opts := OmadaOptions{Host: ts.URL, SkipTLSVerify: true}
	for _, private := range []bool{false, true} {
		p, err := NewOmadaService().APChannelsPage(t.Context(), opts, 0, 1, private)
		if err != nil || p.Total != 1 || len(p.Rows) != 1 || p.Rows[0].CurrentChannels["radio5g"] != "36" || (p.Rows[0].MAC != "") != private || (p.Rows[0].Name != "") != private {
			t.Fatal(p, err)
		}
	}
	empty, err := NewOmadaService().APChannelsPage(t.Context(), opts, 1, 1, false)
	if err != nil || len(empty.Rows) != 0 || empty.Offset != 1 || empty.Total != 1 {
		t.Fatal(empty, err)
	}
}
