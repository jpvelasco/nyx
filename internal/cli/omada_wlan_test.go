package cli

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jpvelasco/nyx/internal/testutil"
)

func TestOmadaWLANOptimizationCommand(t *testing.T) {
	saveRestoreOmadaExtGlobals(t)
	var failList atomic.Bool
	const prefix = "/openapi/v1/controller/sites/site/planningHistory"
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body string
		switch r.URL.Path {
		case "/api/info":
			body = `{"errorCode":0,"result":{"omadacId":"controller","controllerVer":"6.3.0"}}`
		case "/openapi/authorize/token":
			body = `{"errorCode":0,"result":{"accessToken":"fixture"}}`
		case "/openapi/v1/controller/sites":
			body = `{"errorCode":0,"result":{"totalRows":1,"data":[{"id":"site","name":"example"}]}}`
		case prefix:
			if failList.Load() {
				body = `{"errorCode":-34804}`
				break
			}
			body = `{"errorCode":0,"result":{"totalRows":1,"data":[{"planningHistroyId":"run-one","msgType":-34806,"failedMacs2g":"00-00-00-00-00-01,00-00-00-00-00-02"}]}}`
		case prefix + "/run-one":
			body = `{"errorCode":0,"result":{"failDevices":1,"data":[{"name":"fixture-ap","failMsg":"No scan result for fixture-ap","failMsgType":0,"triggerReason":2,"radio5g":{"errCode":-34815}}]}}`
		case prefix + "/empty":
			body = `{"errorCode":0,"result":{"data":[]}}`
		case prefix + "/missing":
			body = `{"errorCode":-34825,"msg":"raw controller details"}`
		default:
			t.Errorf("unexpected endpoint %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		if _, err := testutil.WriteBody(w, body); err != nil {
			t.Errorf("writing response: %v", err)
		}
	}))
	t.Cleanup(ts.Close)
	t.Setenv("OMADA_HOST", ts.URL)
	t.Setenv("OMADA_CLIENT_ID", "fixture-id")
	t.Setenv("OMADA_CLIENT_SECRET", "fixture-secret")
	for _, tc := range []struct {
		name string
		json bool
		args []string
		want []string
	}{
		{"history text", false, nil, []string{"run-one", "2.4 GHz=2", "RFPlanning"}},
		{"history JSON", true, nil, []string{`"failed_2g": 2`, `"msg_type": -34806`}},
		{"detail text", false, []string{"run-one"}, []string{"failMsgType=0", "triggerReason=2", "5 GHz errCode=-34815", "[device]"}},
		{"detail JSON", true, []string{"run-one"}, []string{`"fail_msg_type": 0`, `"5 GHz": -34815`}},
		{"empty detail", false, []string{"empty"}, []string{"No per-AP details"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			jsonOutput = tc.json
			cmd := buildOmadaWLANOptimizationCmd()
			providerSkipTLS = true
			cmd.SetArgs(tc.args)
			out := captureStdout(func() {
				if err := cmd.Execute(); err != nil {
					t.Error(err)
				}
			})
			for _, want := range tc.want {
				if !strings.Contains(out, want) {
					t.Errorf("output=%q missing %q", out, want)
				}
			}
			if strings.Contains(out, "fixture-ap") || strings.Contains(out, "00-00-00-00-00-01") {
				t.Errorf("device identifier in output %q", out)
			}
		})
	}
	cmd := buildOmadaWLANOptimizationCmd()
	providerSkipTLS = true
	if err := cmd.RunE(cmd, []string{"missing"}); err == nil || !strings.Contains(err.Error(), "-34825") || strings.Contains(err.Error(), "raw controller details") {
		t.Fatalf("detail error=%v", err)
	}
	failList.Store(true)
	if err := cmd.RunE(cmd, nil); err == nil || !strings.Contains(err.Error(), "-34804") {
		t.Fatalf("list error=%v", err)
	}
	t.Setenv("OMADA_HOST", "")
	cmd = buildOmadaWLANOptimizationCmd()
	if err := cmd.RunE(cmd, nil); err == nil {
		t.Fatal("expected missing host error")
	}
	jsonOutput = false
	if out := captureStdout(func() {
		if err := renderWLANOptimizationHistory(nil); err != nil {
			t.Error(err)
		}
	}); !strings.Contains(out, "No WLAN optimization history") {
		t.Errorf("empty history output=%q", out)
	}
}
