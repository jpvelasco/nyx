package cli

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/testutil"
)

func TestOmadaPendingCLIProjection(t *testing.T) {
	saveRestoreOmadaExtGlobals(t)
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var data string
		switch {
		case r.URL.Path == "/api/info":
			data = `{"controllerVer":"6.3.0","omadacId":"fixture"}`
		case r.URL.Path == "/openapi/authorize/token":
			data = `{"accessToken":"fixture"}`
		case strings.HasSuffix(r.URL.Path, "/sites"):
			data = `[{"id":"site","name":"management"}]`
		case strings.HasSuffix(r.URL.Path, "/site/grid/devices/pending"):
			data = `{"totalRows":1,"currentPage":1,"data":[{"mac":"AA-BB-CC-DD-EE-00","name":"private.example","type":"switch","detailStatus":20}]}`
		default:
			t.Error("unexpected endpoint")
			http.NotFound(w, r)
			return
		}
		testutil.WriteBody(w, `{"errorCode":0,"result":`+data+`}`)
	}))
	defer ts.Close()
	for _, private := range []bool{false, true} {
		cmd := buildOmadaPendingDevicesCmd()
		args := []string{"--host", ts.URL, "--site", "management", "--client-id", "fixture", "--client-secret", "fixture", "--skip-tls-verify"}
		if private {
			args = append(args, "--include-private-details")
		}
		cmd.SetArgs(args)
		out := captureStdout(func() {
			if err := cmd.Execute(); err != nil {
				t.Fatal(err)
			}
		})
		if strings.Contains(out, "AA-BB-CC-DD-EE-00") != private || strings.Contains(out, "private.example") || !strings.Contains(out, "switch") {
			t.Fatal("incorrect pending device projection")
		}
	}
}
