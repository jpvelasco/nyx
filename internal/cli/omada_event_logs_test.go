package cli

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/testutil"
)

func TestOmadaEventLogsCmd(t *testing.T) {
	saveRestoreOmadaExtGlobals(t)
	controller := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/info":
			testutil.WriteBody(w, `{"errorCode":0,"result":{"controllerVer":"6.4.5.1","omadacId":"abc123"}}`)
		case "/openapi/authorize/token":
			testutil.WriteBody(w, `{"errorCode":0,"result":{"accessToken":"fixture-token"}}`)
		case "/openapi/v1/abc123/sites":
			testutil.WriteBody(w, `{"errorCode":0,"result":{"totalRows":1,"data":[{"id":"s1","name":"Example"}]}}`)
		case "/openapi/v1/abc123/sites/s1/logs/events":
			if got := r.URL.Query().Get("filters.module"); got != "Device" {
				t.Errorf("module = %q, want Device", got)
			}
			testutil.WriteBody(w, `{"errorCode":0,"result":{"totalRows":1,"currentPage":1,"currentSize":1,"data":[{"id":"event-1","content":"Optimization completed"}]}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer controller.Close()
	cmd := buildOmadaLogsCmd()
	cmd.SetArgs([]string{"--host", controller.URL, "--client-id", "fixture-client", "--client-secret", "fixture-secret", "--skip-tls-verify", "--module", "Device", "--since", "30d"})
	var err error
	out := captureStdout(func() { err = cmd.Execute() })
	if err != nil || !strings.Contains(out, "Optimization completed") {
		t.Fatalf("logs output = %q, error = %v", out, err)
	}
}
