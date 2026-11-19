package cli

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestOmadaSiteConfigCommands(t *testing.T) {
	saveRestoreOmadaExtGlobals(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	var vlan atomic.Int32
	vlan.Store(10)
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var result string
		switch r.URL.Path {
		case "/api/info":
			result = `{"controllerVer":"6.4.5.1","omadacId":"abc123"}`
		case "/openapi/authorize/token":
			result = `{"accessToken":"tok"}`
		case "/openapi/v1/abc123/sites":
			result = `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`
		case "/openapi/v1/abc123/sites/s1/lan-networks":
			result = fmt.Sprintf(`[{"id":"n1","name":"private-example","vlan":%d}]`, vlan.Load())
		case "/openapi/v1/abc123/sites/s1/acls/osw-acls", "/openapi/v1/abc123/sites/s1/wlan-groups", "/openapi/v1/abc123/sites/s1/ssids":
			result = `[]`
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		fmt.Fprintf(w, `{"errorCode":0,"result":%s}`, result)
	}))
	defer ts.Close()
	cmd := buildOmadaSiteConfigCmd()
	save, _, err := cmd.Find([]string{"snapshot"})
	if err != nil {
		t.Fatal(err)
	}
	drift, _, err := cmd.Find([]string{"drift"})
	if err != nil {
		t.Fatal(err)
	}
	providerHost, providerSkipTLS = ts.URL, true
	var out bytes.Buffer
	cmd.SetOut(&out)
	if err := drift.RunE(drift, nil); err == nil || !strings.Contains(err.Error(), "no baseline") {
		t.Fatalf("missing baseline error = %v", err)
	}
	if err := save.RunE(save, nil); err != nil {
		t.Fatal(err)
	}
	if err := drift.RunE(drift, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "No site configuration changes") {
		t.Fatalf("unexpected output %q", out.String())
	}
	vlan.Store(20)
	out.Reset()
	if err := drift.RunE(drift, nil); err != nil {
		t.Fatal(err)
	}
	if text := out.String(); !strings.Contains(text, "modified network") || strings.Contains(text, "private-example") {
		t.Fatalf("unexpected output %q", text)
	}
	jsonOutput = true
	output := captureStdout(func() {
		if err := drift.RunE(drift, nil); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(output, `"status": "modified"`) || strings.Contains(output, "private-example") {
		t.Fatalf("unexpected output %q", output)
	}
}
