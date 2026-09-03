package cli

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// omadaExtFakeController serves the minimal endpoint set the omada
// observation commands need: /api/info (served by the client for version
// display), token, sites, and the uplink-info POST. uplinkEmpty controls
// whether the uplink-info call returns a row or an empty array.
func omadaExtFakeController(t *testing.T, uplinkEmpty bool) *httptest.Server {
	t.Helper()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/info":
			w.Write([]byte(`{"errorCode":0,"msg":"","result":{"controllerVer":"6.4.5.1","apiVer":"2.0","omadacId":"abc123","configured":true,"omadacCategory":"advanced"}}`))
		case r.URL.Path == "/openapi/authorize/token":
			w.Write([]byte(`{"errorCode":0,"msg":"","result":{"accessToken":"tok"}}`))
		case r.URL.Path == "/openapi/v1/abc123/sites":
			w.Write([]byte(`{"errorCode":0,"msg":"","result":{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}}`))
		case r.URL.Path == "/openapi/v1/abc123/sites/s1/devices/uplink-info":
			if uplinkEmpty {
				w.Write([]byte(`{"errorCode":0,"msg":"","result":[]}`))
			} else {
				w.Write([]byte(`{"errorCode":0,"msg":"","result":[{"mac":"aa:bb:cc:dd:ee:01","uplinkDeviceMac":"bb:11:22:33:44:55","uplinkDeviceName":"SW-CORE","uplinkDevicePort":"8","linkSpeed":3,"duplex":2}]}`))
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(ts.Close)
	return ts
}

func saveRestoreOmadaExtGlobals(t *testing.T) {
	t.Helper()
	saveRestoreGlobals(t)
	t.Setenv("NYX_CREDENTIALS_FILE", t.TempDir()+"/credentials.json")
	t.Setenv("OMADA_HOST", "")
	t.Setenv("OMADA_CLIENT_ID", "")
	t.Setenv("OMADA_CLIENT_SECRET", "")
	t.Setenv("OMADA_SITE", "")
}

func TestOmadaUplinkInfoCmd_MissingMAC(t *testing.T) {
	saveRestoreOmadaExtGlobals(t)
	cmd := buildOmadaUplinkInfoCmd()
	omadaUplinkMAC = ""
	if err := cmd.RunE(cmd, nil); err == nil || !strings.Contains(err.Error(), "--mac is required") {
		t.Fatalf("error = %v, want --mac required message", err)
	}
}

func TestOmadaUplinkInfoCmd_NoHost(t *testing.T) {
	saveRestoreOmadaExtGlobals(t)
	cmd := buildOmadaUplinkInfoCmd()
	omadaUplinkMAC = "aa:bb:cc:dd:ee:01"
	if err := cmd.RunE(cmd, nil); err == nil || !strings.Contains(err.Error(), "controller host is required") {
		t.Fatalf("error = %v, want host-required message", err)
	}
}

func TestOmadaUplinkInfoCmd_JSON(t *testing.T) {
	saveRestoreOmadaExtGlobals(t)
	ts := omadaExtFakeController(t, false)
	jsonOutput = true
	cmd := buildOmadaUplinkInfoCmd()
	omadaUplinkMAC = "AA:BB:CC:DD:EE:01"
	providerHost = ts.URL
	providerSkipTLS = true
	out := captureStdout(func() {
		if err := cmd.RunE(cmd, nil); err != nil {
			t.Fatalf("uplink-info: %v", err)
		}
	})
	for _, want := range []string{`"uplink_device_port": "8"`, "SW-CORE"} {
		if !strings.Contains(out, want) {
			t.Errorf("JSON output missing %q:\n%s", want, out)
		}
	}
}

func TestOmadaUplinkInfoCmd_JSONEmpty(t *testing.T) {
	saveRestoreOmadaExtGlobals(t)
	ts := omadaExtFakeController(t, true)
	jsonOutput = true
	cmd := buildOmadaUplinkInfoCmd()
	omadaUplinkMAC = "AA:BB:CC:DD:EE:01"
	providerHost = ts.URL
	providerSkipTLS = true
	out := captureStdout(func() {
		if err := cmd.RunE(cmd, nil); err != nil {
			t.Fatalf("uplink-info (empty): %v", err)
		}
	})
	for _, want := range []string{`"mac": "AA:BB:CC:DD:EE:01"`, `"note": "no uplink observed"`} {
		if !strings.Contains(out, want) {
			t.Errorf("empty JSON output missing %q:\n%s", want, out)
		}
	}
}

func TestOmadaUplinkInfoCmd_Text(t *testing.T) {
	saveRestoreOmadaExtGlobals(t)
	ts := omadaExtFakeController(t, false)
	cmd := buildOmadaUplinkInfoCmd()
	omadaUplinkMAC = "aa:bb:cc:dd:ee:01"
	providerHost = ts.URL
	providerSkipTLS = true
	out := captureStdout(func() {
		if err := cmd.RunE(cmd, nil); err != nil {
			t.Fatalf("uplink-info (text): %v", err)
		}
	})
	for _, want := range []string{"Uplink device: SW-CORE", "Uplink port : 8"} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q:\n%s", want, out)
		}
	}
}
