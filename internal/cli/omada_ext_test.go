package cli

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// omadaExtFakeController serves the minimal endpoint set the omada
// observation commands need: /api/info (served by the client for version
// display), token, sites, the uplink-info POST, the ports-overview GET, and
// the lan-profiles/lan-networks GETs. uplinkEmpty, switchEmpty, and
// profilesEmpty control which collections return rows; allEndpointError,
// when set, makes every authenticated endpoint fail with a controller error.
func omadaExtFakeController(t *testing.T, uplinkEmpty, switchEmpty, profilesEmpty, allEndpointError bool) *httptest.Server {
	t.Helper()
	const nets = `{"totalRows":3,"data":[
		{"id":"n1","name":"trusted","purpose":"lan","vlan":1,"gatewaySubnet":"10.0.10.1/24","deviceMac":"aa:bb:cc:dd:ee:00"},
		{"id":"n2","name":"gaming","purpose":"lan","vlan":30,"gatewaySubnet":"10.0.10.1/24","deviceMac":"aa:bb:cc:dd:ee:00"},
		{"id":"n3","name":"media","purpose":"lan","vlan":50,"gatewaySubnet":"10.0.10.1/24","deviceMac":"aa:bb:cc:dd:ee:00"}]}`
	const portsPopulated = `{"totalRows":3,"data":[
		{"port":8,"portName":"GE8","switchMac":"bb:11:22:33:44:55","switchName":"SW-CORE","networkMode":0,"profileId":"P1"},
		{"port":9,"portName":"GE9","switchMac":"aa:bb:cc:dd:ee:01","switchName":"SW-A","networkMode":1,"profileId":"P2"},
		{"port":10,"portName":"GE10","switchMac":"bb:11:22:33:44:55","switchName":"SW-CORE","networkMode":0,"profileId":"P3"}]}`
	const profilesPopulated = `{"totalRows":4,"data":[
		{"id":"P1","name":"Access-trusted","nativeNetworkId":"n1","tagNetworkIds":[],"untagNetworkIds":["n1"]},
		{"id":"P2","name":"gaming","nativeNetworkId":"n2","tagNetworkIds":[],"untagNetworkIds":["n2"]},
		{"id":"P3","name":"trusted+trunk","nativeNetworkId":"n1","tagNetworkIds":["n2"],"untagNetworkIds":["n1"]},
		{"id":"P4","name":"uplink-trunk","nativeNetworkId":"n1","tagNetworkIds":["n2","n3"],"untagNetworkIds":["n1"]}]}`
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if allEndpointError && r.URL.Path != "/api/info" && r.URL.Path != "/openapi/authorize/token" && r.URL.Path != "/openapi/v1/abc123/sites" {
			w.Write([]byte(`{"errorCode":-1005,"msg":"no permission","result":null}`))
			return
		}
		switch r.URL.Path {
		case "/api/info":
			w.Write([]byte(`{"errorCode":0,"msg":"","result":{"controllerVer":"6.4.5.1","apiVer":"2.0","omadacId":"abc123","configured":true,"omadacCategory":"advanced"}}`))
		case "/openapi/authorize/token":
			w.Write([]byte(`{"errorCode":0,"msg":"","result":{"accessToken":"tok"}}`))
		case "/openapi/v1/abc123/sites":
			w.Write([]byte(`{"errorCode":0,"msg":"","result":{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}}`))
		case "/openapi/v1/abc123/sites/s1/devices/uplink-info":
			if uplinkEmpty {
				w.Write([]byte(`{"errorCode":0,"msg":"","result":[]}`))
			} else {
				w.Write([]byte(`{"errorCode":0,"msg":"","result":[{"mac":"aa:bb:cc:dd:ee:01","uplinkDeviceMac":"bb:11:22:33:44:55","uplinkDeviceName":"SW-CORE","uplinkDevicePort":"8","linkSpeed":3,"duplex":2}]}`))
			}
		case "/openapi/v1/abc123/sites/s1/switches/ports/overview":
			if switchEmpty {
				w.Write([]byte(`{"errorCode":0,"msg":"","result":{"totalRows":0,"data":[]}}`))
			} else {
				w.Write([]byte(`{"errorCode":0,"msg":"","result":` + portsPopulated + `}`))
			}
		case "/openapi/v1/abc123/sites/s1/lan-profiles":
			if profilesEmpty {
				w.Write([]byte(`{"errorCode":0,"msg":"","result":{"totalRows":0,"data":[]}}`))
			} else {
				w.Write([]byte(`{"errorCode":0,"msg":"","result":` + profilesPopulated + `}`))
			}
		case "/openapi/v1/abc123/sites/s1/lan-networks":
			w.Write([]byte(`{"errorCode":0,"msg":"","result":` + nets + `}`))
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
	ts := omadaExtFakeController(t, false, false, false, false)
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
	ts := omadaExtFakeController(t, true, false, false, false)
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
	ts := omadaExtFakeController(t, false, false, false, false)
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

func TestShortMAC(t *testing.T) {
	cases := map[string]string{
		"aa:bb:cc:dd:ee:01": "...ee01",
		"aa-bb-cc-dd-ee-01": "...ee01",
		"AA BB CC DD EE 01": "...EE01",
		"ab:0":              "ab:0", // fewer than 4 hex digits: unchanged
		"":                  "",
	}
	for in, want := range cases {
		if got := shortMAC(in); got != want {
			t.Errorf("shortMAC(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestOmadaSwitchPortsCmd_Text(t *testing.T) {
	saveRestoreOmadaExtGlobals(t)
	ts := omadaExtFakeController(t, false, false, false, false)
	cmd := buildOmadaSwitchPortsCmd()
	providerHost = ts.URL
	providerSkipTLS = true
	out := captureStdout(func() {
		if err := cmd.RunE(cmd, nil); err != nil {
			t.Fatalf("switch-ports: %v", err)
		}
	})
	// Port 8 (SW-CORE, trunk) and port 9 (SW-A, access) rows with the
	// resolved native network and tagged-set rendering.
	for _, want := range []string{
		"PORT", "SWITCH", "MODE", "NATIVE", "PROFILE", "TAGGED",
		"...4455", "trunk", "trusted", // port 8: short MAC, trunk mode, native trusted
		"...ee01", "access", // port 9: access mode
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q:\n%s", want, out)
		}
	}
}

func TestOmadaSwitchPortsCmd_JSON(t *testing.T) {
	saveRestoreOmadaExtGlobals(t)
	ts := omadaExtFakeController(t, false, false, false, false)
	jsonOutput = true
	cmd := buildOmadaSwitchPortsCmd()
	providerHost = ts.URL
	providerSkipTLS = true
	out := captureStdout(func() {
		if err := cmd.RunE(cmd, nil); err != nil {
			t.Fatalf("switch-ports (json): %v", err)
		}
	})
	for _, want := range []string{`"port": 8`, `"switch_mac": "bb:11:22:33:44:55"`, `"native_network": "trusted"`} {
		if !strings.Contains(out, want) {
			t.Errorf("JSON output missing %q:\n%s", want, out)
		}
	}
}

func TestOmadaSwitchPortsCmd_JSONEmpty(t *testing.T) {
	saveRestoreOmadaExtGlobals(t)
	ts := omadaExtFakeController(t, false, true, false, false)
	jsonOutput = true
	cmd := buildOmadaSwitchPortsCmd()
	providerHost = ts.URL
	providerSkipTLS = true
	out := captureStdout(func() {
		if err := cmd.RunE(cmd, nil); err != nil {
			t.Fatalf("switch-ports (empty json): %v", err)
		}
	})
	if out != "[]\n" {
		t.Errorf("empty JSON output = %q, want []", out)
	}
}

func TestOmadaSwitchPortsCmd_TextEmpty(t *testing.T) {
	saveRestoreOmadaExtGlobals(t)
	ts := omadaExtFakeController(t, false, true, false, false)
	cmd := buildOmadaSwitchPortsCmd()
	providerHost = ts.URL
	providerSkipTLS = true
	out := captureStdout(func() {
		if err := cmd.RunE(cmd, nil); err != nil {
			t.Fatalf("switch-ports (empty text): %v", err)
		}
	})
	if !strings.Contains(out, "PORT") || strings.Contains(out, "...4455") {
		t.Errorf("empty text output = %q, want header only", out)
	}
}

func TestOmadaSwitchPortsCmd_NoHost(t *testing.T) {
	saveRestoreOmadaExtGlobals(t)
	cmd := buildOmadaSwitchPortsCmd()
	if err := cmd.RunE(cmd, nil); err == nil || !strings.Contains(err.Error(), "controller host is required") {
		t.Fatalf("error = %v, want host-required message", err)
	}
}

func TestOmadaSwitchPortsCmd_BadTimeout(t *testing.T) {
	saveRestoreOmadaExtGlobals(t)
	timeout = "bogus"
	cmd := buildOmadaSwitchPortsCmd()
	providerHost = "https://127.0.0.1:1"
	if err := cmd.RunE(cmd, nil); err == nil || !strings.Contains(err.Error(), "invalid --timeout") {
		t.Fatalf("error = %v, want invalid-timeout message", err)
	}
}

func TestOmadaSwitchPortsCmd_FetchError(t *testing.T) {
	saveRestoreOmadaExtGlobals(t)
	ts := omadaExtFakeController(t, false, false, false, true)
	cmd := buildOmadaSwitchPortsCmd()
	providerHost = ts.URL
	providerSkipTLS = true
	if err := cmd.RunE(cmd, nil); err == nil || !strings.Contains(err.Error(), "fetching switch ports overview") {
		t.Fatalf("error = %v, want ports-overview fetch error propagated", err)
	}
}

func TestOmadaLanProfilesCmd_Text(t *testing.T) {
	saveRestoreOmadaExtGlobals(t)
	ts := omadaExtFakeController(t, false, false, false, false)
	cmd := buildOmadaLanProfilesCmd()
	providerHost = ts.URL
	providerSkipTLS = true
	out := captureStdout(func() {
		if err := cmd.RunE(cmd, nil); err != nil {
			t.Fatalf("lan-profiles: %v", err)
		}
	})
	for _, want := range []string{
		"NAME", "NATIVE", "TAGGED",
		"Access-trusted", "trusted", // P1: native trusted, no tagged
		"gaming",                  // P2 row
		"trusted+trunk", "gaming", // P3: native trusted + tagged gaming
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q:\n%s", want, out)
		}
	}
	// P1 has no tagged networks: the column renders as a dash.
	if !strings.Contains(out, "-") {
		t.Errorf("text output missing dash for empty tagged set:\n%s", out)
	}
}

func TestOmadaLanProfilesCmd_JSON(t *testing.T) {
	saveRestoreOmadaExtGlobals(t)
	ts := omadaExtFakeController(t, false, false, false, false)
	jsonOutput = true
	cmd := buildOmadaLanProfilesCmd()
	providerHost = ts.URL
	providerSkipTLS = true
	out := captureStdout(func() {
		if err := cmd.RunE(cmd, nil); err != nil {
			t.Fatalf("lan-profiles (json): %v", err)
		}
	})
	for _, want := range []string{`"name": "Access-trusted"`, `"native_network": "trusted"`, `"tagged_networks"`} {
		if !strings.Contains(out, want) {
			t.Errorf("JSON output missing %q:\n%s", want, out)
		}
	}
}

func TestOmadaLanProfilesCmd_JSONEmpty(t *testing.T) {
	saveRestoreOmadaExtGlobals(t)
	ts := omadaExtFakeController(t, false, false, true, false)
	jsonOutput = true
	cmd := buildOmadaLanProfilesCmd()
	providerHost = ts.URL
	providerSkipTLS = true
	out := captureStdout(func() {
		if err := cmd.RunE(cmd, nil); err != nil {
			t.Fatalf("lan-profiles (empty json): %v", err)
		}
	})
	if out != "[]\n" {
		t.Errorf("empty JSON output = %q, want []", out)
	}
}

func TestOmadaLanProfilesCmd_NoHost(t *testing.T) {
	saveRestoreOmadaExtGlobals(t)
	cmd := buildOmadaLanProfilesCmd()
	if err := cmd.RunE(cmd, nil); err == nil || !strings.Contains(err.Error(), "controller host is required") {
		t.Fatalf("error = %v, want host-required message", err)
	}
}

func TestOmadaLanProfilesCmd_BadTimeout(t *testing.T) {
	saveRestoreOmadaExtGlobals(t)
	timeout = "bogus"
	cmd := buildOmadaLanProfilesCmd()
	providerHost = "https://127.0.0.1:1"
	if err := cmd.RunE(cmd, nil); err == nil || !strings.Contains(err.Error(), "invalid --timeout") {
		t.Fatalf("error = %v, want invalid-timeout message", err)
	}
}

func TestOmadaLanProfilesCmd_FetchError(t *testing.T) {
	saveRestoreOmadaExtGlobals(t)
	ts := omadaExtFakeController(t, false, false, false, true)
	cmd := buildOmadaLanProfilesCmd()
	providerHost = ts.URL
	providerSkipTLS = true
	if err := cmd.RunE(cmd, nil); err == nil || !strings.Contains(err.Error(), "fetching LAN profiles") {
		t.Fatalf("error = %v, want lan-profiles fetch error propagated", err)
	}
}

func TestOmadaUplinkInfoCmd_BadTimeout(t *testing.T) {
	saveRestoreOmadaExtGlobals(t)
	timeout = "bogus"
	cmd := buildOmadaUplinkInfoCmd()
	omadaUplinkMAC = "aa:bb:cc:dd:ee:01"
	providerHost = "https://127.0.0.1:1"
	if err := cmd.RunE(cmd, nil); err == nil || !strings.Contains(err.Error(), "invalid --timeout") {
		t.Fatalf("error = %v, want invalid-timeout message", err)
	}
}

func TestOmadaUplinkInfoCmd_FetchError(t *testing.T) {
	saveRestoreOmadaExtGlobals(t)
	ts := omadaExtFakeController(t, false, false, false, true)
	cmd := buildOmadaUplinkInfoCmd()
	omadaUplinkMAC = "aa:bb:cc:dd:ee:01"
	providerHost = ts.URL
	providerSkipTLS = true
	if err := cmd.RunE(cmd, nil); err == nil || !strings.Contains(err.Error(), "fetching uplink info") {
		t.Fatalf("error = %v, want uplink-info fetch error propagated", err)
	}
}

func TestOmadaUplinkInfoCmd_TextEmpty(t *testing.T) {
	saveRestoreOmadaExtGlobals(t)
	ts := omadaExtFakeController(t, true, false, false, false)
	cmd := buildOmadaUplinkInfoCmd()
	omadaUplinkMAC = "aa:bb:cc:dd:ee:01"
	providerHost = ts.URL
	providerSkipTLS = true
	out := captureStdout(func() {
		if err := cmd.RunE(cmd, nil); err != nil {
			t.Fatalf("uplink-info (empty text): %v", err)
		}
	})
	if !strings.Contains(out, "No uplink observed for aa:bb:cc:dd:ee:01") {
		t.Errorf("empty text output = %q, want the no-uplink message", out)
	}
}

// TestOmadaLanProfilesCmd_MultiTagged pins joinOrDash's "+" join: a
// profile with several tagged networks renders them joined, not as a dash.
func TestOmadaLanProfilesCmd_MultiTagged(t *testing.T) {
	saveRestoreOmadaExtGlobals(t)
	ts := omadaExtFakeController(t, false, false, false, false)
	cmd := buildOmadaLanProfilesCmd()
	providerHost = ts.URL
	providerSkipTLS = true
	out := captureStdout(func() {
		if err := cmd.RunE(cmd, nil); err != nil {
			t.Fatalf("lan-profiles: %v", err)
		}
	})
	// The multi-tagged fixture row shows both tagged names joined with "+".
	if !strings.Contains(out, "gaming+media") {
		t.Errorf("text output missing multi-tagged join:\n%s", out)
	}
}

func TestJoinOrDash(t *testing.T) {
	if got := joinOrDash(nil); got != "-" {
		t.Errorf("joinOrDash(nil) = %q, want -", got)
	}
	if got := joinOrDash([]string{"a"}); got != "a" {
		t.Errorf("joinOrDash(one) = %q, want a", got)
	}
	if got := joinOrDash([]string{"a", "b", "c"}); got != "a+b+c" {
		t.Errorf("joinOrDash(many) = %q, want a+b+c", got)
	}
}
