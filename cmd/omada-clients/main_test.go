package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// envelope wraps a payload in the Omada API response envelope.
func envelope(result string) string {
	return `{"errorCode":0,"msg":"","result":` + result + `}`
}

func TestRun_MissingCredentials(t *testing.T) {
	cases := []struct {
		name    string
		env     map[string]string
		wantSub string
	}{
		{"all missing", map[string]string{}, "set OMADA_HOST"},
		{"host missing", map[string]string{"OMADA_CLIENT_ID": "u", "OMADA_CLIENT_SECRET": "p"}, "set OMADA_HOST"},
		{"client id missing", map[string]string{"OMADA_HOST": "h", "OMADA_CLIENT_SECRET": "p"}, "set OMADA_HOST"},
		{"client secret missing", map[string]string{"OMADA_HOST": "h", "OMADA_CLIENT_ID": "u"}, "set OMADA_HOST"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			getenv := func(key string) string { return tc.env[key] }
			var stdout bytes.Buffer
			err := run(getenv, &stdout)
			if err == nil {
				t.Fatal("expected error for missing credentials")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error = %q, want substring %q", err.Error(), tc.wantSub)
			}
		})
	}
}

func TestRun_Success(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/info":
			fmt.Fprint(w, `{"errorCode":0,"msg":"","result":{"controllerVer":"6.4.5.1","apiVer":"3","omadacId":"test","configured":true}}`) //nosem // test mock
		case r.URL.Path == "/openapi/authorize/token":
			fmt.Fprint(w, `{"errorCode":0,"msg":"","result":{"accessToken":"tok123"}}`) //nosem // test mock
		case strings.Contains(r.URL.Path, "/lan-networks"):
			//nosem // test mock — Open API shape (dhcpSettingsVO nested, no origName)
			fmt.Fprint(w, envelope(`{"totalRows":1,"data":[
				{"id":"n1","name":"LAN","vlan":1,"gatewaySubnet":"10.0.20.1/24","isolation":false,"dhcpSettingsVO":{"enable":true},"deviceMac":"aa:bb:cc:dd:ee:ff"}
			]}`))
		case strings.Contains(r.URL.Path, "/networks/client"):
			//nosem // test mock — thin client rows (mac/name/type only)
			fmt.Fprint(w, envelope(`{"totalRows":2,"data":[
				{"mac":"aa:bb:cc:dd:ee:01","name":"pc1","type":"wired"},
				{"mac":"aa:bb:cc:dd:ee:02","name":"pc2","type":"wireless"}
			]}`))
		case strings.Contains(r.URL.Path, "/setting/service/dhcp/user-list"):
			//nosem // test mock — DHCP leases join back onto client rows by MAC
			fmt.Fprint(w, envelope(`{"totalRows":2,"data":[
				{"ipAddress":"10.0.20.10","macAddress":"aa:bb:cc:dd:ee:01","name":"pc1","netId":"n1","netName":"LAN"},
				{"ipAddress":"10.0.20.20","macAddress":"aa:bb:cc:dd:ee:02","name":"pc2","netId":"n1","netName":"LAN"}
			]}`))
		case strings.Contains(r.URL.Path, "/sites"):
			fmt.Fprint(w, envelope(`{"totalRows":1,"data":[{"id":"site1","name":"Home","type":0}]}`)) //nosem // test mock
		default:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"errorCode":-1,"msg":"not found","result":null}`) //nosem // test mock
		}
	}))
	defer ts.Close()

	getenv := func(key string) string {
		switch key {
		case "OMADA_HOST":
			return strings.TrimPrefix(ts.URL, "https://")
		case "OMADA_CLIENT_ID":
			return "admin"
		case "OMADA_CLIENT_SECRET":
			return "secret"
		}
		return ""
	}

	var stdout bytes.Buffer
	err := run(getenv, &stdout)
	if err != nil {
		t.Fatalf("run() error: %v", err)
	}

	// Both clients resolve IP and network "LAN" via the DHCP user list.
	out := stdout.String()
	for _, want := range []string{"Site: Home", "LAN (VLAN 1)", "pc1", "pc2", "10.0.20.10", "10.0.20.20"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestRun_LoginFailure(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/info":
			fmt.Fprint(w, `{"errorCode":0,"msg":"","result":{"controllerVer":"6.4.5.1","apiVer":"3","omadacId":"test","configured":true}}`) //nosem // test mock
		case "/openapi/authorize/token":
			fmt.Fprint(w, `{"errorCode":-44106,"msg":"invalid client credentials","result":null}`) //nosem // test mock
		default:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"errorCode":-1,"msg":"not found","result":null}`) //nosem // test mock
		}
	}))
	defer ts.Close()

	getenv := func(key string) string {
		switch key {
		case "OMADA_HOST":
			return strings.TrimPrefix(ts.URL, "https://")
		case "OMADA_CLIENT_ID":
			return "baduser"
		case "OMADA_CLIENT_SECRET":
			return "badpass"
		}
		return ""
	}

	var stdout bytes.Buffer
	err := run(getenv, &stdout)
	if err == nil {
		t.Fatal("expected login error")
	}
	if !strings.Contains(err.Error(), "invalid client credentials") {
		t.Errorf("error = %q, want login failure indication", err.Error())
	}
}

func TestRun_NewClientFailure(t *testing.T) {
	// Use an invalid host that will fail TLS/URL parsing in NewClient.
	getenv := func(key string) string {
		switch key {
		case "OMADA_HOST":
			return "not-a-valid-host"
		case "OMADA_CLIENT_ID":
			return "admin"
		case "OMADA_CLIENT_SECRET":
			return "secret"
		}
		return ""
	}

	var stdout bytes.Buffer
	err := run(getenv, &stdout)
	if err == nil {
		t.Fatal("expected error from NewClient with invalid host")
	}
}

func TestRun_SelectSiteFailure(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/info":
			fmt.Fprint(w, `{"errorCode":0,"msg":"","result":{"controllerVer":"6.4.5.1","apiVer":"3","omadacId":"test","configured":true}}`) //nosem // test mock
		case r.URL.Path == "/openapi/authorize/token":
			fmt.Fprint(w, `{"errorCode":0,"msg":"","result":{"accessToken":"tok123"}}`) //nosem // test mock
		case strings.Contains(r.URL.Path, "/sites"):
			// Return multiple sites but request a non-existent one.
			fmt.Fprint(w, envelope(`{"totalRows":2,"data":[{"id":"site1","name":"Home","type":0},{"id":"site2","name":"Office","type":0}]}`)) //nosem // test mock
		default:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"errorCode":-1,"msg":"not found","result":null}`) //nosem // test mock
		}
	}))
	defer ts.Close()

	getenv := func(key string) string {
		switch key {
		case "OMADA_HOST":
			return strings.TrimPrefix(ts.URL, "https://")
		case "OMADA_CLIENT_ID":
			return "admin"
		case "OMADA_CLIENT_SECRET":
			return "secret"
		case "OMADA_SITE":
			return "NonExistent"
		}
		return ""
	}

	var stdout bytes.Buffer
	err := run(getenv, &stdout)
	if err == nil {
		t.Fatal("expected error when requested site not found")
	}
}

func TestRun_GetClientsFailure(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/info":
			fmt.Fprint(w, `{"errorCode":0,"msg":"","result":{"controllerVer":"6.4.5.1","apiVer":"3","omadacId":"test","configured":true}}`) //nosem // test mock
		case r.URL.Path == "/openapi/authorize/token":
			fmt.Fprint(w, `{"errorCode":0,"msg":"","result":{"accessToken":"tok123"}}`) //nosem // test mock
		case strings.Contains(r.URL.Path, "/networks/client"):
			// Return an error for the clients endpoint.
			fmt.Fprint(w, `{"errorCode":-1,"msg":"internal error","result":null}`) //nosem // test mock
		case strings.Contains(r.URL.Path, "/sites"):
			fmt.Fprint(w, envelope(`{"totalRows":1,"data":[{"id":"site1","name":"Home","type":0}]}`)) //nosem // test mock
		default:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"errorCode":-1,"msg":"not found","result":null}`) //nosem // test mock
		}
	}))
	defer ts.Close()

	getenv := func(key string) string {
		switch key {
		case "OMADA_HOST":
			return strings.TrimPrefix(ts.URL, "https://")
		case "OMADA_CLIENT_ID":
			return "admin"
		case "OMADA_CLIENT_SECRET":
			return "secret"
		}
		return ""
	}

	var stdout bytes.Buffer
	err := run(getenv, &stdout)
	if err == nil {
		t.Fatal("expected error from GetClients")
	}
}

func TestRun_NoSites(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/info":
			fmt.Fprint(w, `{"errorCode":0,"msg":"","result":{"controllerVer":"6.4.5.1","apiVer":"3","omadacId":"test","configured":true}}`) //nosem // test mock
		case r.URL.Path == "/openapi/authorize/token":
			fmt.Fprint(w, `{"errorCode":0,"msg":"","result":{"accessToken":"tok123"}}`) //nosem // test mock
		case strings.Contains(r.URL.Path, "/sites"):
			fmt.Fprint(w, envelope(`{"totalRows":0,"data":[]}`)) //nosem // test mock
		default:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"errorCode":-1,"msg":"not found","result":null}`) //nosem // test mock
		}
	}))
	defer ts.Close()

	getenv := func(key string) string {
		switch key {
		case "OMADA_HOST":
			return strings.TrimPrefix(ts.URL, "https://")
		case "OMADA_CLIENT_ID":
			return "admin"
		case "OMADA_CLIENT_SECRET":
			return "secret"
		}
		return ""
	}

	var stdout bytes.Buffer
	err := run(getenv, &stdout)
	if err == nil {
		t.Fatal("expected error when no sites found")
	}
}

func TestRunMain_Success(t *testing.T) {
	// Use a valid host that will succeed (we'll mock the server).
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/info":
			fmt.Fprint(w, `{"errorCode":0,"msg":"","result":{"controllerVer":"6.4.5.1","apiVer":"3","omadacId":"test","configured":true}}`) //nosem // test mock
		case r.URL.Path == "/openapi/authorize/token":
			fmt.Fprint(w, `{"errorCode":0,"msg":"","result":{"accessToken":"tok123"}}`) //nosem // test mock
		case strings.Contains(r.URL.Path, "/lan-networks"):
			//nosem // test mock
			fmt.Fprint(w, envelope(`{"totalRows":1,"data":[
				{"id":"n1","name":"LAN","vlan":1,"gatewaySubnet":"10.0.20.1/24","isolation":false,"dhcpSettingsVO":{"enable":true}}
			]}`))
		case strings.Contains(r.URL.Path, "/networks/client"):
			//nosem // test mock
			fmt.Fprint(w, envelope(`{"totalRows":1,"data":[
				{"mac":"aa:bb:cc:dd:ee:01","name":"pc1","type":"wired"}
			]}`))
		case strings.Contains(r.URL.Path, "/setting/service/dhcp/user-list"):
			//nosem // test mock
			fmt.Fprint(w, envelope(`{"totalRows":1,"data":[
				{"ipAddress":"10.0.20.10","macAddress":"aa:bb:cc:dd:ee:01","name":"pc1","netId":"n1","netName":"LAN"}
			]}`))
		case strings.Contains(r.URL.Path, "/sites"):
			fmt.Fprint(w, envelope(`{"totalRows":1,"data":[{"id":"site1","name":"Home","type":0}]}`)) //nosem // test mock
		default:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"errorCode":-1,"msg":"not found","result":null}`) //nosem // test mock
		}
	}))
	defer ts.Close()

	getenv := func(key string) string {
		switch key {
		case "OMADA_HOST":
			return strings.TrimPrefix(ts.URL, "https://")
		case "OMADA_CLIENT_ID":
			return "admin"
		case "OMADA_CLIENT_SECRET":
			return "secret"
		}
		return ""
	}

	var stdout, stderr bytes.Buffer
	code := runMain(getenv, &stdout, &stderr)
	if code != 0 {
		t.Errorf("runMain() = %d, want 0 (success)", code)
	}
	if stderr.Len() != 0 {
		t.Errorf("runMain() wrote to stderr: %s", stderr.String())
	}
	if !strings.Contains(stdout.String(), "Site: Home") {
		t.Errorf("runMain() output missing 'Site: Home':\n%s", stdout.String())
	}
}

func TestRunMain_Failure(t *testing.T) {
	// Use missing credentials to trigger a failure.
	getenv := func(key string) string {
		return ""
	}

	var stdout, stderr bytes.Buffer
	code := runMain(getenv, &stdout, &stderr)
	if code != 1 {
		t.Errorf("runMain() = %d, want 1 (failure)", code)
	}
	if !strings.Contains(stderr.String(), "omada-clients:") {
		t.Errorf("runMain() stderr missing 'omada-clients:':\n%s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "set OMADA_HOST") {
		t.Errorf("runMain() stderr missing error message:\n%s", stderr.String())
	}
}

var _ io.Writer = (*bytes.Buffer)(nil)
