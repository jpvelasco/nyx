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
		{"host missing", map[string]string{"OMADA_USERNAME": "u", "OMADA_PASSWORD": "p"}, "set OMADA_HOST"},
		{"user missing", map[string]string{"OMADA_HOST": "h", "OMADA_PASSWORD": "p"}, "set OMADA_HOST"},
		{"pass missing", map[string]string{"OMADA_HOST": "h", "OMADA_USERNAME": "u"}, "set OMADA_HOST"},
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
		case strings.Contains(r.URL.Path, "/login"):
			fmt.Fprint(w, `{"errorCode":0,"msg":"","result":{"token":"tok123"}}`) //nosem // test mock
		case strings.Contains(r.URL.Path, "/logout"):
			fmt.Fprint(w, `{"errorCode":0,"msg":"","result":null}`) //nosem // test mock
		case strings.Contains(r.URL.Path, "/clients"):
			//nosem // test mock
			fmt.Fprint(w, envelope(`{"totalRows":2,"data":[
				{"mac":"aa:bb:cc:dd:ee:01","ip":"10.0.20.10","name":"PC1","hostName":"pc1","networkName":"LAN","vid":1,"wireless":false,"vendor":"Dell","deviceType":"Computer","active":true,"uptime":100},
				{"mac":"aa:bb:cc:dd:ee:02","ip":"10.0.20.20","name":"PC2","hostName":"pc2","networkName":"LAN","vid":1,"wireless":true,"vendor":"Apple","deviceType":"Laptop","active":true,"uptime":200}
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
		case "OMADA_USERNAME":
			return "admin"
		case "OMADA_PASSWORD":
			return "secret"
		}
		return ""
	}

	var stdout bytes.Buffer
	err := run(getenv, &stdout)
	if err != nil {
		t.Fatalf("run() error: %v", err)
	}

	out := stdout.String()
	for _, want := range []string{"Site: Home", "LAN", "pc1", "pc2", "10.0.20.10", "10.0.20.20"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestRun_LoginFailure(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/info":
			fmt.Fprint(w, `{"errorCode":0,"msg":"","result":{"controllerVer":"6.4.5.1","apiVer":"3","omadacId":"test","configured":true}}`) //nosem // test mock
		case strings.Contains(r.URL.Path, "/login"):
			fmt.Fprint(w, `{"errorCode":-30109,"msg":"invalid username or password","result":null}`) //nosem // test mock
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
		case "OMADA_USERNAME":
			return "baduser"
		case "OMADA_PASSWORD":
			return "badpass"
		}
		return ""
	}

	var stdout bytes.Buffer
	err := run(getenv, &stdout)
	if err == nil {
		t.Fatal("expected login error")
	}
	if !strings.Contains(err.Error(), "invalid username or password") {
		t.Errorf("error = %q, want login failure indication", err.Error())
	}
}

func TestRun_NewClientFailure(t *testing.T) {
	// Use an invalid host that will fail TLS/URL parsing in NewClient.
	getenv := func(key string) string {
		switch key {
		case "OMADA_HOST":
			return "not-a-valid-host"
		case "OMADA_USERNAME":
			return "admin"
		case "OMADA_PASSWORD":
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
		case strings.Contains(r.URL.Path, "/login"):
			fmt.Fprint(w, `{"errorCode":0,"msg":"","result":{"token":"tok123"}}`) //nosem // test mock
		case strings.Contains(r.URL.Path, "/logout"):
			fmt.Fprint(w, `{"errorCode":0,"msg":"","result":null}`) //nosem // test mock
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
		case "OMADA_USERNAME":
			return "admin"
		case "OMADA_PASSWORD":
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
		case strings.Contains(r.URL.Path, "/login"):
			fmt.Fprint(w, `{"errorCode":0,"msg":"","result":{"token":"tok123"}}`) //nosem // test mock
		case strings.Contains(r.URL.Path, "/logout"):
			fmt.Fprint(w, `{"errorCode":0,"msg":"","result":null}`) //nosem // test mock
		case strings.Contains(r.URL.Path, "/clients"):
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
		case "OMADA_USERNAME":
			return "admin"
		case "OMADA_PASSWORD":
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
		case strings.Contains(r.URL.Path, "/login"):
			fmt.Fprint(w, `{"errorCode":0,"msg":"","result":{"token":"tok123"}}`) //nosem // test mock
		case strings.Contains(r.URL.Path, "/logout"):
			fmt.Fprint(w, `{"errorCode":0,"msg":"","result":null}`) //nosem // test mock
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
		case "OMADA_USERNAME":
			return "admin"
		case "OMADA_PASSWORD":
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
		case strings.Contains(r.URL.Path, "/login"):
			fmt.Fprint(w, `{"errorCode":0,"msg":"","result":{"token":"tok123"}}`) //nosem // test mock
		case strings.Contains(r.URL.Path, "/logout"):
			fmt.Fprint(w, `{"errorCode":0,"msg":"","result":null}`) //nosem // test mock
		case strings.Contains(r.URL.Path, "/clients"):
			//nosem // test mock
			fmt.Fprint(w, envelope(`{"totalRows":1,"data":[
				{"mac":"aa:bb:cc:dd:ee:01","ip":"10.0.20.10","name":"PC1","hostName":"pc1","networkName":"LAN","vid":1,"wireless":false,"vendor":"Dell","deviceType":"Computer","active":true,"uptime":100}
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
		case "OMADA_USERNAME":
			return "admin"
		case "OMADA_PASSWORD":
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
