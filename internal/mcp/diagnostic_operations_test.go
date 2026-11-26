package mcp

import (
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/backends/omada"
	"github.com/jpvelasco/nyx/internal/snapshot"
	"github.com/jpvelasco/nyx/internal/testutil"
)

func TestDiagnosticToolDiscoveryAndBounds(t *testing.T) {
	hermeticCreds(t)
	s := NewServerWithLogger(nil)
	for _, name := range []string{"omada_ap_channel_info", "omada_wlan_optimization", "omada_controller_firmware", "omada_site_config_drift", "opnsense_query_states"} {
		if !slices.Contains(ToolNames(), name) {
			t.Errorf("missing %s", name)
		}
		if _, failed := s.dispatchTool(t.Context(), name, nil); !failed {
			t.Errorf("accepted missing connection for %s", name)
		}
		for _, key := range []string{"host", "site", "api_key", "ca_cert_path", "skip_tls_verify"} {
			if got, failed := s.dispatchTool(t.Context(), name, map[string]any{key: "other.example"}); !failed || !strings.Contains(got, "unsupported diagnostic argument") {
				t.Fatal("accepted connection override", name, key)
			}
		}
	}
	for _, bad := range []map[string]any{{"profile": 2}, {"include_private_details": "false"}} {
		if _, failed := s.dispatchTool(t.Context(), "omada_ap_channel_info", bad); !failed {
			t.Fatal("accepted invalid diagnostic argument")
		}
	}
	for _, value := range []any{float64(-1), float64(201), 0.5, "50"} {
		got, failed := s.dispatchTool(t.Context(), "omada_ap_channel_info", map[string]any{"limit": value})
		if !failed || !strings.Contains(got, "limit") {
			t.Fatal(value, got)
		}
	}
	page := diagnosticRows([]string{"first", "second"}, diagnosticWindow{offset: 1, limit: 10})
	if page.Total != 2 || len(page.Rows) != 1 || page.Rows[0] != "second" {
		t.Fatal(page)
	}
	if got := diagnosticRows([]string{"first"}, diagnosticWindow{offset: 5, limit: 1}); got.Rows == nil || len(got.Rows) != 0 {
		t.Fatal(got)
	}
}

func TestDiagnosticStatePrivacyAndFailures(t *testing.T) {
	hermeticCreds(t)
	status := http.StatusOK
	calls := 0
	firewall, ca := testutil.CASignedServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/api/diagnostics/firewall/query_states" || r.Method != http.MethodPost {
			t.Errorf("unexpected state request")
		}
		if status != http.StatusOK {
			w.WriteHeader(status)
			testutil.WriteBody(w, "private server message")
			return
		}
		var query struct {
			Search string            `json:"searchPhrase"`
			Page   int               `json:"current"`
			Limit  int               `json:"rowCount"`
			Sort   map[string]string `json:"sort"`
		}
		if err := json.NewDecoder(r.Body).Decode(&query); err != nil || query.Search != "ESTABLISHED" || query.Page != 1 || query.Limit != 2 || query.Sort["age"] != "desc" {
			t.Errorf("invalid filter or pagination: %v", query)
		}
		testutil.WriteBody(w, `{"total":1,"current":1,"rowCount":1,"rows":[{"source":"host.example"}]}`)
	}))
	configureDiagnosticFirewall(t, firewall, ca)
	args := map[string]any{"page_size": float64(2), "sort": "age:desc"}
	s := NewServerWithLogger(nil)
	if _, failed := s.dispatchTool(t.Context(), "opnsense_query_states", args); !failed || calls != 0 {
		t.Fatal("unscoped query accepted")
	}
	args["search"] = "ESTABLISHED"
	for _, details := range []bool{false, true} {
		args["include_private_details"] = details
		got, failed := s.dispatchTool(t.Context(), "opnsense_query_states", args)
		if failed || strings.Contains(got, "host.example") != details {
			t.Fatalf("unexpected state details %v: %s", details, got)
		}
	}
	status = http.StatusForbidden
	got, failed := s.dispatchTool(t.Context(), "opnsense_query_states", args)
	if !failed || !strings.Contains(got, "permission_denied") || strings.Contains(got, "private server message") {
		t.Fatal(got)
	}
}

func TestOmadaDiagnosticPrivacyAndEmpty(t *testing.T) {
	hermeticCreds(t)
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	controller, ca := testutil.CASignedServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body string
		switch r.URL.Path {
		case "/api/info":
			body = `{"controllerVer":"6.3","apiVer":"1","omadacId":"fixture","configured":true}`
		case "/openapi/authorize/token":
			body = `{"accessToken":"fixture-token"}`
		case "/openapi/v1/fixture/sites":
			body = `[{"id":"site","name":"management"}]`
		case "/openapi/v1/fixture/sites/site/networks/devices":
			body = `[{"name":"access-point.example","type":"AP","mac":"02-00-00-00-00-01"}]`
		case "/openapi/v1/fixture/sites/site/aps/02-00-00-00-00-01/radios":
			body = `{"wp5g":{"actualChannel":"36"}}`
		case "/openapi/v1/fixture/sites/site/aps/02-00-00-00-00-01/available-channel":
			body = `{"wp5g":[36,40]}`
		case "/openapi/v1/fixture/system/setting/hardware/check-firmware":
			body = `{"update":false,"currentVersion":"1.0","latestVersion":"1.0"}`
		case "/openapi/v1/fixture/sites/site/lan-networks", "/openapi/v1/fixture/sites/site/acls/osw-acls", "/openapi/v1/fixture/sites/site/wlan-groups", "/openapi/v1/fixture/sites/site/ssids":
			body = `[]`
		case "/openapi/v1/fixture/sites/site/planningHistory/run":
			body = `{"successDevices":0,"failDevices":0,"data":[]}`
		case "/openapi/v1/fixture/sites/site/planningHistory":
			body = `[]`
		default:
			t.Errorf("unexpected diagnostic path %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		testutil.WriteBody(w, `{"errorCode":0,"result":`+body+`}`)
	}))
	configureDiagnosticController(t, controller, ca)
	args := map[string]any{}
	s := NewServerWithLogger(nil)
	for _, details := range []bool{false, true} {
		args["include_private_details"] = details
		got, failed := s.dispatchTool(t.Context(), "omada_ap_channel_info", args)
		if failed || !strings.Contains(got, "36") || strings.Contains(got, "access-point.example") != details || strings.Contains(got, "02-00-00-00-00-01") != details {
			t.Fatal(got)
		}
	}
	delete(args, "include_private_details")
	got, failed := s.dispatchTool(t.Context(), "omada_wlan_optimization", args)
	if failed || !strings.Contains(got, `"total": 0`) {
		t.Fatal(got)
	}
	args["history_id"] = "run"
	got, failed = s.dispatchTool(t.Context(), "omada_wlan_optimization", args)
	if failed || !strings.Contains(got, "success_devices") {
		t.Fatal(got)
	}
	delete(args, "history_id")
	got, failed = s.dispatchTool(t.Context(), "omada_controller_firmware", args)
	if failed || !strings.Contains(got, "up_to_date") {
		t.Fatal(got)
	}
	got, failed = s.dispatchTool(t.Context(), "omada_site_config_drift", args)
	if !failed || !strings.Contains(got, "site-config snapshot") {
		t.Fatal(got)
	}
	if err := snapshot.SaveOmadaSiteConfig(omada.SiteConfigState{Scope: sha256.Sum256([]byte("fixture\x00site")), Resources: omada.SiteConfig{}}); err != nil {
		t.Fatal(err)
	}
	got, failed = s.dispatchTool(t.Context(), "omada_site_config_drift", args)
	if failed || !strings.Contains(got, `"total": 0`) {
		t.Fatal(got)
	}
}

func configureDiagnosticController(t *testing.T, host, ca string) {
	t.Helper()
	t.Setenv("OMADA_HOST", host)
	t.Setenv("OMADA_CLIENT_ID", "fixture")
	t.Setenv("OMADA_CLIENT_SECRET", "fixture")
	t.Setenv("OMADA_SITE", "management")
	t.Setenv("NYX_OMADA_CA_CERT", ca)
}

func configureDiagnosticFirewall(t *testing.T, host, ca string) {
	t.Helper()
	t.Setenv("OPNSENSE_HOST", strings.TrimPrefix(host, "https://"))
	t.Setenv("OPNSENSE_API_KEY", "fixture")
	t.Setenv("OPNSENSE_API_SECRET", "fixture")
	t.Setenv("NYX_OPNSENSE_CA_CERT", ca)
}

func TestDiagnosticReadErrorsDoNotExposeVendorPayload(t *testing.T) {
	hermeticCreds(t)
	host, ca := testutil.CASignedServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/info":
			testutil.WriteBody(w, `{"errorCode":0,"result":{"controllerVer":"6.3.0","omadacId":"fixture"}}`)
		case "/openapi/authorize/token":
			testutil.WriteBody(w, `{"errorCode":0,"result":{"accessToken":"fixture"}}`)
		case "/openapi/v1/fixture/sites":
			testutil.WriteBody(w, `{"errorCode":0,"result":[{"id":"site","name":"management"}]}`)
		default:
			http.Error(w, "private.example", http.StatusForbidden)
		}
	}))
	configureDiagnosticController(t, host, ca)
	configureDiagnosticFirewall(t, host, ca)
	s := NewServerWithLogger(nil)
	a := map[string]any{}
	for _, n := range []string{"omada_wlan_optimization", "omada_site_config_drift", "omada_ap_channel_info"} {
		got, failed := s.dispatchTool(t.Context(), n, a)
		if !failed || strings.Contains(got, "private.example") {
			t.Fatal(n, got)
		}
	}
	a["history_id"] = "private-run"
	if _, failed := s.dispatchTool(t.Context(), "omada_wlan_optimization", a); !failed {
		t.Fatal("accepted unreadable history")
	}
	for _, tc := range []struct {
		key   string
		value any
	}{{"page", float64(0)}, {"page_size", float64(201)}, {"sort", "invalid"}} {
		a = map[string]any{"search": "selected", tc.key: tc.value}
		if _, failed := s.dispatchTool(t.Context(), "opnsense_query_states", a); !failed {
			t.Fatal("accepted invalid state query", tc.key)
		}
	}
}
