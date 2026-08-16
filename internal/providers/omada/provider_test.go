package omadaprovider

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	omadabackend "github.com/jpvelasco/nyx/internal/backends/omada"
	providers "github.com/jpvelasco/nyx/internal/providers"
)

const infoJSON = `{"errorCode":0,"msg":"","result":{"controllerVer":"6.4.5.1","apiVer":"2.0","omadacId":"abc123","configured":true}}`

// TestParseAPIResponse tests parsing API response
func TestParseAPIResponse(t *testing.T) {
	jsonData := `{
		"networks": [
			{"name": "personal", "cidr": "10.0.0.0/24"}
		],
		"policies": [
			{"name": "personal-isolation", "from": "personal", "to": "gaming", "action": "deny"}
		]
	}`

	var response struct {
		Networks []struct {
			Name string `json:"name"`
			Cidr string `json:"cidr"`
		} `json:"networks"`
		Policies []struct {
			Name   string `json:"name"`
			From   string `json:"from"`
			To     string `json:"to"`
			Action string `json:"action"`
		} `json:"policies"`
	}

	if err := json.Unmarshal([]byte(jsonData), &response); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	if len(response.Networks) == 0 {
		t.Error("expected at least one network")
	}

	if len(response.Policies) == 0 {
		t.Error("expected at least one policy")
	}
}

func writeEnvelope(w http.ResponseWriter, errorCode int, msg, result string) {
	w.Write([]byte(`{"errorCode":` + itoa(errorCode) + `,"msg":"` + msg + `","result":` + result + `}`))
}

func readReqBody(t *testing.T, r *http.Request) string {
	t.Helper()
	data, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("reading request body: %v", err)
	}
	return string(data)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	return itoa(n/10) + string(rune('0'+n%10))
}

// omadaServer serves a canned Omada 6.x API for provider-level tests.
func omadaServer(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/info" {
			w.Write([]byte(infoJSON))
			return
		}
		h(w, r)
	}))
	t.Cleanup(ts.Close)
	return ts
}

func TestProviderIdentity(t *testing.T) {
	p := &OmadaProvider{}
	if p.Name() != "omada" {
		t.Errorf("Name() = %q, want omada", p.Name())
	}
	caps := p.Capabilities()
	if len(caps) != 3 || caps[0] != "info" || caps[1] != "import" || caps[2] != "check" {
		t.Errorf("Capabilities() = %v, want [info import check]", caps)
	}
}

func TestProviderInfo(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		ts := omadaServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		p := &OmadaProvider{}
		info, err := p.Info(context.Background(), providers.ImportOptions{Host: ts.URL, SkipTLSVerify: true})
		if err != nil {
			t.Fatalf("Info: %v", err)
		}
		if info.Provider != "omada" || info.Version != "6.4.5.1" {
			t.Errorf("info = %+v", info)
		}
		if info.Extra["api_version"] != "2.0" || info.Extra["omada_cid"] != "abc123" {
			t.Errorf("extra = %v", info.Extra)
		}
	})

	t.Run("connect fails", func(t *testing.T) {
		p := &OmadaProvider{}
		_, err := p.Info(context.Background(), providers.ImportOptions{Host: "https://127.0.0.1:1"})
		if err == nil || !strings.Contains(err.Error(), "connecting to omada controller") {
			t.Errorf("error = %v, want connecting to omada controller", err)
		}
	})
}

func TestProviderImportSpec(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		ts := omadaServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/abc123/api/v2/login":
				writeEnvelope(w, 0, "", `{"token":"t1"}`)
			case "/abc123/api/v2/logout":
				writeEnvelope(w, 0, "", "null")
			case "/abc123/api/v2/sites":
				writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
			case "/abc123/api/v2/sites/s1/setting/lan/networks":
				writeEnvelope(w, 0, "", `{"totalRows":1,"data":[
					{"id":"n1","name":"Trusted","gatewaySubnet":"10.0.0.1/24"}
				]}`)
			case "/abc123/api/v2/sites/s1/setting/firewall/acls":
				if r.URL.Query().Get("type") == "0" {
					writeEnvelope(w, 0, "", `{"totalRows":0,"data":[]}`)
					return
				}
				writeEnvelope(w, 0, "", `{"totalRows":1,"data":[
					{"id":"a1","name":"Deny IoT","status":true,"policy":0}
				]}`)
			case "/abc123/api/v2/sites/s1/clients":
				writeEnvelope(w, 0, "", `{"totalRows":1,"data":[
					{"mac":"aa","ip":"10.0.0.10","networkName":"Trusted"}
				]}`)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		p := &OmadaProvider{}
		res, err := p.ImportSpec(context.Background(), providers.ImportOptions{
			Host: ts.URL, Username: "admin", Password: "pw", Site: "hq", SkipTLSVerify: true,
		})
		if err != nil {
			t.Fatalf("ImportSpec: %v", err)
		}
		if res.NetworkCount != 1 || res.PolicyCount != 1 || res.ClientCount != 1 {
			t.Errorf("counts = %d/%d/%d, want 1/1/1", res.NetworkCount, res.PolicyCount, res.ClientCount)
		}
		if res.ProviderInfo.Version != "6.4.5.1" {
			t.Errorf("version = %q", res.ProviderInfo.Version)
		}
		if res.Spec == nil || len(res.Spec.Networks) != 1 {
			t.Fatalf("spec = %+v, want 1 network", res.Spec)
		}
	})

	t.Run("import error propagates", func(t *testing.T) {
		ts := omadaServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/abc123/api/v2/login":
				writeEnvelope(w, -30109, "bad creds", "null")
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		p := &OmadaProvider{}
		_, err := p.ImportSpec(context.Background(), providers.ImportOptions{
			Host: ts.URL, Username: "admin", Password: "bad", SkipTLSVerify: true,
		})
		if err == nil || !strings.Contains(err.Error(), "login failed") {
			t.Errorf("error = %v, want login failed", err)
		}
	})
}

func TestProviderCheck(t *testing.T) {
	t.Run("success with empty networks", func(t *testing.T) {
		// A site with no networks yields a spec whose only assertion is the
		// always-added 8.8.8.8 route check (local routing table, hermetic).
		ts := omadaServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/abc123/api/v2/login":
				writeEnvelope(w, 0, "", `{"token":"t1"}`)
			case "/abc123/api/v2/logout":
				writeEnvelope(w, 0, "", "null")
			case "/abc123/api/v2/sites":
				writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
			case "/abc123/api/v2/sites/s1/setting/lan/networks":
				writeEnvelope(w, 0, "", `{"totalRows":0,"data":[]}`)
			case "/abc123/api/v2/sites/s1/setting/networks":
				writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"n1","name":"IoT"}]}`)
			case "/abc123/api/v2/sites/s1/setting/firewall/acls":
				writeEnvelope(w, 0, "", `{"totalRows":0,"data":[]}`)
			case "/abc123/api/v2/sites/s1/clients":
				writeEnvelope(w, 0, "", `{"totalRows":0,"data":[]}`)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		p := &OmadaProvider{}
		res, err := p.Check(context.Background(), providers.ImportOptions{
			Host: ts.URL, Username: "admin", Password: "pw", Site: "hq", SkipTLSVerify: true,
		})
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		if res.Report == nil {
			t.Fatal("Report is nil")
		}
	})

	t.Run("import fails", func(t *testing.T) {
		p := &OmadaProvider{}
		_, err := p.Check(context.Background(), providers.ImportOptions{Host: "https://127.0.0.1:1", Username: "a", Password: "b"})
		if err == nil {
			t.Error("expected import failure to propagate")
		}
	})
}

func TestProviderCheckACL(t *testing.T) {
	// Mock controller with one enabled drop rule "lan -> iot".
	newServer := func() (*httptest.Server, *OmadaProvider) {
		ts := omadaServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/abc123/api/v2/login":
				writeEnvelope(w, 0, "", `{"token":"t1"}`)
			case "/abc123/api/v2/logout":
				writeEnvelope(w, 0, "", "null")
			case "/abc123/api/v2/sites":
				writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
			case "/abc123/api/v2/sites/s1/setting/lan/networks":
				writeEnvelope(w, 0, "", `{"totalRows":2,"data":[
					{"id":"n-lan","name":"lan","gatewaySubnet":"10.0.0.1/24"},
					{"id":"n-iot","name":"iot","gatewaySubnet":"10.0.1.1/24"}
				]}`)
			case "/abc123/api/v2/sites/s1/setting/firewall/acls":
				if r.URL.Query().Get("type") == "0" {
					writeEnvelope(w, 0, "", `{"totalRows":0,"data":[]}`)
					return
				}
				writeEnvelope(w, 0, "", `{"totalRows":2,"data":[
					{"id":"a1","name":"Deny Lan to IoT","status":true,"policy":0,"sourceType":"network","sourceIds":["n-lan"],"destinationType":"network","destinationIds":["n-iot"]},
					{"id":"a2","name":"Disabled rule","status":false,"policy":0,"sourceType":"network","sourceIds":["n-lan"],"destinationType":"network","destinationIds":["n-iot"]}
				]}`)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		return ts, &OmadaProvider{}
	}

	// The site is addressed by display name; the ACL endpoints are keyed by
	// site ID — resolution must happen inside CheckACL.
	opts := func(ts *httptest.Server) providers.ImportOptions {
		return providers.ImportOptions{Host: ts.URL, Username: "admin", Password: "pw", Site: "HQ", SkipTLSVerify: true}
	}

	t.Run("enforced and found", func(t *testing.T) {
		ts, p := newServer()
		res, err := p.CheckACL(context.Background(), providers.ACLCheckRequest{
			PolicyName: "p", From: "lan", To: "iot", Action: "deny", ExpectEnforced: true,
		}, opts(ts))
		if err != nil {
			t.Fatalf("CheckACL: %v", err)
		}
		if res.Status != "pass" {
			t.Errorf("status = %s, want pass (got summary %q)", res.Status, res.Summary)
		}
		if res.Observed["rule_count"] != 2 {
			t.Errorf("rule_count = %v, want 2", res.Observed["rule_count"])
		}
	})

	t.Run("enforced and not found", func(t *testing.T) {
		ts, p := newServer()
		res, err := p.CheckACL(context.Background(), providers.ACLCheckRequest{
			PolicyName: "p", From: "guest", To: "iot", Action: "deny", ExpectEnforced: true,
		}, opts(ts))
		if err != nil {
			t.Fatalf("CheckACL: %v", err)
		}
		if res.Status != "fail" || len(res.Violations) == 0 {
			t.Errorf("status = %s, violations = %v; want fail with violations", res.Status, res.Violations)
		}
	})

	t.Run("not enforced and not found", func(t *testing.T) {
		ts, p := newServer()
		res, err := p.CheckACL(context.Background(), providers.ACLCheckRequest{
			PolicyName: "p", From: "guest", To: "iot", Action: "deny", ExpectEnforced: false,
		}, opts(ts))
		if err != nil {
			t.Fatalf("CheckACL: %v", err)
		}
		if res.Status != "pass" {
			t.Errorf("status = %s, want pass", res.Status)
		}
	})

	t.Run("not enforced but found", func(t *testing.T) {
		ts, p := newServer()
		res, err := p.CheckACL(context.Background(), providers.ACLCheckRequest{
			PolicyName: "p", From: "lan", To: "iot", Action: "deny", ExpectEnforced: false,
		}, opts(ts))
		if err != nil {
			t.Fatalf("CheckACL: %v", err)
		}
		if res.Status != "fail" {
			t.Errorf("status = %s, want fail (enforced but expected not)", res.Status)
		}
	})

	t.Run("allow action matches accept policy", func(t *testing.T) {
		ts := omadaServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/abc123/api/v2/login":
				writeEnvelope(w, 0, "", `{"token":"t1"}`)
			case "/abc123/api/v2/logout":
				writeEnvelope(w, 0, "", "null")
			case "/abc123/api/v2/sites":
				writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
			case "/abc123/api/v2/sites/s1/setting/lan/networks":
				writeEnvelope(w, 0, "", `{"totalRows":2,"data":[
					{"id":"n-lan","name":"LAN","gatewaySubnet":"10.0.0.1/24"},
					{"id":"n-iot","name":"IoT","gatewaySubnet":"10.0.1.1/24"}
				]}`)
			case "/abc123/api/v2/sites/s1/setting/firewall/acls":
				if r.URL.Query().Get("type") == "0" {
					writeEnvelope(w, 0, "", `{"totalRows":0,"data":[]}`)
					return
				}
				writeEnvelope(w, 0, "", `{"totalRows":1,"data":[
					{"id":"a1","name":"Allow Web","status":true,"policy":1,"sourceType":"network","sourceIds":["n-lan"],"destinationType":"network","destinationIds":["n-iot"]}
				]}`)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		p := &OmadaProvider{}
		res, err := p.CheckACL(context.Background(), providers.ACLCheckRequest{
			PolicyName: "p", From: "lan", To: "iot", Action: "allow", ExpectEnforced: true,
		}, opts(ts))
		if err != nil {
			t.Fatalf("CheckACL: %v", err)
		}
		if res.Status != "pass" {
			t.Errorf("status = %s, want pass (case-insensitive match, accept==allow)", res.Status)
		}
	})

	t.Run("connect fails", func(t *testing.T) {
		p := &OmadaProvider{}
		res, err := p.CheckACL(context.Background(), providers.ACLCheckRequest{
			PolicyName: "p", From: "lan", To: "iot", Action: "deny", ExpectEnforced: true,
		}, providers.ImportOptions{Host: "https://127.0.0.1:1"})
		if err != nil {
			t.Fatalf("CheckACL: %v", err)
		}
		if res.Status != "error" {
			t.Errorf("status = %s, want error", res.Status)
		}
	})

	t.Run("login fails", func(t *testing.T) {
		ts := omadaServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/abc123/api/v2/login" {
				writeEnvelope(w, -30109, "bad", "null")
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		p := &OmadaProvider{}
		res, err := p.CheckACL(context.Background(), providers.ACLCheckRequest{
			PolicyName: "p", From: "lan", To: "iot", Action: "deny", ExpectEnforced: true,
		}, opts(ts))
		if err != nil {
			t.Fatalf("CheckACL: %v", err)
		}
		if res.Status != "error" {
			t.Errorf("status = %s, want error", res.Status)
		}
	})

	t.Run("acl fetch fails", func(t *testing.T) {
		ts := omadaServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/abc123/api/v2/login":
				writeEnvelope(w, 0, "", `{"token":"t1"}`)
			case "/abc123/api/v2/logout":
				writeEnvelope(w, 0, "", "null")
			case "/abc123/api/v2/sites":
				writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		p := &OmadaProvider{}
		res, err := p.CheckACL(context.Background(), providers.ACLCheckRequest{
			PolicyName: "p", From: "lan", To: "iot", Action: "deny", ExpectEnforced: true,
		}, opts(ts))
		if err != nil {
			t.Fatalf("CheckACL: %v", err)
		}
		if res.Status != "error" {
			t.Errorf("status = %s, want error", res.Status)
		}
	})

	t.Run("site selection fails for unknown site", func(t *testing.T) {
		ts := omadaServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/abc123/api/v2/login":
				writeEnvelope(w, 0, "", `{"token":"t1"}`)
			case "/abc123/api/v2/logout":
				writeEnvelope(w, 0, "", "null")
			case "/abc123/api/v2/sites":
				writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		p := &OmadaProvider{}
		res, err := p.CheckACL(context.Background(), providers.ACLCheckRequest{
			PolicyName: "p", From: "lan", To: "iot", Action: "deny", ExpectEnforced: true,
		}, providers.ImportOptions{Host: ts.URL, Username: "admin", Password: "pw", Site: "Branch", SkipTLSVerify: true})
		if err != nil {
			t.Fatalf("CheckACL: %v", err)
		}
		if res.Status != "error" {
			t.Errorf("status = %s, want error for unknown site", res.Status)
		}
	})

	t.Run("site fetch failure surfaces as error", func(t *testing.T) {
		ts := omadaServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/abc123/api/v2/login":
				writeEnvelope(w, 0, "", `{"token":"t1"}`)
			case "/abc123/api/v2/logout":
				writeEnvelope(w, 0, "", "null")
			case "/abc123/api/v2/sites":
				w.WriteHeader(http.StatusInternalServerError)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		p := &OmadaProvider{}
		res, err := p.CheckACL(context.Background(), providers.ACLCheckRequest{
			PolicyName: "p", From: "lan", To: "iot", Action: "deny", ExpectEnforced: true,
		}, providers.ImportOptions{Host: ts.URL, Username: "admin", Password: "pw", Site: "HQ", SkipTLSVerify: true})
		if err != nil {
			t.Fatalf("CheckACL: %v", err)
		}
		if res.Status != "error" || !strings.Contains(res.Summary, "failed to fetch sites") {
			t.Errorf("status = %s, summary = %q; want error mentioning failed site fetch", res.Status, res.Summary)
		}
	})

	t.Run("gateway ACL fetch failure downgrades negative verdicts to warn", func(t *testing.T) {
		ts := omadaServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/abc123/api/v2/login":
				writeEnvelope(w, 0, "", `{"token":"t1"}`)
			case "/abc123/api/v2/logout":
				writeEnvelope(w, 0, "", "null")
			case "/abc123/api/v2/sites":
				writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
			case "/abc123/api/v2/sites/s1/setting/lan/networks":
				writeEnvelope(w, 0, "", `{"totalRows":2,"data":[
					{"id":"n-lan","name":"lan","gatewaySubnet":"10.0.0.1/24"},
					{"id":"n-iot","name":"iot","gatewaySubnet":"10.0.1.1/24"}
				]}`)
			case "/abc123/api/v2/sites/s1/setting/firewall/acls":
				if r.URL.Query().Get("type") == "0" {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				writeEnvelope(w, 0, "", `{"totalRows":1,"data":[
					{"id":"a1","name":"Deny Lan to IoT","status":true,"policy":0,"sourceType":"network","sourceIds":["n-lan"],"destinationType":"network","destinationIds":["n-iot"]}
				]}`)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		p := &OmadaProvider{}
		// Found in switch ACLs: definitive pass even without gateway data.
		res, err := p.CheckACL(context.Background(), providers.ACLCheckRequest{
			PolicyName: "p", From: "lan", To: "iot", Action: "deny", ExpectEnforced: true,
		}, opts(ts))
		if err != nil {
			t.Fatalf("CheckACL: %v", err)
		}
		if res.Status != "pass" {
			t.Errorf("status = %s, want pass (found in switch ACLs)", res.Status)
		}
		// Not found: a gateway-scoped rule could flip this — warn, not fail.
		res, err = p.CheckACL(context.Background(), providers.ACLCheckRequest{
			PolicyName: "p", From: "guest", To: "iot", Action: "deny", ExpectEnforced: true,
		}, opts(ts))
		if err != nil {
			t.Fatalf("CheckACL: %v", err)
		}
		if res.Status != "warn" {
			t.Errorf("status = %s, want warn (gateway ACLs unverified)", res.Status)
		}
		if !strings.Contains(res.Summary, "gateway ACLs unverified") {
			t.Errorf("summary = %q, want mention of unverified gateway ACLs", res.Summary)
		}
		foundEvidence := false
		for _, e := range res.Evidence {
			if strings.Contains(e, "gateway ACL rules could not be fetched") {
				foundEvidence = true
				break
			}
		}
		if !foundEvidence {
			t.Errorf("evidence = %v, want gateway fetch error surfaced", res.Evidence)
		}
	})
}

// applyACLServer serves networks n1/n2 plus a mutable ACL rule list for
// ApplyACL tests. The rule list starts with the given JSON rules and updates
// as writes arrive; any write on an unexpected path or a write when
// writesAllowed is false fails the test.
func applyACLServer(t *testing.T, initialRules string, writesAllowed bool) *httptest.Server {
	t.Helper()
	state := initialRules
	ts := omadaServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/abc123/api/v2/login":
			writeEnvelope(w, 0, "", `{"token":"t1"}`)
		case r.URL.Path == "/abc123/api/v2/logout":
			writeEnvelope(w, 0, "", "null")
		case r.URL.Path == "/abc123/api/v2/sites":
			writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		case r.URL.Path == "/abc123/api/v2/sites/s1/setting/lan/networks":
			writeEnvelope(w, 0, "", `{"totalRows":2,"data":[
				{"id":"n1","name":"Trusted","gatewaySubnet":"10.0.10.1/24"},
				{"id":"n2","name":"IoT","gatewaySubnet":"10.0.20.1/24"}]}`)
		case r.URL.Path == "/abc123/api/v2/sites/s1/setting/firewall/acls" && r.Method == http.MethodGet:
			if r.URL.Query().Get("type") == "0" {
				writeEnvelope(w, 0, "", `{"totalRows":0,"data":[]}`)
				return
			}
			writeEnvelope(w, 0, "", state)
		case r.URL.Path == "/abc123/api/v2/sites/s1/setting/firewall/acls" && r.Method == http.MethodPost:
			if !writesAllowed {
				t.Error("unexpected POST create when writes are not allowed")
			}
			writeEnvelope(w, 0, "", `{"id":"a9","name":"block-iot","status":true,"type":1,"policy":0,"protocols":[256],"sourceType":"network","sourceIds":["n2"],"destinationType":"network","destinationIds":["n1"],"index":4}`)
			state = `{"totalRows":1,"data":[{"id":"a9","name":"block-iot","status":true,"type":1,"policy":0,"protocols":[256],"sourceType":"network","sourceIds":["n2"],"destinationType":"network","destinationIds":["n1"],"index":4}]}`
		case strings.HasPrefix(r.URL.Path, "/abc123/api/v2/sites/s1/setting/firewall/acls/") && r.Method == http.MethodPut:
			if !writesAllowed {
				t.Error("unexpected PUT update when writes are not allowed")
			}
			writeEnvelope(w, 0, "", `{"id":"a1","name":"block-iot","status":true,"type":1,"policy":0,"protocols":[256],"sourceType":"network","sourceIds":["n2"],"destinationType":"network","destinationIds":["n1"],"index":4}`)
			state = `{"totalRows":1,"data":[{"id":"a1","name":"block-iot","status":true,"type":1,"policy":0,"protocols":[256],"sourceType":"network","sourceIds":["n2"],"destinationType":"network","destinationIds":["n1"],"index":4}]}`
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	return ts
}

func applyOpts(ts *httptest.Server) providers.ImportOptions {
	return providers.ImportOptions{Host: ts.URL, Username: "admin", Password: "pw", Site: "HQ", SkipTLSVerify: true}
}

func TestProviderApplyACL(t *testing.T) {
	t.Run("creates a rule with resolved network ids", func(t *testing.T) {
		ts := applyACLServer(t, `{"totalRows":0,"data":[]}`, true)
		p := &OmadaProvider{}
		res, err := p.ApplyACL(context.Background(), providers.ACLApplyRequest{
			PolicyName: "block-iot", From: "IoT", To: "Trusted", Action: "deny",
		}, applyOpts(ts))
		if err != nil {
			t.Fatalf("ApplyACL: %v", err)
		}
		if res.DryRun || res.Outcome != "created" || res.RuleID != "a9" {
			t.Errorf("result = %+v, want real created rule a9", res)
		}
		if res.FromCIDR != "10.0.20.0/24" || res.ToCIDR != "10.0.10.0/24" {
			t.Errorf("cidrs = from %q to %q, want resolved network CIDRs", res.FromCIDR, res.ToCIDR)
		}
		if res.FromGateway != "10.0.20.1" || res.ToGateway != "10.0.10.1" {
			t.Errorf("gateways = from %q to %q, want resolved network gateways", res.FromGateway, res.ToGateway)
		}
		if res.Before == res.After {
			t.Error("before/after evidence must differ after a real create")
		}
		var before, after []omadabackend.ACLRule
		if err := json.Unmarshal([]byte(res.Before), &before); err != nil {
			t.Fatalf("before evidence %q: %v", res.Before, err)
		}
		if err := json.Unmarshal([]byte(res.After), &after); err != nil {
			t.Fatalf("after evidence %q: %v", res.After, err)
		}
		if len(before) != 0 || len(after) != 1 || after[0].ID != "a9" || after[0].Policy != omadabackend.ACLPolicyDeny {
			t.Errorf("evidence = before %d rules, after %+v; want empty before, a9 after", len(before), after)
		}
	})

	t.Run("idempotent when rule already active", func(t *testing.T) {
		ts := applyACLServer(t, `{"totalRows":1,"data":[{"id":"a1","name":"block-iot","status":true,"policy":0,"sourceType":"network","sourceIds":["n2"],"destinationType":"network","destinationIds":["n1"],"index":4}]}`, false)
		p := &OmadaProvider{}
		res, err := p.ApplyACL(context.Background(), providers.ACLApplyRequest{
			From: "IoT", To: "Trusted", Action: "deny",
		}, applyOpts(ts))
		if err != nil {
			t.Fatalf("ApplyACL: %v", err)
		}
		if res.Outcome != "unchanged" || res.RuleID != "a1" {
			t.Errorf("result = %+v, want unchanged rule a1", res)
		}
		if res.Before != res.After {
			t.Error("before/after evidence must be identical when nothing changed")
		}
	})

	t.Run("enables a matching disabled rule", func(t *testing.T) {
		ts := applyACLServer(t, `{"totalRows":1,"data":[{"id":"a1","name":"block-iot","status":false,"policy":0,"sourceType":"network","sourceIds":["n2"],"destinationType":"network","destinationIds":["n1"],"index":4}]}`, true)
		p := &OmadaProvider{}
		res, err := p.ApplyACL(context.Background(), providers.ACLApplyRequest{
			From: "IoT", To: "Trusted", Action: "deny",
		}, applyOpts(ts))
		if err != nil {
			t.Fatalf("ApplyACL: %v", err)
		}
		if res.Outcome != "enabled" || res.RuleID != "a1" {
			t.Errorf("result = %+v, want enabled rule a1", res)
		}
	})

	t.Run("rejects conflicting action", func(t *testing.T) {
		ts := applyACLServer(t, `{"totalRows":1,"data":[{"id":"a1","name":"allow-iot","status":true,"policy":1,"sourceType":"network","sourceIds":["n2"],"destinationType":"network","destinationIds":["n1"],"index":4}]}`, false)
		p := &OmadaProvider{}
		_, err := p.ApplyACL(context.Background(), providers.ACLApplyRequest{
			From: "IoT", To: "Trusted", Action: "deny",
		}, applyOpts(ts))
		if err == nil || !strings.Contains(err.Error(), "conflicting") {
			t.Fatalf("ApplyACL error = %v, want conflicting rule error", err)
		}
	})

	t.Run("dry run never mutates", func(t *testing.T) {
		ts := applyACLServer(t, `{"totalRows":0,"data":[]}`, false)
		p := &OmadaProvider{}
		res, err := p.ApplyACL(context.Background(), providers.ACLApplyRequest{
			From: "IoT", To: "Trusted", Action: "deny", DryRun: true,
		}, applyOpts(ts))
		if err != nil {
			t.Fatalf("ApplyACL: %v", err)
		}
		if !res.DryRun || res.Outcome != "created" {
			t.Errorf("result = %+v, want planned create with dry_run true", res)
		}
		if res.Before != res.After {
			t.Error("dry run must not change before/after evidence")
		}
	})

	t.Run("unknown network name lists available names", func(t *testing.T) {
		ts := applyACLServer(t, `{"totalRows":0,"data":[]}`, false)
		p := &OmadaProvider{}
		_, err := p.ApplyACL(context.Background(), providers.ACLApplyRequest{
			From: "Missing", To: "Trusted", Action: "deny",
		}, applyOpts(ts))
		if err == nil || !strings.Contains(err.Error(), "Trusted") || !strings.Contains(err.Error(), "IoT") {
			t.Fatalf("ApplyACL error = %v, want available network names listed", err)
		}
	})

	t.Run("invalid request is rejected before any controller request", func(t *testing.T) {
		p := &OmadaProvider{}
		opts := providers.ImportOptions{Host: "https://127.0.0.1:1"}
		cases := []struct {
			name string
			req  providers.ACLApplyRequest
			want string
		}{
			{"empty from", providers.ACLApplyRequest{From: "", To: "b", Action: "deny"}, "from is required"},
			{"empty to", providers.ACLApplyRequest{From: "a", To: "", Action: "deny"}, "to is required"},
			{"bad action", providers.ACLApplyRequest{From: "a", To: "b", Action: "drop"}, "action"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := p.ApplyACL(context.Background(), tc.req, opts)
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("ApplyACL error = %v, want %q", err, tc.want)
				}
			})
		}
	})

	t.Run("session failures propagate", func(t *testing.T) {
		p := &OmadaProvider{}
		_, err := p.ApplyACL(context.Background(), providers.ACLApplyRequest{
			From: "a", To: "b", Action: "deny",
		}, providers.ImportOptions{Host: "https://127.0.0.1:1", Username: "u", Password: "p"})
		if err == nil {
			t.Fatal("expected session failure to propagate")
		}
	})

	t.Run("sites fetch failure propagates", func(t *testing.T) {
		ts := omadaServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/abc123/api/v2/login":
				writeEnvelope(w, 0, "", `{"token":"t1"}`)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		p := &OmadaProvider{}
		_, err := p.ApplyACL(context.Background(), providers.ACLApplyRequest{
			From: "IoT", To: "Trusted", Action: "deny",
		}, applyOpts(ts))
		if err == nil || !strings.Contains(err.Error(), "fetching sites") {
			t.Fatalf("ApplyACL error = %v, want sites fetch failure", err)
		}
	})

	t.Run("networks fetch failure propagates", func(t *testing.T) {
		ts := omadaServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/abc123/api/v2/login":
				writeEnvelope(w, 0, "", `{"token":"t1"}`)
			case "/abc123/api/v2/sites":
				writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		p := &OmadaProvider{}
		_, err := p.ApplyACL(context.Background(), providers.ACLApplyRequest{
			From: "IoT", To: "Trusted", Action: "deny",
		}, applyOpts(ts))
		if err == nil || !strings.Contains(err.Error(), "fetching networks") {
			t.Fatalf("ApplyACL error = %v, want networks fetch failure", err)
		}
	})

	t.Run("acl fetch failure propagates", func(t *testing.T) {
		ts := omadaServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/abc123/api/v2/login":
				writeEnvelope(w, 0, "", `{"token":"t1"}`)
			case "/abc123/api/v2/sites":
				writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
			case "/abc123/api/v2/sites/s1/setting/lan/networks":
				writeEnvelope(w, 0, "", `{"totalRows":2,"data":[
					{"id":"n1","name":"Trusted","gatewaySubnet":"10.0.10.1/24"},
					{"id":"n2","name":"IoT","gatewaySubnet":"10.0.20.1/24"}]}`)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		p := &OmadaProvider{}
		_, err := p.ApplyACL(context.Background(), providers.ACLApplyRequest{
			From: "IoT", To: "Trusted", Action: "deny",
		}, applyOpts(ts))
		if err == nil || !strings.Contains(err.Error(), "fetching ACL rules") {
			t.Fatalf("ApplyACL error = %v, want ACL fetch failure", err)
		}
	})

	t.Run("create failure propagates", func(t *testing.T) {
		ts := omadaServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/abc123/api/v2/login":
				writeEnvelope(w, 0, "", `{"token":"t1"}`)
			case r.URL.Path == "/abc123/api/v2/sites":
				writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
			case r.URL.Path == "/abc123/api/v2/sites/s1/setting/lan/networks":
				writeEnvelope(w, 0, "", `{"totalRows":2,"data":[
					{"id":"n1","name":"Trusted","gatewaySubnet":"10.0.10.1/24"},
					{"id":"n2","name":"IoT","gatewaySubnet":"10.0.20.1/24"}]}`)
			case r.URL.Path == "/abc123/api/v2/sites/s1/setting/firewall/acls" && r.Method == http.MethodGet:
				writeEnvelope(w, 0, "", `{"totalRows":0,"data":[]}`)
			case r.URL.Path == "/abc123/api/v2/sites/s1/setting/firewall/acls" && r.Method == http.MethodPost:
				writeEnvelope(w, -1005, "no permission", "null")
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		p := &OmadaProvider{}
		_, err := p.ApplyACL(context.Background(), providers.ACLApplyRequest{
			From: "IoT", To: "Trusted", Action: "deny",
		}, applyOpts(ts))
		if err == nil || !strings.Contains(err.Error(), "creating ACL rule") {
			t.Fatalf("ApplyACL error = %v, want create failure", err)
		}
	})

	t.Run("enable failure propagates", func(t *testing.T) {
		ts := omadaServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/abc123/api/v2/login":
				writeEnvelope(w, 0, "", `{"token":"t1"}`)
			case r.URL.Path == "/abc123/api/v2/sites":
				writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
			case r.URL.Path == "/abc123/api/v2/sites/s1/setting/lan/networks":
				writeEnvelope(w, 0, "", `{"totalRows":2,"data":[
					{"id":"n1","name":"Trusted","gatewaySubnet":"10.0.10.1/24"},
					{"id":"n2","name":"IoT","gatewaySubnet":"10.0.20.1/24"}]}`)
			case r.URL.Path == "/abc123/api/v2/sites/s1/setting/firewall/acls" && r.Method == http.MethodGet:
				writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"a1","name":"block-iot","status":false,"policy":0,"sourceType":"network","sourceIds":["n2"],"destinationType":"network","destinationIds":["n1"],"index":4}]}`)
			case strings.HasPrefix(r.URL.Path, "/abc123/api/v2/sites/s1/setting/firewall/acls/") && r.Method == http.MethodPut:
				writeEnvelope(w, -1005, "no permission", "null")
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		p := &OmadaProvider{}
		_, err := p.ApplyACL(context.Background(), providers.ACLApplyRequest{
			From: "IoT", To: "Trusted", Action: "deny",
		}, applyOpts(ts))
		if err == nil || !strings.Contains(err.Error(), "updating ACL rule") {
			t.Fatalf("ApplyACL error = %v, want enable failure", err)
		}
	})

	t.Run("refetch failure after create propagates", func(t *testing.T) {
		var wrote bool
		ts := omadaServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/abc123/api/v2/login":
				writeEnvelope(w, 0, "", `{"token":"t1"}`)
			case r.URL.Path == "/abc123/api/v2/sites":
				writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
			case r.URL.Path == "/abc123/api/v2/sites/s1/setting/lan/networks":
				writeEnvelope(w, 0, "", `{"totalRows":2,"data":[
					{"id":"n1","name":"Trusted","gatewaySubnet":"10.0.10.1/24"},
					{"id":"n2","name":"IoT","gatewaySubnet":"10.0.20.1/24"}]}`)
			case r.URL.Path == "/abc123/api/v2/sites/s1/setting/firewall/acls" && r.Method == http.MethodGet:
				if wrote {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				writeEnvelope(w, 0, "", `{"totalRows":0,"data":[]}`)
			case r.URL.Path == "/abc123/api/v2/sites/s1/setting/firewall/acls" && r.Method == http.MethodPost:
				wrote = true
				writeEnvelope(w, 0, "", `{"id":"a9","status":true,"policy":0}`)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		p := &OmadaProvider{}
		_, err := p.ApplyACL(context.Background(), providers.ACLApplyRequest{
			From: "IoT", To: "Trusted", Action: "deny",
		}, applyOpts(ts))
		if err == nil || !strings.Contains(err.Error(), "refetching ACL rules") {
			t.Fatalf("ApplyACL error = %v, want refetch failure", err)
		}
	})

	t.Run("allow action creates an accept rule", func(t *testing.T) {
		var gotBody string
		var wrote bool
		ts := omadaServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/abc123/api/v2/login":
				writeEnvelope(w, 0, "", `{"token":"t1"}`)
			case r.URL.Path == "/abc123/api/v2/sites":
				writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
			case r.URL.Path == "/abc123/api/v2/sites/s1/setting/lan/networks":
				writeEnvelope(w, 0, "", `{"totalRows":2,"data":[
					{"id":"n1","name":"Trusted","gatewaySubnet":"10.0.10.1/24"},
					{"id":"n2","name":"IoT","gatewaySubnet":"10.0.20.1/24"}]}`)
			case r.URL.Path == "/abc123/api/v2/sites/s1/setting/firewall/acls" && r.Method == http.MethodGet:
				if r.URL.Query().Get("type") == "0" {
					writeEnvelope(w, 0, "", `{"totalRows":0,"data":[]}`)
					return
				}
				if wrote {
					writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"a8","status":true,"policy":1,"sourceType":"network","sourceIds":["n1"],"destinationType":"network","destinationIds":["n2"]}]}`)
					return
				}
				writeEnvelope(w, 0, "", `{"totalRows":0,"data":[]}`)
			case r.URL.Path == "/abc123/api/v2/sites/s1/setting/firewall/acls" && r.Method == http.MethodPost:
				wrote = true
				gotBody = readReqBody(t, r)
				writeEnvelope(w, 0, "", `{"id":"a8","status":true,"policy":1}`)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		p := &OmadaProvider{}
		res, err := p.ApplyACL(context.Background(), providers.ACLApplyRequest{
			From: "Trusted", To: "IoT", Action: "allow",
		}, applyOpts(ts))
		if err != nil {
			t.Fatalf("ApplyACL: %v", err)
		}
		if res.Outcome != "created" || res.RuleID != "a8" {
			t.Errorf("result = %+v, want created accept rule a8", res)
		}
		var body struct {
			Policy omadabackend.ACLPolicy `json:"policy"`
		}
		if err := json.Unmarshal([]byte(gotBody), &body); err != nil {
			t.Fatalf("request body %q: %v", gotBody, err)
		}
		if body.Policy != omadabackend.ACLPolicyPermit {
			t.Errorf("policy = %v, want permit (1) for allow action", body.Policy)
		}
	})

	t.Run("policy name default derives from endpoints", func(t *testing.T) {
		var gotBody string
		var wrote bool
		ts := omadaServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/abc123/api/v2/login":
				writeEnvelope(w, 0, "", `{"token":"t1"}`)
			case r.URL.Path == "/abc123/api/v2/sites":
				writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
			case r.URL.Path == "/abc123/api/v2/sites/s1/setting/lan/networks":
				writeEnvelope(w, 0, "", `{"totalRows":2,"data":[
					{"id":"n1","name":"Trusted","gatewaySubnet":"10.0.10.1/24"},
					{"id":"n2","name":"IoT","gatewaySubnet":"10.0.20.1/24"}]}`)
			case r.URL.Path == "/abc123/api/v2/sites/s1/setting/firewall/acls" && r.Method == http.MethodGet:
				if r.URL.Query().Get("type") == "0" {
					writeEnvelope(w, 0, "", `{"totalRows":0,"data":[]}`)
					return
				}
				if wrote {
					writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"a9","status":true,"policy":0,"sourceType":"network","sourceIds":["n2"],"destinationType":"network","destinationIds":["n1"]}]}`)
					return
				}
				writeEnvelope(w, 0, "", `{"totalRows":0,"data":[]}`)
			case r.URL.Path == "/abc123/api/v2/sites/s1/setting/firewall/acls" && r.Method == http.MethodPost:
				wrote = true
				gotBody = readReqBody(t, r)
				writeEnvelope(w, 0, "", `{"id":"a9","status":true,"policy":0}`)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		p := &OmadaProvider{}
		res, err := p.ApplyACL(context.Background(), providers.ACLApplyRequest{
			From: "IoT", To: "Trusted", Action: "deny",
		}, applyOpts(ts))
		if err != nil {
			t.Fatalf("ApplyACL: %v", err)
		}
		var body struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal([]byte(gotBody), &body); err != nil {
			t.Fatalf("request body %q: %v", gotBody, err)
		}
		if body.Name != "iot-trusted-deny" {
			t.Errorf("derived rule name = %q, want iot-trusted-deny", body.Name)
		}
		if res.RuleID != "a9" {
			t.Errorf("rule_id = %q, want a9 from refetch", res.RuleID)
		}
	})
}

func TestProviderImplementsACLApplier(t *testing.T) {
	var _ providers.ACLApplier = (*OmadaProvider)(nil)
}
