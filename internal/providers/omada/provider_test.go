package omadaprovider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
			case "/abc123/api/v2/sites/s1/setting/firewall/acl":
				writeEnvelope(w, 0, "", `{"totalRows":1,"data":[
					{"id":"a1","name":"Deny IoT","status":true,"policy":"drop"}
				]}`)
			case "/abc123/api/v2/sites/s1/setting/firewall/gwacl":
				writeEnvelope(w, 0, "", `{"totalRows":0,"data":[]}`)
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
			case "/abc123/api/v2/sites/s1/setting/firewall/acl":
				writeEnvelope(w, 0, "", `{"totalRows":0,"data":[]}`)
			case "/abc123/api/v2/sites/s1/setting/firewall/gwacl":
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
			case "/abc123/api/v2/sites/s1/setting/firewall/acl":
				writeEnvelope(w, 0, "", `{"totalRows":1,"data":[
					{"id":"a1","name":"Deny Lan to IoT","status":true,"policy":"drop","srcName":"lan","dstName":"iot"},
					{"id":"a2","name":"Disabled rule","status":false,"policy":"drop","srcName":"lan","dstName":"iot"}
				]}`)
			case "/abc123/api/v2/sites/s1/setting/firewall/gwacl":
				writeEnvelope(w, 0, "", `{"totalRows":0,"data":[]}`)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		return ts, &OmadaProvider{}
	}

	opts := func(ts *httptest.Server) providers.ImportOptions {
		return providers.ImportOptions{Host: ts.URL, Username: "admin", Password: "pw", Site: "s1", SkipTLSVerify: true}
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
			case "/abc123/api/v2/sites/s1/setting/firewall/acl":
				writeEnvelope(w, 0, "", `{"totalRows":1,"data":[
					{"id":"a1","name":"Allow Web","status":true,"policy":"accept","srcName":"LAN","dstName":"IoT"}
				]}`)
			case "/abc123/api/v2/sites/s1/setting/firewall/gwacl":
				writeEnvelope(w, 0, "", `{"totalRows":0,"data":[]}`)
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
}
