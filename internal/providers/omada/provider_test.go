package omadaprovider

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	omadabackend "github.com/jpvelasco/nyx/internal/backends/omada"
	providers "github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/testutil"
)

const infoJSON = `{"errorCode":0,"msg":"","result":{"controllerVer":"6.4.5.1","apiVer":"2.0","omadacId":"abc123","configured":true,"omadacCategory":"advanced"}}`

// threeNetworksJSON is the canned LAN network list for ApplyACL tests:
// n1 Trusted, n2 IoT, n3 Guest.
const threeNetworksJSON = `{"totalRows":3,"data":[{"id":"n1","name":"Trusted","gatewaySubnet":"10.0.10.1/24"},{"id":"n2","name":"IoT","gatewaySubnet":"10.0.20.1/24"},{"id":"n3","name":"Guest","gatewaySubnet":"10.0.30.1/24"}]}`

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

func writeEnvelope(w io.Writer, errorCode int, msg, result string) {
	testutil.WriteBody(w, `{"errorCode":`+strconv.Itoa(errorCode)+`,"msg":"`+msg+`","result":`+result+`}`)
}

func readReqBody(t *testing.T, r *http.Request) string {
	t.Helper()
	data, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("reading request body: %v", err)
	}
	return string(data)
}

// omadaServer serves a canned Omada 6.x API for provider-level tests.
func omadaServer(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/info" {
			testutil.WriteBody(w, infoJSON)
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
	if len(caps) != 4 || caps[0] != "info" || caps[1] != "import" || caps[2] != "check" || caps[3] != "inventory" {
		t.Errorf("Capabilities() = %v, want [info import check inventory]", caps)
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
			case "/openapi/authorize/token":
				writeEnvelope(w, 0, "", `{"accessToken":"t1"}`)
			case "/openapi/v1/abc123/sites":
				writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
			case "/openapi/v1/abc123/sites/s1/lan-networks":
				// Open API shape: nested dhcpSettingsVO, no origName.
				writeEnvelope(w, 0, "", `{"totalRows":1,"data":[
					{"id":"n1","name":"Trusted","vlan":10,"purpose":"interface","gatewaySubnet":"10.0.0.1/24","deviceMac":"aa:bb:cc:dd:ee:00","dhcpSettingsVO":{"enable":true}}
				]}`)
			case "/openapi/v1/abc123/sites/s1/acls/osw-acls":
				writeEnvelope(w, 0, "", `{"totalRows":1,"data":[
					{"id":"a1","description":"Deny IoT","status":true,"policy":0}
				]}`)
			case "/openapi/v1/abc123/sites/s1/acls/osg-acls":
				writeEnvelope(w, 0, "", `{"totalRows":0,"data":[]}`)
			case "/openapi/v1/abc123/sites/s1/networks/client":
				// Thin client rows (mac/name/type); the DHCP user list joins
				// back the IP and network name.
				writeEnvelope(w, 0, "", `{"totalRows":1,"data":[
					{"mac":"aa","name":"trusted-pc","type":"wired"}
				]}`)
			case "/openapi/v1/abc123/sites/s1/setting/service/dhcp/user-list":
				writeEnvelope(w, 0, "", `{"totalRows":1,"data":[
					{"ipAddress":"10.0.0.10","macAddress":"aa","name":"trusted-pc","netId":"n1","netName":"Trusted"}
				]}`)
			case "/openapi/v1/abc123/sites/s1/networks/devices":
				writeEnvelope(w, 0, "", `{"totalRows":0,"data":[]}`)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		p := &OmadaProvider{}
		res, err := p.ImportSpec(context.Background(), providers.ImportOptions{
			Host: ts.URL, ClientID: "admin", ClientSecret: "pw", Site: "hq", SkipTLSVerify: true,
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
			case "/openapi/authorize/token":
				writeEnvelope(w, -44106, "bad creds", "null")
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		p := &OmadaProvider{}
		_, err := p.ImportSpec(context.Background(), providers.ImportOptions{
			Host: ts.URL, ClientID: "admin", ClientSecret: "bad", SkipTLSVerify: true,
		})
		if err == nil || !strings.Contains(err.Error(), "token mint failed") {
			t.Errorf("error = %v, want token mint failed", err)
		}
	})
}

func TestProviderCheck(t *testing.T) {
	t.Run("success with empty networks", func(t *testing.T) {
		// A site with no networks yields a spec whose only assertion is the
		// always-added 8.8.8.8 route check (local routing table, hermetic).
		ts := omadaServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/openapi/authorize/token":
				writeEnvelope(w, 0, "", `{"accessToken":"t1"}`)
			case "/openapi/v1/abc123/sites":
				writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
			case "/openapi/v1/abc123/sites/s1/lan-networks":
				writeEnvelope(w, 0, "", `{"totalRows":0,"data":[]}`)
			case "/openapi/v1/abc123/sites/s1/acls/osg-acls", "/openapi/v1/abc123/sites/s1/acls/osw-acls":
				writeEnvelope(w, 0, "", `{"totalRows":0,"data":[]}`)
			case "/openapi/v1/abc123/sites/s1/networks/client":
				writeEnvelope(w, 0, "", `{"totalRows":0,"data":[]}`)
			case "/openapi/v1/abc123/sites/s1/setting/service/dhcp/user-list":
				writeEnvelope(w, 0, "", `{"totalRows":0,"data":[]}`)
			case "/openapi/v1/abc123/sites/s1/networks/devices":
				writeEnvelope(w, 0, "", `{"totalRows":0,"data":[]}`)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		p := &OmadaProvider{}
		res, err := p.Check(context.Background(), providers.ImportOptions{
			Host: ts.URL, ClientID: "admin", ClientSecret: "pw", Site: "hq", SkipTLSVerify: true,
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
		_, err := p.Check(context.Background(), providers.ImportOptions{Host: "https://127.0.0.1:1", ClientID: "a", ClientSecret: "b"})
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
			case "/openapi/authorize/token":
				writeEnvelope(w, 0, "", `{"accessToken":"t1"}`)
			case "/openapi/v1/abc123/sites":
				writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
			case "/openapi/v1/abc123/sites/s1/lan-networks":
				writeEnvelope(w, 0, "", `{"totalRows":2,"data":[
					{"id":"n-lan","name":"lan","gatewaySubnet":"10.0.0.1/24"},
					{"id":"n-iot","name":"iot","gatewaySubnet":"10.0.1.1/24"}
				]}`)
			case "/openapi/v1/abc123/sites/s1/acls/osg-acls":
				writeEnvelope(w, 0, "", `{"totalRows":0,"data":[]}`)
			case "/openapi/v1/abc123/sites/s1/acls/osw-acls":
				writeEnvelope(w, 0, "", `{"totalRows":2,"data":[
					{"id":"a1","description":"Deny Lan to IoT","status":true,"policy":0,"sourceType":"network","sourceIds":["n-lan"],"destinationType":"network","destinationIds":["n-iot"]},
					{"id":"a2","description":"Disabled rule","status":false,"policy":0,"sourceType":"network","sourceIds":["n-lan"],"destinationType":"network","destinationIds":["n-iot"]}
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
		return providers.ImportOptions{Host: ts.URL, ClientID: "admin", ClientSecret: "pw", Site: "HQ", SkipTLSVerify: true}
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
			case "/openapi/authorize/token":
				writeEnvelope(w, 0, "", `{"accessToken":"t1"}`)
			case "/openapi/v1/abc123/sites":
				writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
			case "/openapi/v1/abc123/sites/s1/lan-networks":
				writeEnvelope(w, 0, "", `{"totalRows":2,"data":[
					{"id":"n-lan","name":"LAN","gatewaySubnet":"10.0.0.1/24"},
					{"id":"n-iot","name":"IoT","gatewaySubnet":"10.0.1.1/24"}
				]}`)
			case "/openapi/v1/abc123/sites/s1/acls/osg-acls":
				writeEnvelope(w, 0, "", `{"totalRows":0,"data":[]}`)
			case "/openapi/v1/abc123/sites/s1/acls/osw-acls":
				writeEnvelope(w, 0, "", `{"totalRows":1,"data":[
					{"id":"a1","description":"Allow Web","status":true,"policy":1,"sourceType":"network","sourceIds":["n-lan"],"destinationType":"network","destinationIds":["n-iot"]}
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
			if r.URL.Path == "/openapi/authorize/token" {
				writeEnvelope(w, -44106, "bad", "null")
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
			case "/openapi/authorize/token":
				writeEnvelope(w, 0, "", `{"accessToken":"t1"}`)
			case "/openapi/v1/abc123/sites":
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
			case "/openapi/authorize/token":
				writeEnvelope(w, 0, "", `{"accessToken":"t1"}`)
			case "/openapi/v1/abc123/sites":
				writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		p := &OmadaProvider{}
		res, err := p.CheckACL(context.Background(), providers.ACLCheckRequest{
			PolicyName: "p", From: "lan", To: "iot", Action: "deny", ExpectEnforced: true,
		}, providers.ImportOptions{Host: ts.URL, ClientID: "admin", ClientSecret: "pw", Site: "Branch", SkipTLSVerify: true})
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
			case "/openapi/authorize/token":
				writeEnvelope(w, 0, "", `{"accessToken":"t1"}`)
			case "/openapi/v1/abc123/sites":
				w.WriteHeader(http.StatusInternalServerError)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		p := &OmadaProvider{}
		res, err := p.CheckACL(context.Background(), providers.ACLCheckRequest{
			PolicyName: "p", From: "lan", To: "iot", Action: "deny", ExpectEnforced: true,
		}, providers.ImportOptions{Host: ts.URL, ClientID: "admin", ClientSecret: "pw", Site: "HQ", SkipTLSVerify: true})
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
			case "/openapi/authorize/token":
				writeEnvelope(w, 0, "", `{"accessToken":"t1"}`)
			case "/openapi/v1/abc123/sites":
				writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
			case "/openapi/v1/abc123/sites/s1/lan-networks":
				writeEnvelope(w, 0, "", `{"totalRows":2,"data":[
					{"id":"n-lan","name":"lan","gatewaySubnet":"10.0.0.1/24"},
					{"id":"n-iot","name":"iot","gatewaySubnet":"10.0.1.1/24"}
				]}`)
			case "/openapi/v1/abc123/sites/s1/acls/osg-acls":
				w.WriteHeader(http.StatusNotFound)
				return
			case "/openapi/v1/abc123/sites/s1/acls/osw-acls":
				writeEnvelope(w, 0, "", `{"totalRows":1,"data":[
					{"id":"a1","description":"Deny Lan to IoT","status":true,"policy":0,"sourceType":"network","sourceIds":["n-lan"],"destinationType":"network","destinationIds":["n-iot"]}
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

func TestProviderCheckACL_PerScopePaths(t *testing.T) {
	// The Open API read paths carry no scope capability flags (no
	// aclDisable): a stored gateway rule is a match in its own scope and
	// passes as enforced; a not-enforced expectation still fails when the
	// rule is present.
	ts := omadaServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			writeEnvelope(w, 0, "", `{"accessToken":"t1"}`)
		case "/openapi/v1/abc123/sites":
			writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		case "/openapi/v1/abc123/sites/s1/lan-networks":
			writeEnvelope(w, 0, "", `{"totalRows":2,"data":[
				{"id":"n1","name":"Trusted","gatewaySubnet":"10.0.0.1/24"},
				{"id":"n2","name":"IoT","gatewaySubnet":"10.0.1.1/24"}
			]}`)
		case "/openapi/v1/abc123/sites/s1/acls/osg-acls":
			writeEnvelope(w, 0, "", `{"totalRows":1,"data":[
				{"id":"g1","description":"Trusted Deny","status":true,"policy":0,"sourceType":"network","sourceIds":["n1"],"destinationType":"network","destinationIds":["n2"]}
			]}`)
		case "/openapi/v1/abc123/sites/s1/acls/osw-acls":
			writeEnvelope(w, 0, "", `{"totalRows":1,"data":[
				{"id":"s1r","description":"IoT Deny","status":true,"policy":0,"sourceType":"network","sourceIds":["n2"],"destinationType":"network","destinationIds":["n1"]}
			]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	p := &OmadaProvider{}
	opts := providers.ImportOptions{Host: ts.URL, ClientID: "admin", ClientSecret: "pw", Site: "HQ", SkipTLSVerify: true}

	t.Run("gateway rule passes as enforced", func(t *testing.T) {
		res, err := p.CheckACL(context.Background(), providers.ACLCheckRequest{
			PolicyName: "trusted-deny", From: "trusted", To: "iot", Action: "deny", ExpectEnforced: true,
		}, opts)
		if err != nil {
			t.Fatalf("CheckACL: %v", err)
		}
		if res.Status != "pass" {
			t.Errorf("status = %s (summary %q), want pass", res.Status, res.Summary)
		}
		if res.Observed["scope"] != "gateway" {
			t.Errorf("observed = %v, want scope gateway", res.Observed)
		}
		if res.Observed["rule_count"] != 2 {
			t.Errorf("rule_count = %v, want 2 (both scopes)", res.Observed["rule_count"])
		}
	})

	t.Run("switch rule passes as enforced", func(t *testing.T) {
		res, err := p.CheckACL(context.Background(), providers.ACLCheckRequest{
			PolicyName: "iot-deny", From: "iot", To: "trusted", Action: "deny", ExpectEnforced: true,
		}, opts)
		if err != nil {
			t.Fatalf("CheckACL: %v", err)
		}
		if res.Status != "pass" {
			t.Errorf("status = %s (summary %q), want pass", res.Status, res.Summary)
		}
		if res.Observed["scope"] != "switch" {
			t.Errorf("observed = %v, want scope switch", res.Observed)
		}
	})

	t.Run("not-enforced expectation fails when the rule is present", func(t *testing.T) {
		res, err := p.CheckACL(context.Background(), providers.ACLCheckRequest{
			PolicyName: "missing", From: "trusted", To: "iot", Action: "deny", ExpectEnforced: false,
		}, opts)
		if err != nil {
			t.Fatalf("CheckACL: %v", err)
		}
		// "trusted→iot deny" matches the gateway rule: the policy IS
		// present, so a not-enforced expectation fails.
		if res.Status != "fail" {
			t.Errorf("status = %s, want fail (rule present but not expected)", res.Status)
		}
	})
}

func TestProviderInventory(t *testing.T) {
	ts := omadaServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			writeEnvelope(w, 0, "", `{"accessToken":"t1"}`)
		case "/openapi/v1/abc123/sites":
			writeEnvelope(w, 0, "", `{"totalRows":2,"data":[{"id":"s1","name":"HQ"},{"id":"s2","name":"Branch"}]}`)
		case "/openapi/v1/abc123/sites/s1/lan-networks":
			// Open API shape: nested dhcpSettingsVO, no origName.
			writeEnvelope(w, 0, "", `{"totalRows":2,"data":[
				{"id":"n1","name":"Trusted","vlan":10,"purpose":"interface","gatewaySubnet":"10.0.0.1/24","deviceMac":"aa:bb:cc:dd:ee:00","dhcpSettingsVO":{"enable":true}},
				{"id":"n2","name":"IoT","vlan":20,"purpose":"interface","gatewaySubnet":"10.0.1.1/24","deviceMac":"aa:bb:cc:dd:ee:00","dhcpSettingsVO":{"enable":false}}
			]}`)
		case "/openapi/v1/abc123/sites/s1/networks/devices":
			writeEnvelope(w, 0, "", `{"totalRows":2,"data":[
				{"id":"d1","name":"GW-CORE","model":"GW-CORE","type":"gateway","mac":"aa:bb:cc:dd:ee:00","ip":"10.0.0.254","firmwareVersion":"2.2.3","needUpgrade":true},
				{"id":"d2","name":"SW-2428P","model":"SW-2428P","type":"switch","mac":"aa:bb:cc:dd:ee:01","ip":"10.0.0.253"}
			]}`)
		case "/openapi/v1/abc123/sites/s1/acls/osg-acls":
			writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"g1","description":"Trusted Deny","status":true,"policy":0}]}`)
		case "/openapi/v1/abc123/sites/s1/acls/osw-acls":
			writeEnvelope(w, 0, "", `{"totalRows":0,"data":[]}`)
		case "/openapi/v1/abc123/sites/s1/networks/client":
			// Thin client rows; the DHCP user list joins back IP + network.
			writeEnvelope(w, 0, "", `{"totalRows":2,"data":[
				{"mac":"aa","name":"trusted-pc","type":"wired"},
				{"mac":"bb","name":"iot-pc","type":"wired"}
			]}`)
		case "/openapi/v1/abc123/sites/s1/setting/service/dhcp/user-list":
			writeEnvelope(w, 0, "", `{"totalRows":2,"data":[
				{"ipAddress":"10.0.0.50","macAddress":"aa","name":"trusted-pc","netId":"n1","netName":"Trusted"},
				{"ipAddress":"10.0.1.51","macAddress":"bb","name":"iot-pc","netId":"n2","netName":"IoT"}
			]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	p := &OmadaProvider{}
	res, err := p.Inventory(context.Background(), providers.ImportOptions{
		Host: ts.URL, ClientID: "admin", ClientSecret: "pw", Site: "hq", SkipTLSVerify: true,
	})
	if err != nil {
		t.Fatalf("Inventory: %v", err)
	}
	if res.Site != "HQ" || res.ClientCount != 2 {
		t.Errorf("site/count = %q/%d, want HQ/2", res.Site, res.ClientCount)
	}
	if res.Inventory.ControllerCategory != "advanced" {
		t.Errorf("controller_category = %q, want advanced", res.Inventory.ControllerCategory)
	}
	if len(res.Inventory.Devices) != 2 || res.Inventory.Devices[0].Name != "GW-CORE" {
		t.Errorf("devices = %+v, want gateway first (sorted)", res.Inventory.Devices)
	}
	if res.Inventory.Devices[0].Type != "gateway" || !res.Inventory.Devices[0].Upgrade {
		t.Errorf("gateway device = %+v, want type gateway + upgrade flag", res.Inventory.Devices[0])
	}
	if len(res.Inventory.Devices[0].Networks) != 2 {
		t.Errorf("gateway networks = %v, want both LANs bound via deviceMac", res.Inventory.Devices[0].Networks)
	}
	if res.Inventory.NetworkGateways["trusted"] != "GW-CORE" || res.Inventory.NetworkGateways["iot"] != "GW-CORE" {
		t.Errorf("NetworkGateways = %v", res.Inventory.NetworkGateways)
	}
	if len(res.Inventory.ACLScopes) != 2 {
		t.Fatalf("ACLScopes = %+v, want 2", res.Inventory.ACLScopes)
	}
	gw, sw := res.Inventory.ACLScopes[0], res.Inventory.ACLScopes[1]
	if gw.Scope != "gateway" || gw.RuleCount != 1 {
		t.Errorf("gateway scope = %+v, want 1 rule", gw)
	}
	if sw.Scope != "switch" || sw.RuleCount != 0 {
		t.Errorf("switch scope = %+v, want 0 rules", sw)
	}
	for _, want := range []string{"Site: HQ", "== Devices (2) ==", "== Networks (2) ==", "2 active clients", "gateway: 1 rule", "switch:  0 rules"} {
		if !strings.Contains(res.Human, want) {
			t.Errorf("human output missing %q:\n%s", want, res.Human)
		}
	}
	if len(res.Warnings) != 0 {
		t.Errorf("warnings = %v, want none", res.Warnings)
	}

	t.Run("token mint failure propagates", func(t *testing.T) {
		bad := omadaServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/openapi/authorize/token" {
				writeEnvelope(w, -44106, "bad creds", "null")
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		_, err := p.Inventory(context.Background(), providers.ImportOptions{Host: bad.URL, ClientID: "admin", ClientSecret: "bad", SkipTLSVerify: true})
		if err == nil || !strings.Contains(err.Error(), "token mint failed") {
			t.Errorf("error = %v, want token mint failed", err)
		}
	})

	t.Run("site selection error propagates", func(t *testing.T) {
		_, err := p.Inventory(context.Background(), providers.ImportOptions{Host: ts.URL, ClientID: "admin", ClientSecret: "pw", Site: "nope", SkipTLSVerify: true})
		if err == nil || !strings.Contains(err.Error(), "not found") {
			t.Errorf("error = %v, want site not found", err)
		}
	})
}

func TestNetworkList_Positional(t *testing.T) {
	nets := []omadabackend.Network{
		{Name: "lan", GatewaySubnet: "10.0.0.1/24"},
		{Name: "bare"},
		{Name: "iot", GatewaySubnet: "10.0.1.1/24"},
	}
	if got := networkList(nets, func(n omadabackend.Network) string { return n.CIDR() }); len(got) != 3 || got[0] != "10.0.0.0/24" || got[1] != "" || got[2] != "10.0.1.0/24" {
		t.Errorf("cidrs = %v, want positional with empty slot", got)
	}
	if got := networkList(nets, func(n omadabackend.Network) string { return n.Gateway() }); len(got) != 3 || got[1] != "" || got[2] != "10.0.1.1" {
		t.Errorf("gateways = %v, want positional with empty slot", got)
	}
}

// applyACLServer serves networks n1/n2/n3 plus mutable, per-scope ACL rule
// lists for ApplyACL tests. Reads and writes both use the per-scope Open
// API paths (BDD §4); creates return no payload, so the post-create
// refetch serves the updated scope list. The switch and gateway lists start
// with the given JSON rules and update as writes arrive; any write on an
// unexpected path or a write when writesAllowed is false fails the test.
func applyACLServer(t *testing.T, initialSwitch, initialGateway string, writesAllowed bool) *httptest.Server {
	t.Helper()
	switchState := initialSwitch
	gatewayState := initialGateway
	switchAfterCreate := `{"totalRows":1,"data":[{"id":"a9","description":"block-iot","status":true,"policy":0,"protocols":[256],"sourceType":"network","sourceIds":["n2"],"destinationType":"network","destinationIds":["n1"],"index":4}]}`
	switchAfterUpdate := `{"totalRows":1,"data":[{"id":"a1","description":"block-iot","status":true,"policy":0,"protocols":[256],"sourceType":"network","sourceIds":["n2"],"destinationType":"network","destinationIds":["n1"],"index":4}]}`
	gatewayAfterCreate := `{"totalRows":1,"data":[{"id":"a7","description":"block-iot","status":true,"policy":0,"protocols":[256],"sourceType":"network","sourceIds":["n2"],"destinationType":"network","destinationIds":["n1","n3"],"index":4}]}`
	ts := omadaServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/openapi/authorize/token":
			writeEnvelope(w, 0, "", `{"accessToken":"t1"}`)
		case r.URL.Path == "/openapi/v1/abc123/sites":
			writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		case r.URL.Path == "/openapi/v1/abc123/sites/s1/lan-networks":
			writeEnvelope(w, 0, "", threeNetworksJSON)
		case r.URL.Path == "/openapi/v1/abc123/sites/s1/acls/osw-acls" && r.Method == http.MethodPost:
			if !writesAllowed {
				t.Error("unexpected POST create when writes are not allowed")
			}
			writeEnvelope(w, 0, "", "null")
			switchState = switchAfterCreate
		case strings.HasPrefix(r.URL.Path, "/openapi/v1/abc123/sites/s1/acls/osw-acls/") && r.Method == http.MethodPut:
			if !writesAllowed {
				t.Error("unexpected PUT update when writes are not allowed")
			}
			writeEnvelope(w, 0, "", "null")
			switchState = switchAfterUpdate
		case r.URL.Path == "/openapi/v1/abc123/sites/s1/acls/osw-acls":
			writeEnvelope(w, 0, "", switchState)
		case r.URL.Path == "/openapi/v1/abc123/sites/s1/acls/osg-acls" && r.Method == http.MethodPost:
			if !writesAllowed {
				t.Error("unexpected POST create when writes are not allowed")
			}
			writeEnvelope(w, 0, "", "null")
			gatewayState = gatewayAfterCreate
		case r.URL.Path == "/openapi/v1/abc123/sites/s1/acls/osg-acls":
			writeEnvelope(w, 0, "", gatewayState)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	return ts
}

func applyOpts(ts *httptest.Server) providers.ImportOptions {
	return providers.ImportOptions{Host: ts.URL, ClientID: "admin", ClientSecret: "pw", Site: "HQ", SkipTLSVerify: true}
}

func aclApplyReq(policyName, action string, from, to []string) providers.ACLApplyRequest {
	return providers.ACLApplyRequest{PolicyName: policyName, From: from, To: to, Action: action}
}

func TestProviderApplyACL(t *testing.T) {
	const emptyList = `{"totalRows":0,"data":[]}`
	t.Run("creates a rule with resolved network ids", func(t *testing.T) {
		ts := applyACLServer(t, emptyList, emptyList, true)
		p := &OmadaProvider{}
		res, err := p.ApplyACL(context.Background(), aclApplyReq("block-iot", "deny", []string{"IoT"}, []string{"Trusted"}), applyOpts(ts))
		if err != nil {
			t.Fatalf("ApplyACL: %v", err)
		}
		if res.DryRun || res.Outcome != "created" || res.RuleID != "a9" {
			t.Errorf("result = %+v, want real created rule a9", res)
		}
		if res.Scope != "switch" || res.RuleName != "block-iot" {
			t.Errorf("scope/rule_name = %q %q, want switch block-iot", res.Scope, res.RuleName)
		}
		if len(res.FromCIDRs) != 1 || res.FromCIDRs[0] != "10.0.20.0/24" || len(res.ToCIDRs) != 1 || res.ToCIDRs[0] != "10.0.10.0/24" {
			t.Errorf("cidrs = from %v to %v, want resolved network CIDRs", res.FromCIDRs, res.ToCIDRs)
		}
		if len(res.FromGateways) != 1 || res.FromGateways[0] != "10.0.20.1" || len(res.ToGateways) != 1 || res.ToGateways[0] != "10.0.10.1" {
			t.Errorf("gateways = from %v to %v, want resolved network gateways", res.FromGateways, res.ToGateways)
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

	t.Run("creates a gateway scope rule with direction", func(t *testing.T) {
		var gotBody string
		var wrote bool
		ts := omadaServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/openapi/authorize/token":
				writeEnvelope(w, 0, "", `{"accessToken":"t1"}`)
			case r.URL.Path == "/openapi/v1/abc123/sites":
				writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
			case r.URL.Path == "/openapi/v1/abc123/sites/s1/lan-networks":
				writeEnvelope(w, 0, "", threeNetworksJSON)
			case r.URL.Path == "/openapi/v1/abc123/sites/s1/acls/osg-acls" && r.Method == http.MethodPost:
				wrote = true
				gotBody = readReqBody(t, r)
				writeEnvelope(w, 0, "", "null")
			case r.URL.Path == "/openapi/v1/abc123/sites/s1/acls/osw-acls":
				writeEnvelope(w, 0, "", emptyList)
			case r.URL.Path == "/openapi/v1/abc123/sites/s1/acls/osg-acls":
				if wrote {
					writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"a7","status":true,"policy":0,"protocols":[256],"sourceType":"network","sourceIds":["n2"],"destinationType":"network","destinationIds":["n1","n3"]}]}`)
					return
				}
				writeEnvelope(w, 0, "", emptyList)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		p := &OmadaProvider{}
		res, err := p.ApplyACL(context.Background(), providers.ACLApplyRequest{
			From: []string{"IoT"}, To: []string{"Trusted", "Guest"}, Action: "deny", Scope: "gateway",
		}, applyOpts(ts))
		if err != nil {
			t.Fatalf("ApplyACL: %v", err)
		}
		if res.Scope != "gateway" || res.RuleID != "a7" {
			t.Errorf("scope = %q rule_id = %q, want gateway a7", res.Scope, res.RuleID)
		}
		var body struct {
			SourceIDs   []string                  `json:"sourceIds"`
			DestIDs     []string                  `json:"destinationIds"`
			Protocols   []int                     `json:"protocols"`
			Direction   omadabackend.ACLDirection `json:"direction"`
			BindingType *int                      `json:"bindingType"`
			Syslog      bool                      `json:"syslog"`
			StateMode   int                       `json:"stateMode"`
			States      map[string]bool           `json:"states"`
		}
		if err := json.Unmarshal([]byte(gotBody), &body); err != nil {
			t.Fatalf("request body %q: %v", gotBody, err)
		}
		if body.BindingType != nil {
			t.Errorf("gateway wire body bindingType = %v, want omitted", *body.BindingType)
		}
		if !body.Syslog || body.StateMode != 0 || len(body.States) != 4 {
			t.Errorf("wire state tracking = syslog %v stateMode %d states %v, want syslog/stateMode/4 states", body.Syslog, body.StateMode, body.States)
		}
		if !body.Direction.LANToLAN || body.Direction.LANToWAN {
			t.Errorf("wire direction = %+v, want lanToLan only", body.Direction)
		}
		if len(body.SourceIDs) != 1 || body.SourceIDs[0] != "n2" || len(body.DestIDs) != 2 {
			t.Errorf("wire endpoints = %v -> %v, want n2 -> n1,n3", body.SourceIDs, body.DestIDs)
		}
		if !omadabackend.ProtocolsEqual(body.Protocols, []int{omadabackend.ProtocolAll}) {
			t.Errorf("wire protocols = %v, want [256]", body.Protocols)
		}
	})

	t.Run("idempotent when rule already active", func(t *testing.T) {
		ts := applyACLServer(t, `{"totalRows":1,"data":[{"id":"a1","description":"block-iot","status":true,"policy":0,"sourceType":"network","sourceIds":["n2"],"destinationType":"network","destinationIds":["n1"],"index":4}]}`, emptyList, false)
		p := &OmadaProvider{}
		res, err := p.ApplyACL(context.Background(), aclApplyReq("", "deny", []string{"IoT"}, []string{"Trusted"}), applyOpts(ts))
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

	t.Run("multi-dest cover of a singleton request is unchanged", func(t *testing.T) {
		// A same-action status-on rule covering more destinations than the
		// request satisfies the request: no write, outcome unchanged.
		ts := applyACLServer(t, `{"totalRows":1,"data":[{"id":"a1","description":"block-iot","status":true,"policy":0,"protocols":[256],"sourceType":"network","sourceIds":["n2"],"destinationType":"network","destinationIds":["n1","n3"],"index":4}]}`, emptyList, false)
		p := &OmadaProvider{}
		res, err := p.ApplyACL(context.Background(), aclApplyReq("", "deny", []string{"IoT"}, []string{"Trusted"}), applyOpts(ts))
		if err != nil {
			t.Fatalf("ApplyACL: %v", err)
		}
		if res.Outcome != "unchanged" || res.RuleID != "a1" {
			t.Errorf("result = %+v, want unchanged covering rule a1", res)
		}
		if res.Before != res.After {
			t.Error("covered request must not mutate")
		}
	})

	t.Run("narrower protocol request against an all-protocols rule creates", func(t *testing.T) {
		// The existing rule is broader (all protocols), so it does not cover
		// the narrower request: a new rule is created instead of fighting it.
		var gotBody string
		var wrote bool
		ts := omadaServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/openapi/authorize/token":
				writeEnvelope(w, 0, "", `{"accessToken":"t1"}`)
			case r.URL.Path == "/openapi/v1/abc123/sites":
				writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
			case r.URL.Path == "/openapi/v1/abc123/sites/s1/lan-networks":
				writeEnvelope(w, 0, "", threeNetworksJSON)
			case r.URL.Path == "/openapi/v1/abc123/sites/s1/acls/osg-acls":
				writeEnvelope(w, 0, "", emptyList)
			case r.URL.Path == "/openapi/v1/abc123/sites/s1/acls/osw-acls" && r.Method == http.MethodPost:
				wrote = true
				gotBody = readReqBody(t, r)
				writeEnvelope(w, 0, "", "null")
			case r.URL.Path == "/openapi/v1/abc123/sites/s1/acls/osw-acls":
				if wrote {
					writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"a9","status":true,"policy":0,"protocols":[6],"sourceType":"network","sourceIds":["n2"],"destinationType":"network","destinationIds":["n1"]}]}`)
					return
				}
				writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"a1","description":"block-iot","status":true,"policy":0,"protocols":[256],"sourceType":"network","sourceIds":["n2"],"destinationType":"network","destinationIds":["n1"],"index":4}]}`)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		p := &OmadaProvider{}
		res, err := p.ApplyACL(context.Background(), providers.ACLApplyRequest{
			From: []string{"IoT"}, To: []string{"Trusted"}, Action: "deny", Protocols: []int{6},
		}, applyOpts(ts))
		if err != nil {
			t.Fatalf("ApplyACL: %v", err)
		}
		if res.Outcome != "created" || res.RuleID != "a9" {
			t.Errorf("result = %+v, want created a9 (broader rule never covers)", res)
		}
		var body struct {
			Protocols []int `json:"protocols"`
		}
		if err := json.Unmarshal([]byte(gotBody), &body); err != nil {
			t.Fatalf("request body %q: %v", gotBody, err)
		}
		if !omadabackend.ProtocolsEqual(body.Protocols, []int{6}) {
			t.Errorf("wire protocols = %v, want [6]", body.Protocols)
		}
	})

	t.Run("empty protocols equals an all-protocols rule", func(t *testing.T) {
		ts := applyACLServer(t, `{"totalRows":1,"data":[{"id":"a1","description":"block-iot","status":true,"policy":0,"protocols":[256],"sourceType":"network","sourceIds":["n2"],"destinationType":"network","destinationIds":["n1"],"index":4}]}`, emptyList, false)
		p := &OmadaProvider{}
		res, err := p.ApplyACL(context.Background(), aclApplyReq("", "deny", []string{"IoT"}, []string{"Trusted"}), applyOpts(ts))
		if err != nil {
			t.Fatalf("ApplyACL: %v", err)
		}
		if res.Outcome != "unchanged" {
			t.Errorf("result = %+v, want unchanged (empty ≡ [256])", res)
		}
	})

	t.Run("enables a matching disabled rule", func(t *testing.T) {
		ts := applyACLServer(t, `{"totalRows":1,"data":[{"id":"a1","description":"block-iot","status":false,"policy":0,"sourceType":"network","sourceIds":["n2"],"destinationType":"network","destinationIds":["n1"],"index":4}]}`, emptyList, true)
		p := &OmadaProvider{}
		res, err := p.ApplyACL(context.Background(), aclApplyReq("", "deny", []string{"IoT"}, []string{"Trusted"}), applyOpts(ts))
		if err != nil {
			t.Fatalf("ApplyACL: %v", err)
		}
		if res.Outcome != "enabled" || res.RuleID != "a1" {
			t.Errorf("result = %+v, want enabled rule a1", res)
		}
	})

	t.Run("rejects conflicting action", func(t *testing.T) {
		ts := applyACLServer(t, `{"totalRows":1,"data":[{"id":"a1","description":"allow-iot","status":true,"policy":1,"sourceType":"network","sourceIds":["n2"],"destinationType":"network","destinationIds":["n1"],"index":4}]}`, emptyList, false)
		p := &OmadaProvider{}
		_, err := p.ApplyACL(context.Background(), aclApplyReq("", "deny", []string{"IoT"}, []string{"Trusted"}), applyOpts(ts))
		if err == nil || !strings.Contains(err.Error(), "conflicting") {
			t.Fatalf("ApplyACL error = %v, want conflicting rule error", err)
		}
	})

	t.Run("scopes never cover each other", func(t *testing.T) {
		// A covering switch rule must not satisfy a gateway-scope request.
		var wrote bool
		ts := omadaServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/openapi/authorize/token":
				writeEnvelope(w, 0, "", `{"accessToken":"t1"}`)
			case r.URL.Path == "/openapi/v1/abc123/sites":
				writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
			case r.URL.Path == "/openapi/v1/abc123/sites/s1/lan-networks":
				writeEnvelope(w, 0, "", threeNetworksJSON)
			case r.URL.Path == "/openapi/v1/abc123/sites/s1/acls/osg-acls" && r.Method == http.MethodPost:
				wrote = true
				writeEnvelope(w, 0, "", "null")
			case r.URL.Path == "/openapi/v1/abc123/sites/s1/acls/osg-acls":
				if wrote {
					writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"a7","status":true,"policy":0,"protocols":[256],"sourceType":"network","sourceIds":["n2"],"destinationType":"network","destinationIds":["n1"]}]}`)
					return
				}
				writeEnvelope(w, 0, "", emptyList)
			case r.URL.Path == "/openapi/v1/abc123/sites/s1/acls/osw-acls":
				// A covering switch rule exists, but it must not satisfy a
				// gateway-scope request.
				writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"a1","description":"block-iot","status":true,"policy":0,"sourceType":"network","sourceIds":["n2"],"destinationType":"network","destinationIds":["n1"],"index":4}]}`)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		p := &OmadaProvider{}
		res, err := p.ApplyACL(context.Background(), providers.ACLApplyRequest{
			From: []string{"IoT"}, To: []string{"Trusted"}, Action: "deny", Scope: "gateway",
		}, applyOpts(ts))
		if err != nil {
			t.Fatalf("ApplyACL: %v", err)
		}
		if res.Outcome != "created" || res.Scope != "gateway" || res.RuleID != "a7" {
			t.Errorf("result = %+v, want created a7 in the gateway scope", res)
		}
	})

	t.Run("dry run never mutates", func(t *testing.T) {
		ts := applyACLServer(t, emptyList, emptyList, false)
		p := &OmadaProvider{}
		res, err := p.ApplyACL(context.Background(), providers.ACLApplyRequest{
			From: []string{"IoT"}, To: []string{"Trusted"}, Action: "deny", DryRun: true,
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
		ts := applyACLServer(t, emptyList, emptyList, false)
		p := &OmadaProvider{}
		_, err := p.ApplyACL(context.Background(), aclApplyReq("", "deny", []string{"Missing"}, []string{"Trusted"}), applyOpts(ts))
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
			{"empty from", providers.ACLApplyRequest{From: nil, To: []string{"b"}, Action: "deny"}, "from is required"},
			{"empty to", providers.ACLApplyRequest{From: []string{"a"}, To: nil, Action: "deny"}, "to is required"},
			{"bad action", providers.ACLApplyRequest{From: []string{"a"}, To: []string{"b"}, Action: "drop"}, "action"},
			{"eap scope refused", providers.ACLApplyRequest{From: []string{"a"}, To: []string{"b"}, Action: "deny", Scope: "eap"}, "not supported"},
			{"bogus scope refused", providers.ACLApplyRequest{From: []string{"a"}, To: []string{"b"}, Action: "deny", Scope: "bogus"}, "not supported"},
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
			From: []string{"a"}, To: []string{"b"}, Action: "deny",
		}, providers.ImportOptions{Host: "https://127.0.0.1:1", ClientID: "u", ClientSecret: "p"})
		if err == nil {
			t.Fatal("expected session failure to propagate")
		}
	})

	t.Run("sites fetch failure propagates", func(t *testing.T) {
		ts := omadaServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/openapi/authorize/token":
				writeEnvelope(w, 0, "", `{"accessToken":"t1"}`)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		p := &OmadaProvider{}
		_, err := p.ApplyACL(context.Background(), aclApplyReq("", "deny", []string{"IoT"}, []string{"Trusted"}), applyOpts(ts))
		if err == nil || !strings.Contains(err.Error(), "fetching sites") {
			t.Fatalf("ApplyACL error = %v, want sites fetch failure", err)
		}
	})

	t.Run("networks fetch failure propagates", func(t *testing.T) {
		ts := omadaServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/openapi/authorize/token":
				writeEnvelope(w, 0, "", `{"accessToken":"t1"}`)
			case "/openapi/v1/abc123/sites":
				writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		p := &OmadaProvider{}
		_, err := p.ApplyACL(context.Background(), aclApplyReq("", "deny", []string{"IoT"}, []string{"Trusted"}), applyOpts(ts))
		if err == nil || !strings.Contains(err.Error(), "fetching networks") {
			t.Fatalf("ApplyACL error = %v, want networks fetch failure", err)
		}
	})

	t.Run("acl fetch failure propagates", func(t *testing.T) {
		ts := omadaServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/openapi/authorize/token":
				writeEnvelope(w, 0, "", `{"accessToken":"t1"}`)
			case "/openapi/v1/abc123/sites":
				writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
			case "/openapi/v1/abc123/sites/s1/lan-networks":
				writeEnvelope(w, 0, "", `{"totalRows":3,"data":[
					{"id":"n1","name":"Trusted","gatewaySubnet":"10.0.10.1/24"},
					{"id":"n2","name":"IoT","gatewaySubnet":"10.0.20.1/24"},
					{"id":"n3","name":"Guest","gatewaySubnet":"10.0.30.1/24"}]}`)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		p := &OmadaProvider{}
		_, err := p.ApplyACL(context.Background(), aclApplyReq("", "deny", []string{"IoT"}, []string{"Trusted"}), applyOpts(ts))
		if err == nil || !strings.Contains(err.Error(), "fetching ACL rules") {
			t.Fatalf("ApplyACL error = %v, want ACL fetch failure", err)
		}
	})

	t.Run("create failure propagates", func(t *testing.T) {
		ts := omadaServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/openapi/authorize/token":
				writeEnvelope(w, 0, "", `{"accessToken":"t1"}`)
			case r.URL.Path == "/openapi/v1/abc123/sites":
				writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
			case r.URL.Path == "/openapi/v1/abc123/sites/s1/lan-networks":
				writeEnvelope(w, 0, "", threeNetworksJSON)
			case r.URL.Path == "/openapi/v1/abc123/sites/s1/acls/osw-acls" && r.Method == http.MethodPost:
				writeEnvelope(w, -1005, "no permission", "null")
			case r.URL.Path == "/openapi/v1/abc123/sites/s1/acls/osw-acls":
				writeEnvelope(w, 0, "", emptyList)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		p := &OmadaProvider{}
		_, err := p.ApplyACL(context.Background(), aclApplyReq("", "deny", []string{"IoT"}, []string{"Trusted"}), applyOpts(ts))
		if err == nil || !strings.Contains(err.Error(), "creating ACL rule") {
			t.Fatalf("ApplyACL error = %v, want create failure", err)
		}
	})

	t.Run("enable failure propagates", func(t *testing.T) {
		ts := omadaServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/openapi/authorize/token":
				writeEnvelope(w, 0, "", `{"accessToken":"t1"}`)
			case r.URL.Path == "/openapi/v1/abc123/sites":
				writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
			case r.URL.Path == "/openapi/v1/abc123/sites/s1/lan-networks":
				writeEnvelope(w, 0, "", threeNetworksJSON)
			case strings.HasPrefix(r.URL.Path, "/openapi/v1/abc123/sites/s1/acls/osw-acls/") && r.Method == http.MethodPut:
				writeEnvelope(w, -1005, "no permission", "null")
			case r.URL.Path == "/openapi/v1/abc123/sites/s1/acls/osw-acls":
				writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"a1","description":"block-iot","status":false,"policy":0,"sourceType":"network","sourceIds":["n2"],"destinationType":"network","destinationIds":["n1"],"index":4}]}`)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		p := &OmadaProvider{}
		_, err := p.ApplyACL(context.Background(), aclApplyReq("", "deny", []string{"IoT"}, []string{"Trusted"}), applyOpts(ts))
		if err == nil || !strings.Contains(err.Error(), "updating ACL rule") {
			t.Fatalf("ApplyACL error = %v, want enable failure", err)
		}
	})

	t.Run("refetch failure after create propagates", func(t *testing.T) {
		var wrote bool
		ts := omadaServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/openapi/authorize/token":
				writeEnvelope(w, 0, "", `{"accessToken":"t1"}`)
			case r.URL.Path == "/openapi/v1/abc123/sites":
				writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
			case r.URL.Path == "/openapi/v1/abc123/sites/s1/lan-networks":
				writeEnvelope(w, 0, "", threeNetworksJSON)
			case r.URL.Path == "/openapi/v1/abc123/sites/s1/acls/osw-acls" && r.Method == http.MethodPost:
				wrote = true
				writeEnvelope(w, 0, "", "null")
			case r.URL.Path == "/openapi/v1/abc123/sites/s1/acls/osw-acls":
				if wrote {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				writeEnvelope(w, 0, "", emptyList)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		p := &OmadaProvider{}
		_, err := p.ApplyACL(context.Background(), aclApplyReq("", "deny", []string{"IoT"}, []string{"Trusted"}), applyOpts(ts))
		if err == nil || !strings.Contains(err.Error(), "refetching ACL rules") {
			t.Fatalf("ApplyACL error = %v, want refetch failure", err)
		}
	})

	t.Run("allow action creates an accept rule", func(t *testing.T) {
		var gotBody string
		var wrote bool
		ts := omadaServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/openapi/authorize/token":
				writeEnvelope(w, 0, "", `{"accessToken":"t1"}`)
			case r.URL.Path == "/openapi/v1/abc123/sites":
				writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
			case r.URL.Path == "/openapi/v1/abc123/sites/s1/lan-networks":
				writeEnvelope(w, 0, "", threeNetworksJSON)
			case r.URL.Path == "/openapi/v1/abc123/sites/s1/acls/osg-acls":
				writeEnvelope(w, 0, "", emptyList)
			case r.URL.Path == "/openapi/v1/abc123/sites/s1/acls/osw-acls" && r.Method == http.MethodPost:
				wrote = true
				gotBody = readReqBody(t, r)
				writeEnvelope(w, 0, "", "null")
			case r.URL.Path == "/openapi/v1/abc123/sites/s1/acls/osw-acls":
				if wrote {
					writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"a8","status":true,"policy":1,"sourceType":"network","sourceIds":["n1"],"destinationType":"network","destinationIds":["n2"]}]}`)
					return
				}
				writeEnvelope(w, 0, "", emptyList)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		p := &OmadaProvider{}
		res, err := p.ApplyACL(context.Background(), aclApplyReq("", "allow", []string{"Trusted"}, []string{"IoT"}), applyOpts(ts))
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

	t.Run("policy name default derives from endpoint sets", func(t *testing.T) {
		var gotBody string
		var wrote bool
		ts := omadaServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/openapi/authorize/token":
				writeEnvelope(w, 0, "", `{"accessToken":"t1"}`)
			case r.URL.Path == "/openapi/v1/abc123/sites":
				writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
			case r.URL.Path == "/openapi/v1/abc123/sites/s1/lan-networks":
				writeEnvelope(w, 0, "", threeNetworksJSON)
			case r.URL.Path == "/openapi/v1/abc123/sites/s1/acls/osg-acls":
				writeEnvelope(w, 0, "", emptyList)
			case r.URL.Path == "/openapi/v1/abc123/sites/s1/acls/osw-acls" && r.Method == http.MethodPost:
				wrote = true
				gotBody = readReqBody(t, r)
				writeEnvelope(w, 0, "", "null")
			case r.URL.Path == "/openapi/v1/abc123/sites/s1/acls/osw-acls":
				if wrote {
					writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"a9","status":true,"policy":0,"sourceType":"network","sourceIds":["n2"],"destinationType":"network","destinationIds":["n1","n3"]}]}`)
					return
				}
				writeEnvelope(w, 0, "", emptyList)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		p := &OmadaProvider{}
		res, err := p.ApplyACL(context.Background(), aclApplyReq("", "deny", []string{"IoT"}, []string{"Trusted", "Guest"}), applyOpts(ts))
		if err != nil {
			t.Fatalf("ApplyACL: %v", err)
		}
		var body struct {
			Description string `json:"description"`
		}
		if err := json.Unmarshal([]byte(gotBody), &body); err != nil {
			t.Fatalf("request body %q: %v", gotBody, err)
		}
		if body.Description != "iot-trusted-guest-deny" {
			t.Errorf("derived rule name = %q, want iot-trusted-guest-deny", body.Description)
		}
		if res.RuleID != "a9" {
			t.Errorf("rule_id = %q, want a9 from refetch", res.RuleID)
		}
	})
}

func TestProviderImplementsACLApplier(t *testing.T) {
	var _ providers.ACLApplier = (*OmadaProvider)(nil)
}
