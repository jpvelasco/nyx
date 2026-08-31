package omadaprovider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jpvelasco/nyx/internal/models"
	"github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/testutil"
)

// aclCheckMockHandler is a canned Omada controller for the TLS-forwarding
// regression tests: no networks (so no subnet_discovery / network_health)
// and one enabled permit ACL rule (exactly one acl_check assertion; a
// permit rule adds no isolation assertion).
func aclCheckMockHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/info":
			testutil.WriteBody(w, infoJSON)
		case "/openapi/authorize/token":
			writeEnvelope(w, 0, "", `{"accessToken":"t1"}`)
		case "/openapi/v1/abc123/sites":
			writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		case "/openapi/v1/abc123/sites/s1/lan-networks":
			writeEnvelope(w, 0, "", `{"totalRows":0,"data":[]}`)
		case "/openapi/v1/abc123/sites/s1/acls/osg-acls":
			writeEnvelope(w, 0, "", `{"totalRows":0,"data":[]}`)
		case "/openapi/v1/abc123/sites/s1/acls/osw-acls":
			writeEnvelope(w, 0, "", `{"totalRows":1,"data":[
				{"id":"a1","description":"Allow Web","status":true,"policy":1,"sourceType":"network","sourceIds":["n-lan"],"destinationType":"network","destinationIds":["n-iot"]}
			]}`)
		case "/openapi/v1/abc123/sites/s1/networks/client":
			writeEnvelope(w, 0, "", `{"totalRows":0,"data":[]}`)
		case "/openapi/v1/abc123/sites/s1/setting/service/dhcp/user-list":
			writeEnvelope(w, 0, "", `{"totalRows":0,"data":[]}`)
		case "/openapi/v1/abc123/sites/s1/networks/devices":
			writeEnvelope(w, 0, "", `{"totalRows":0,"data":[]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

// findingByType returns the first report finding of the given check type.
func findingByType(t *testing.T, r *models.AuditReport, checkType string) *models.CheckResult {
	t.Helper()
	for i := range r.Findings {
		if r.Findings[i].CheckType == checkType {
			return &r.Findings[i]
		}
	}
	t.Fatalf("report has no %s finding (summary: %+v)", checkType, r.Summary)
	return nil
}

// TestProviderCheck_ForwardsTLSOptions is the regression test for #24:
// Check() must forward --skip-tls-verify / --ca-cert to the audit engine,
// because the engine-backed acl_check builds its own controller client from
// the engine's TLS fields. Without the forwarding, the engine's client
// enforced system-CA verification against a self-signed controller and the
// acl_check assertion came back as an error even though the import (which
// honors the flag) succeeded.
func TestProviderCheck_ForwardsTLSOptions(t *testing.T) {
	setEnv := func(t *testing.T, host string) {
		t.Helper()
		t.Setenv("OMADA_HOST", host)
		t.Setenv("OMADA_CLIENT_ID", "admin")
		t.Setenv("OMADA_CLIENT_SECRET", "pw")
		t.Setenv("OMADA_SITE", "HQ")
	}

	t.Run("skip-tls-verify reaches the engine acl_check", func(t *testing.T) {
		ts := httptest.NewTLSServer(aclCheckMockHandler())
		defer ts.Close()
		setEnv(t, ts.URL)

		p := &OmadaProvider{}
		res, err := p.Check(context.Background(), providers.ImportOptions{
			Host: ts.URL, ClientID: "admin", ClientSecret: "pw", Site: "HQ",
			SkipTLSVerify: true,
		})
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		if res.Report == nil {
			t.Fatal("Report is nil")
		}
		// The engine-backed acl_check must have reached the self-signed
		// mock and matched the enabled rule — only possible when the
		// engine's SkipTLSVerify honored the import option.
		acl := findingByType(t, res.Report, "acl_check")
		if acl.Status != models.StatusPass {
			t.Errorf("acl_check status = %s, want pass (summary %q)", acl.Status, acl.Summary)
		}
	})

	t.Run("ca-cert reaches the engine acl_check", func(t *testing.T) {
		serverURL, caPath := testutil.CASignedServer(t, aclCheckMockHandler())
		setEnv(t, serverURL)

		p := &OmadaProvider{}
		res, err := p.Check(context.Background(), providers.ImportOptions{
			Host: serverURL, ClientID: "admin", ClientSecret: "pw", Site: "HQ",
			CACertPath: caPath,
		})
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		acl := findingByType(t, res.Report, "acl_check")
		if acl.Status != models.StatusPass {
			t.Errorf("acl_check status = %s, want pass (summary %q)", acl.Status, acl.Summary)
		}
	})
}
