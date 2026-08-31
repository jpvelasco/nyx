package omadaprovider

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

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

// caSignedServerURL serves the handler over TLS with a leaf certificate
// signed by a freshly generated CA (IP SAN for 127.0.0.1) and returns the
// server URL plus the path of the CA PEM. Clients that pin caPath verify
// the leaf; clients with system-CAs-only verification fail the handshake.
func caSignedServerURL(t *testing.T, h http.Handler) (string, string) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "nyx-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("creating CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parsing CA cert: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("creating leaf cert: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	srv := &http.Server{
		Handler: h,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{{
				Certificate: [][]byte{leafDER, caDER},
				PrivateKey:  leafKey,
			}},
		},
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })

	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatalf("writing CA pem: %v", err)
	}
	return "https://" + ln.Addr().String(), caPath
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
		serverURL, caPath := caSignedServerURL(t, aclCheckMockHandler())
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
