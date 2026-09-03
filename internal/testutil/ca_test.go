package testutil

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// TestWriteCAPem covers the canonical self-signed CA writer: the PEM file
// exists, parses to a single CA certificate, and carries the documented
// identity (serial 1, CN "nyx-test-ca").
func TestWriteCAPem(t *testing.T) {
	caPath := WriteCAPem(t, t.TempDir())

	raw, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatalf("reading CA pem: %v", err)
	}
	if !strings.HasPrefix(string(raw), "-----BEGIN CERTIFICATE-----") {
		t.Fatalf("pem = %q, want a PEM CERTIFICATE block", raw)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("no PEM block found in CA pem")
	}
	certs, err := x509.ParseCertificates(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificates: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("certificates = %d, want 1", len(certs))
	}
	ca := certs[0]
	if !ca.IsCA {
		t.Error("IsCA = false, want true")
	}
	if ca.Subject.CommonName != "nyx-test-ca" {
		t.Errorf("CN = %q, want nyx-test-ca", ca.Subject.CommonName)
	}
	if ca.SerialNumber.Int64() != 1 {
		t.Errorf("serial = %d, want 1", ca.SerialNumber.Int64())
	}
}

// TestCASignedServer covers the CA-signed TLS server end to end: a client
// that pins the returned CA verifies the leaf (HTTPS 200, at both TLS 1.2
// and 1.3), while a client on the system CAs only fails the handshake —
// the property every CACertPath test in the repo relies on.
func TestCASignedServer(t *testing.T) {
	const want = "ok-from-leaf"
	serverURL, caPath := CASignedServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, want)
	}))

	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatalf("reading CA pem: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("AppendCertsFromPEM: CA pem does not parse")
	}

	for _, minVer := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		client := &http.Client{Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: minVer, RootCAs: pool},
		}}
		resp, err := client.Get(serverURL)
		if err != nil {
			t.Fatalf("GET via pinned CA (min %d): %v", minVer, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || string(body) != want {
			t.Fatalf("status = %d body = %q, want 200 %q", resp.StatusCode, body, want)
		}
	}

	// System-CAs-only client must not trust the leaf: the CA is not in the
	// system pool, so the handshake has to fail.
	sysClient := &http.Client{Transport: &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: 10 * time.Second,
	}}
	if _, err := sysClient.Get(serverURL); err == nil {
		t.Error("GET via system CAs only succeeded, want a handshake verification failure")
	}
}
