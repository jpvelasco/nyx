package opnsense

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBuildTLSConfig(t *testing.T) {
	dir := t.TempDir()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "nyx-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	caPath := filepath.Join(dir, "ca.pem")
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(caPath, pemData, 0o600); err != nil {
		t.Fatalf("writing CA pem: %v", err)
	}

	t.Run("default", func(t *testing.T) {
		cfg := buildTLSConfig(false, "")
		if cfg.InsecureSkipVerify || cfg.RootCAs != nil {
			t.Errorf("cfg = %+v, want plain TLS 1.2 config", cfg)
		}
		if cfg.MinVersion != tls.VersionTLS12 {
			t.Errorf("MinVersion = %v, want TLS 1.2", cfg.MinVersion)
		}
	})

	t.Run("skip verify", func(t *testing.T) {
		cfg := buildTLSConfig(true, "")
		if !cfg.InsecureSkipVerify {
			t.Error("InsecureSkipVerify should be true when skipTLSVerify is set")
		}
	})

	t.Run("valid CA", func(t *testing.T) {
		cfg := buildTLSConfig(false, caPath)
		if cfg.RootCAs == nil {
			t.Error("RootCAs should be populated for a valid CA file")
		}
		if cfg.InsecureSkipVerify {
			t.Error("InsecureSkipVerify should stay false with a CA file")
		}
	})

	t.Run("missing CA file", func(t *testing.T) {
		cfg := buildTLSConfig(false, filepath.Join(dir, "missing.pem"))
		if cfg.RootCAs != nil {
			t.Error("RootCAs should be nil when the CA file is missing")
		}
	})

	t.Run("invalid CA pem", func(t *testing.T) {
		badPath := filepath.Join(dir, "bad.pem")
		if err := os.WriteFile(badPath, []byte("not a cert"), 0o600); err != nil {
			t.Fatalf("writing bad pem: %v", err)
		}
		cfg := buildTLSConfig(false, badPath)
		if cfg.RootCAs != nil {
			t.Error("RootCAs should be nil when the CA file has no valid certs")
		}
	})
}
