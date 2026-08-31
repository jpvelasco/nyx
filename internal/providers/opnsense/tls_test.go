package opnsense

import (
	"os"
	"path/filepath"
	"testing"

	"crypto/tls"

	"github.com/jpvelasco/nyx/internal/testutil"
)

func TestBuildTLSConfig(t *testing.T) {
	dir := t.TempDir()
	caPath := testutil.WriteCAPem(t, dir)

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
