package omada

import (
	"os"
	"path/filepath"
	"testing"

	"crypto/tls"

	"github.com/jpvelasco/nyx/internal/testutil"
)

func TestSiteEffectiveID(t *testing.T) {
	cases := []struct {
		name string
		site Site
		want string
	}{
		{"id populated", Site{ID: "abc123", SiteID: "old456"}, "abc123"},
		{"fallback to siteId", Site{SiteID: "fallback789"}, "fallback789"},
		{"both empty", Site{}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.site.EffectiveID(); got != tc.want {
				t.Errorf("EffectiveID() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestNetworkCIDR(t *testing.T) {
	cases := []struct {
		name string
		n    Network
		want string
	}{
		{"standard subnet", Network{GatewaySubnet: "10.0.10.1/24"}, "10.0.10.0/24"},
		{"empty gateway", Network{}, ""},
		{"invalid cidr", Network{GatewaySubnet: "not-a-cidr"}, ""},
		{"host route", Network{GatewaySubnet: "192.168.1.1/32"}, "192.168.1.1/32"},
		{"wide subnet", Network{GatewaySubnet: "10.1.0.0/16"}, "10.1.0.0/16"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.n.CIDR(); got != tc.want {
				t.Errorf("CIDR() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestNetworkGateway(t *testing.T) {
	cases := []struct {
		name string
		n    Network
		want string
	}{
		{"standard", Network{GatewaySubnet: "10.0.10.1/24"}, "10.0.10.1"},
		{"empty", Network{}, ""},
		{"no prefix", Network{GatewaySubnet: "192.168.1.1"}, "192.168.1.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.n.Gateway(); got != tc.want {
				t.Errorf("Gateway() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestIsVersionSupported(t *testing.T) {
	cases := []struct {
		name string
		ver  string
		want bool
	}{
		{"6.0.0.36", "6.0.0.36", true},
		{"6.1.0", "6.1.0", true},
		{"7.0.0", "7.0.0", true},
		{"5.4.2", "5.4.2", false},
		{"4.0", "4.0", false},
		{"invalid", "invalid", false},
		{"empty", "", false},
		{"non-numeric minor", "6.x", false},
		{"non-numeric major", "x.y", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isVersionSupported(tc.ver)
			if got != tc.want {
				t.Errorf("isVersionSupported(%q) = %v, want %v", tc.ver, got, tc.want)
			}
		})
	}
}

func TestBuildTLSConfig(t *testing.T) {
	// Default: standard verification
	cfg := buildTLSConfig(false, "")
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be false by default")
	}

	// Skip verification
	cfg = buildTLSConfig(true, "")
	if !cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be true when skipTLSVerify is true")
	}
}

func TestBuildTLSConfigWithCA(t *testing.T) {
	dir := t.TempDir()
	caPath := testutil.WriteCAPem(t, dir)

	// Valid CA file: RootCAs populated, InsecureSkipVerify stays false.
	cfg := buildTLSConfig(false, caPath)
	if cfg.RootCAs == nil {
		t.Error("RootCAs should be populated when a valid CA file is given")
	}
	if cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should stay false when a CA file is given")
	}

	// Missing CA file: warning, fall back to system pool.
	cfg = buildTLSConfig(false, filepath.Join(dir, "missing.pem"))
	if cfg.RootCAs != nil {
		t.Error("RootCAs should be nil when the CA file is missing")
	}
	if cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should stay false on missing CA file")
	}

	// Invalid PEM: warning, fall back to system pool.
	badPath := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(badPath, []byte("not a certificate"), 0o600); err != nil {
		t.Fatalf("writing bad pem: %v", err)
	}
	cfg = buildTLSConfig(false, badPath)
	if cfg.RootCAs != nil {
		t.Error("RootCAs should be nil when the CA file has no valid certs")
	}
}

func TestMinVersionSet(t *testing.T) {
	cfg := buildTLSConfig(false, "")
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %v, want TLS 1.2", cfg.MinVersion)
	}
}
