package omada

import "testing"

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
