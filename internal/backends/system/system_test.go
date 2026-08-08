package system

import (
	"context"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestClassifyInterface(t *testing.T) {
	tests := []struct {
		name     string
		linkType string
		want     string
	}{
		{"wg0", "", "wireguard"},
		{"wg-home", "ether", "wireguard"},
		{"lo", "", "loopback"},
		{"tun0", "", "tunnel"},
		{"tap1", "", "tunnel"},
		{"utun2", "", "tunnel"},
		{"br0", "", "bridge"},
		{"docker0", "", "virtual"},
		{"veth123", "", "virtual"},
		{"wlan0", "", "wireless"},
		{"wlp3s0", "", "wireless"},
		{"wifi0", "", "wireless"},
		{"awdl0", "", "wireless"},
		{"eth0", "", "ethernet"},
		{"en0", "ether", "ethernet"},
		{"enp0s3", "", "ethernet"},
		{"Ethernet", "ether", "ethernet"},
		{"some-custom", "foo", "foo"},
		{"random0", "", "unknown"},
		{"", "ether", "ethernet"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyInterface(tt.name, tt.linkType); got != tt.want {
				t.Errorf("classifyInterface(%q, %q) = %q, want %q", tt.name, tt.linkType, got, tt.want)
			}
		})
	}
}

func TestIsVPNInterfaceName(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"wg0", true},
		{"wg-home", true},
		{"tun0", true},
		{"tap1", true},
		{"utun2", true},
		{"ipsec0", true},
		{"tailscale0", true},
		{"nordlynx", true},
		{"mullvad", true},
		{"eth0", false},
		{"en0", false},
		{"lo", false},
		{"docker0", false},
		{"br-lan", false},
		{"WLAN0", false}, // case: only wg/tun etc prefixes are lower-checked, but wg would match if Wg? wait lower
		{"WG0", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isVPNInterfaceName(tt.name); got != tt.want {
				t.Errorf("isVPNInterfaceName(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestRunCmd(t *testing.T) {
	// Use the go binary that is running this test suite: guaranteed to exist
	// on every CI leg and deterministic in output.
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go binary not in PATH")
	}

	t.Run("success", func(t *testing.T) {
		out, err := runCmd(context.Background(), goBin, "version")
		if err != nil {
			t.Fatalf("runCmd(go version) error: %v", err)
		}
		if out == "" {
			t.Fatal("expected version output")
		}
	})

	t.Run("missing binary", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "definitely-missing-command")
		if runtime.GOOS == "windows" {
			missing += ".exe"
		}
		if _, err := runCmd(context.Background(), missing); err == nil {
			t.Fatal("expected error for missing command")
		}
	})

	t.Run("cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := runCmd(ctx, goBin, "version"); err == nil {
			t.Fatal("expected error for cancelled context")
		}
	})
}

func lookup(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("%s not available in PATH", name)
	}
}
