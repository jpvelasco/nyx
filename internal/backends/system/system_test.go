package system

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestClassifyInterface(t *testing.T) {
	tests := []struct {
		name     string
		linkType string
		want     string
	}{
		{"wg0", "", "wireguard"},
		{"wg-home", "ether", "wireguard"},
		{"WireGuard Tunnel", "", "wireguard"},
		{"wireguard tunnel", "", "wireguard"},
		{"My VPN WireGuard Adapter", "", "wireguard"},
		{"lo", "", "loopback"},
		{"tun0", "", "tunnel"},
		{"tap1", "", "tunnel"},
		{"utun2", "", "tunnel"},
		{"Teredo Tunneling Pseudo-Interface", "", "tunnel"},
		{"Renamed Tunnel VPN", "", "tunnel"},
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
		{"WireGuard Tunnel", true},
		{"wireguard tunnel", true},
		{"My VPN WireGuard Adapter", true},
		{"tun0", true},
		{"tap1", true},
		{"utun2", true},
		{"Teredo Tunneling Pseudo-Interface", true},
		{"Renamed Tunnel VPN", true},
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

func TestCheckPingTarget(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		wantErr bool
	}{
		{"empty", "", true},
		{"leading dash option", "-n 5", true},
		{"leading dash alone", "-w", true},
		{"leading slash path", "/etc/passwd", true},
		{"slash root", "/", true},
		{"embedded space", "10.0.0.1 -c 3", true},
		{"tab", "10.0.0.1\t-c 3", true},
		{"newline", "10.0.0.1\n-c 3", true},
		{"nul byte", "10.0.0.1\x00-c 3", true},
		{"valid IPv4", "192.168.1.1", false},
		{"valid hostname", "nas.example", false},
		{"valid IPv6", "fe80::1", false},
		{"IPv6 zone target", "fe80::1%eth0", false},
		{"IPv6 zone windows suffix", "fe80::1%Ethernet2", false},
		{"double dash is an option", "--help", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkPingTarget(tt.target)
			if (err != nil) != tt.wantErr {
				t.Fatalf("checkPingTarget(%q) error = %v, wantErr %v", tt.target, err, tt.wantErr)
			}
		})
	}
}

// TestPing_CommandErrorIsNotUnreachable pins that a ping usage/command
// failure (exit code 2, unparseable output) is reported as an error, not
// fabricated as 100% packet loss — a target/command error must never read
// as evidence of an unreachable host (#189). The ping binary is shimmed
// on PATH so the test is hermetic.
func TestPing_CommandErrorIsNotUnreachable(t *testing.T) {
	dir := t.TempDir()
	name := "ping"
	script := "#!/bin/sh\nusage: bad invocation\nexit 2\n"
	if runtime.GOOS == "windows" {
		name = "ping.bat"
		script = "@echo off\r\necho usage: bad invocation\r\nexit /b 2\r\n"
	}
	shim := filepath.Join(dir, name)
	if err := os.WriteFile(shim, []byte(script), 0o700); err != nil { // nosemgrep — the shim needs its owner execute bit
		t.Fatalf("writing ping shim: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pr, err := Ping(ctx, "10.0.60.0/24")
	if err == nil {
		t.Fatalf("command failure must surface as an error, got %+v", pr)
	}
	if pr != nil && pr.Reachable == false && pr.PacketLoss == 100 {
		t.Error("command failure was fabricated as 100% packet loss")
	}
}
