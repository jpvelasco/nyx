// Package system provides platform-specific backends for route, interface,
// ping, and traceroute checks. The public API is the same on every OS; the
// actual implementations live in system_linux.go, system_darwin.go, and
// system_windows.go selected at build time via Go build tags.
package system

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// Route represents a single entry in the kernel routing table.
type Route struct {
	Destination string `json:"destination"`
	Gateway     string `json:"gateway,omitempty"`
	Device      string `json:"device"`
	Protocol    string `json:"protocol,omitempty"`
	Scope       string `json:"scope,omitempty"`
	Metric      int    `json:"metric,omitempty"`
}

// Interface represents a network interface with its addresses.
type Interface struct {
	Name  string   `json:"name"`
	State string   `json:"state"`
	Addrs []string `json:"addrs"`
	Type  string   `json:"type,omitempty"` // e.g., "wireguard", "ethernet"
}

// PingResult captures the outcome of a ping test.
type PingResult struct {
	Reachable  bool    `json:"reachable"`
	PacketLoss float64 `json:"packet_loss"`
	AvgLatency string  `json:"avg_latency_ms,omitempty"`
}

// TracerouteHop represents a single hop in a traceroute.
type TracerouteHop struct {
	Number  int    `json:"number"`
	Address string `json:"address"`
	RTT     string `json:"rtt,omitempty"`
}

// -----------------------------------------------------------------------
// Shared helpers
// -----------------------------------------------------------------------

// checkPingTarget rejects ping targets that would be interpreted as command
// options by the platform's ping binary. It rejects the empty string,
// targets leading with '-' (option, e.g. "-n 5") or '/' (a path), any
// embedded whitespace (argument injection), and NUL bytes. IPv6 zone targets
// ("fe80::1%eth0") stay valid: they carry no leading option character and no
// whitespace.
//
// A leading "--" separator is deliberately not accepted as an escape: the
// Windows ping.exe does not support it, so the defense has to hold on its
// own.
func checkPingTarget(target string) error {
	if target == "" {
		return fmt.Errorf("ping target must not be empty")
	}
	if strings.HasPrefix(target, "-") {
		return fmt.Errorf("ping target %q must not start with '-'", target)
	}
	if strings.HasPrefix(target, "/") {
		return fmt.Errorf("ping target %q must not start with '/'", target)
	}
	if strings.ContainsAny(target, " \t\n\r\x00") {
		return fmt.Errorf("ping target %q must not contain whitespace or NUL", target)
	}
	return nil
}

// runCmd executes a command with the supplied context and returns stdout.
// #nosec G204 — internal helper; callers pass hardcoded system commands
func runCmd(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...) // nosemgrep
	out, err := cmd.Output()
	return string(out), err
}

// classifyInterface returns a human-readable interface type based on name
// and optional link type string. Shared across all platforms.
func classifyInterface(name, linkType string) string {
	lower := strings.ToLower(name)
	switch {
	case strings.HasPrefix(lower, "wg") || strings.Contains(lower, "wireguard"):
		return "wireguard"
	case strings.HasPrefix(lower, "lo"):
		return "loopback"
	case strings.HasPrefix(lower, "tun") || strings.HasPrefix(lower, "tap") ||
		strings.HasPrefix(lower, "utun") || strings.Contains(lower, "tunnel"):
		return "tunnel"
	case strings.HasPrefix(lower, "br"):
		return "bridge"
	case strings.HasPrefix(lower, "docker") || strings.HasPrefix(lower, "veth"):
		return "virtual"
	case strings.HasPrefix(lower, "wlan") || strings.HasPrefix(lower, "wifi") ||
		strings.HasPrefix(lower, "wlp"):
		return "wireless"
	case strings.HasPrefix(lower, "awdl"):
		return "wireless"
	case linkType == "ether" || strings.HasPrefix(lower, "eth") ||
		strings.HasPrefix(lower, "en"):
		return "ethernet"
	default:
		if linkType != "" {
			return linkType
		}
		return "unknown"
	}
}

// isVPNInterfaceName returns true if the interface name looks like a VPN tunnel.
// "wireguard" and "tunnel" are matched as substrings, not just prefixes, so
// Windows adapters named "WireGuard Tunnel" (or renamed variants keeping
// either marker) are detected — a WireGuard TUN adapter's name is not
// guaranteed to start with "wg".
func isVPNInterfaceName(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasPrefix(lower, "wg") ||
		strings.Contains(lower, "wireguard") ||
		strings.HasPrefix(lower, "tun") ||
		strings.HasPrefix(lower, "tap") ||
		strings.HasPrefix(lower, "utun") ||
		strings.Contains(lower, "tunnel") ||
		strings.HasPrefix(lower, "ipsec") ||
		strings.HasPrefix(lower, "tailscale") ||
		strings.HasPrefix(lower, "nordlynx") ||
		strings.HasPrefix(lower, "mullvad")
}
