package cli

import (
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/backends/nmap"
)

func TestResolveDiscoverProbeSet_Unknown(t *testing.T) {
	if _, err := resolveDiscoverProbeSet("bogus", "10.0.0.0/24"); err == nil || !strings.Contains(err.Error(), "unknown probe set") {
		t.Errorf("got %v, want unknown probe set error", err)
	}
}

func TestResolveDiscoverProbeSet_ArpNotAttached(t *testing.T) {
	_, err := resolveDiscoverProbeSet("arp", "203.0.113.0/24")
	if err == nil || !strings.Contains(err.Error(), "not attached") {
		t.Errorf("got %v, want directly-attached error", err)
	}
}

func TestResolveDiscoverProbeSet_ArpInvalidSubnet(t *testing.T) {
	_, err := resolveDiscoverProbeSet("arp", "not-a-cidr")
	if err == nil || !strings.Contains(err.Error(), "invalid CIDR") {
		t.Errorf("got %v, want invalid CIDR error", err)
	}
}

func TestResolveDiscoverProbeSet_ArpAttached(t *testing.T) {
	cidr := attachedSubnet24(t)
	got, err := resolveDiscoverProbeSet("arp", cidr)
	if err != nil {
		t.Fatalf("got error %v, want arp", err)
	}
	if got != nmap.ProbeSetARP {
		t.Errorf("got %q, want arp", got)
	}
}

func TestResolveDiscoverProbeSet_Auto(t *testing.T) {
	got, err := resolveDiscoverProbeSet("auto", "203.0.113.0/24")
	if err != nil {
		t.Fatalf("routed auto got error %v", err)
	}
	if got != nmap.ProbeSetICMP {
		t.Errorf("routed auto = %q, want icmp", got)
	}

	got, err = resolveDiscoverProbeSet("auto", attachedSubnet24(t))
	if err != nil {
		t.Fatalf("attached auto got error %v", err)
	}
	if got != nmap.ProbeSetARP {
		t.Errorf("attached auto = %q, want arp", got)
	}
}

func TestResolveDiscoverProbeSet_Explicit(t *testing.T) {
	got, err := resolveDiscoverProbeSet("icmp", "203.0.113.0/24")
	if err != nil || got != nmap.ProbeSetICMP {
		t.Errorf("explicit icmp = (%q, %v)", got, err)
	}
	got, err = resolveDiscoverProbeSet("default", "203.0.113.0/24")
	if err != nil || got != nmap.ProbeSetDefault {
		t.Errorf("explicit default = (%q, %v)", got, err)
	}
}

func TestPacingFor(t *testing.T) {
	// Routed sweeps stay polite unless the user opted in.
	if t1, r1 := pacingFor(nmap.ProbeSetICMP, 4, 500, false, false); t1 != 2 || r1 != 50 {
		t.Errorf("icmp default pacing = (T%d, %d), want (T2, 50)", t1, r1)
	}
	if t1, r1 := pacingFor(nmap.ProbeSetICMP, 4, 500, true, false); t1 != 4 || r1 != 500 {
		t.Errorf("icmp timing-changed pacing = (T%d, %d), want (T4, 500)", t1, r1)
	}
	if t1, r1 := pacingFor(nmap.ProbeSetICMP, 4, 500, false, true); t1 != 4 || r1 != 500 {
		t.Errorf("icmp min-rate-changed pacing = (T%d, %d), want (T4, 500)", t1, r1)
	}
	// Local (ARP/default) sweeps keep the flag values.
	if t1, r1 := pacingFor(nmap.ProbeSetARP, 4, 500, false, false); t1 != 4 || r1 != 500 {
		t.Errorf("arp pacing = (T%d, %d), want (T4, 500)", t1, r1)
	}
}

// attachedSubnet24 builds a /24 around a non-loopback IPv4 on this host, so
// the subnet is guaranteed directly-attached regardless of where the test
// runs.
func attachedSubnet24(t *testing.T) string {
	t.Helper()
	ip := net.ParseIP(hostIPv4(t)).To4()
	return fmt.Sprintf("%d.%d.%d.0/24", ip[0], ip[1], ip[2])
}

// Probe resolution happens before the nmap availability check, so these
// command-level error paths run even where nmap is not installed.

func TestDiscoverCmd_UnknownProbes(t *testing.T) {
	saveRestoreGlobals(t)
	discoverSubnet = "203.0.113.0/24"
	discoverProbes = "bogus"
	if err := discoverCmd.RunE(discoverCmd, nil); err == nil || !strings.Contains(err.Error(), "unknown probe set") {
		t.Errorf("got %v, want unknown probe set error", err)
	}
}

func TestDiscoverCmd_ArpNotAttached(t *testing.T) {
	saveRestoreGlobals(t)
	discoverSubnet = "203.0.113.0/24"
	discoverProbes = "arp"
	if err := discoverCmd.RunE(discoverCmd, nil); err == nil || !strings.Contains(err.Error(), "not attached") {
		t.Errorf("got %v, want directly-attached error", err)
	}
}

func TestDiscoverCmd_HappyPath_Loopback(t *testing.T) {
	if !nmap.Available() {
		t.Skip("nmap not available")
	}
	saveRestoreGlobals(t)
	discoverSubnet = "127.0.0.1/32"
	discoverProbes = "icmp"
	timeout = "30s"
	if err := discoverCmd.RunE(discoverCmd, nil); err != nil {
		t.Fatalf("discover RunE failed: %v", err)
	}
}
