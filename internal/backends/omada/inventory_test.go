package omada

import (
	"strings"
	"testing"
)

func TestGroupClientsByNetwork(t *testing.T) {
	clients := []ConnectedClient{
		{IP: "10.0.0.100", Hostname: "OPNsense", NetworkName: "LAN(Default)", VLANID: 1, DeviceType: "Network Monitor", Vendor: "Unknown", Active: true},
		{IP: "10.0.0.112", Hostname: "Desktop-01", NetworkName: "LAN(Default)", VLANID: 1, DeviceType: "Computer", Vendor: "Unknown", Active: true},
		{IP: "10.0.0.110", Hostname: "Mac", NetworkName: "Trusted", VLANID: 10, DeviceType: "Laptop", Vendor: "Apple", Active: true},
		{IP: "10.0.0.106", Hostname: "Ring", NetworkName: "IoT", VLANID: 60, DeviceType: "Doorbell", Vendor: "Amazon", Active: true},
		{IP: "10.0.0.5", Hostname: "Mystery", NetworkName: "", VLANID: 0, DeviceType: "Unknown", Vendor: "Unknown", Active: true},
		{IP: "10.0.0.200", Hostname: "Old", NetworkName: "LAN(Default)", VLANID: 1, DeviceType: "Laptop", Vendor: "Unknown", Active: false},
	}

	groups := GroupClientsByNetwork(clients)

	// Inactive clients are excluded; 4 active clients span 4 distinct networks.
	if len(groups) != 4 {
		t.Fatalf("expected 4 groups, got %d: %+v", len(groups), groups)
	}

	nf := findGroup(groups, "LAN(Default)")
	if nf == nil {
		t.Fatal("missing LAN(Default) group")
	}
	if nf.Count != 2 {
		t.Errorf("LAN count = %d, want 2 (inactive excluded)", nf.Count)
	}
	// Sorted by IP ascending (numeric).
	if nf.Clients[0].IP != "10.0.0.100" || nf.Clients[1].IP != "10.0.0.112" {
		t.Errorf("LAN clients not sorted by IP: %+v", nf.Clients)
	}

	// The client with no network name lands in the "" group.
	unk := findGroup(groups, "")
	if unk == nil || unk.Count != 1 {
		t.Errorf("expected one client in unknown group, got %+v", unk)
	}
}

func TestGroupClientsByNetwork_NumericIPSort(t *testing.T) {
	// These IPs would sort incorrectly with lexicographic comparison:
	// "10.0.0.9" > "10.0.0.100" lexicographically, but 9 < 100 numerically.
	clients := []ConnectedClient{
		{IP: "10.0.0.100", Hostname: "A", NetworkName: "LAN", VLANID: 1, Active: true},
		{IP: "10.0.0.9", Hostname: "B", NetworkName: "LAN", VLANID: 1, Active: true},
		{IP: "10.0.0.20", Hostname: "C", NetworkName: "LAN", VLANID: 1, Active: true},
	}
	groups := GroupClientsByNetwork(clients)
	g := findGroup(groups, "LAN")
	if g == nil {
		t.Fatal("missing LAN group")
	}
	want := []string{"10.0.0.9", "10.0.0.20", "10.0.0.100"}
	for i, ip := range want {
		if g.Clients[i].IP != ip {
			t.Errorf("position %d: got %s, want %s (full: %+v)", i, g.Clients[i].IP, ip, g.Clients)
		}
	}
}

func TestGroupClientsByNetwork_Empty(t *testing.T) {
	if groups := GroupClientsByNetwork(nil); len(groups) != 0 {
		t.Errorf("expected no groups for nil input, got %+v", groups)
	}
}

func TestRenderClientInventory(t *testing.T) {
	clients := []ConnectedClient{
		{IP: "10.0.0.100", Hostname: "OPNsense", NetworkName: "LAN(Default)", VLANID: 1, DeviceType: "Network Monitor", Vendor: "Unknown", Active: true},
		{IP: "10.0.0.112", Hostname: "Desktop-01", NetworkName: "LAN(Default)", VLANID: 1, DeviceType: "Computer", Vendor: "Unknown", Active: true},
		{IP: "10.0.0.110", Hostname: "Mac", NetworkName: "Trusted", VLANID: 10, DeviceType: "Laptop", Vendor: "Apple", Active: true},
	}
	out := RenderClientInventory("Home", clients)

	for _, want := range []string{"Site: Home", "LAN(Default)", "OPNsense", "Desktop-01", "Trusted", "Mac"} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered output missing %q:\n%s", want, out)
		}
	}
	// Groups are ordered by VLAN id ascending: LAN (1) before Trusted (10).
	idxNF := strings.Index(out, "LAN(Default)")
	idxTrusted := strings.Index(out, "Trusted")
	if idxNF == -1 || idxTrusted == -1 || idxNF > idxTrusted {
		t.Errorf("expected LAN group before Trusted group:\n%s", out)
	}
}

func TestRenderClientInventory_NoClients(t *testing.T) {
	out := RenderClientInventory("Home", nil)
	if !strings.Contains(out, "No active clients") {
		t.Errorf("expected 'No active clients' message, got:\n%s", out)
	}
}

func TestRenderClientInventory_UnknownNetworkLabel(t *testing.T) {
	// Clients with empty NetworkName should render as "unknown network".
	clients := []ConnectedClient{
		{IP: "10.0.0.1", Hostname: "Mystery", NetworkName: "", VLANID: 0, DeviceType: "Unknown", Vendor: "Unknown", Active: true},
	}
	out := RenderClientInventory("Home", clients)
	if !strings.Contains(out, "unknown network") {
		t.Errorf("expected 'unknown network' label, got:\n%s", out)
	}
}

func TestGroupClientsByNetwork_SameVLANDifferentNames(t *testing.T) {
	// Two groups with the same VLANID but different network names should be
	// sorted by name (the tie-breaker at line 52).
	clients := []ConnectedClient{
		{IP: "192.168.1.1", Hostname: "A", NetworkName: "Zeta", VLANID: 10, Active: true},
		{IP: "192.168.1.2", Hostname: "B", NetworkName: "Alpha", VLANID: 10, Active: true},
	}
	groups := GroupClientsByNetwork(clients)
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(groups))
	}
	// Alpha should come before Zeta (same VLAN, sorted by name).
	if groups[0].NetworkName != "Alpha" || groups[1].NetworkName != "Zeta" {
		t.Errorf("expected [Alpha Zeta], got [%s %s]", groups[0].NetworkName, groups[1].NetworkName)
	}
}

func TestCompareIPs_InvalidIPFallback(t *testing.T) {
	// When IPs don't parse, compareIPs falls back to lexicographic order.
	// "banana" < "apple" is false, so "apple" should sort before "banana".
	if !compareIPs("apple", "banana") {
		t.Error("expected 'apple' to sort before 'banana' (lexicographic fallback)")
	}
	if compareIPs("banana", "apple") {
		t.Error("expected 'banana' to NOT sort before 'apple'")
	}
}

func findGroup(groups []ClientGroup, name string) *ClientGroup {
	for i := range groups {
		if groups[i].NetworkName == name {
			return &groups[i]
		}
	}
	return nil
}
