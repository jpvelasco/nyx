package opnsense

import (
	"strings"
	"testing"
)

func TestRenderInventory(t *testing.T) {
	snap := &InventorySnapshot{
		System:     mustSystemInfo(t),
		Interfaces: []Interface{{Name: "lan", Description: "LAN", IP: "10.0.0.1", Subnet: 24, Gateway: "10.0.0.254"}},
		Rules:      []FirewallRule{{}, {}, {}},
		RulesOK:    true,
		Leases:     []DHCPLease{{}, {}},
		LeasesOK:   true,
		Warnings:   []string{"DHCP leases unavailable: boom"},
	}
	out := RenderInventory(snap, "opnsense-firewall")
	for _, want := range []string{
		"Site: opnsense-firewall",
		"Controller: 24.1.7_2 (amd64)",
		"Warning: DHCP leases unavailable: boom",
		"== Networks (1) ==",
		"gateway: 10.0.0.254",
		"== Devices (1) ==",
		"== Firewall rules (3) ==",
		"3 rules",
		"== Clients ==",
		"2 active clients",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("render output missing %q:\n%s", want, out)
		}
	}
}

func TestRenderInventoryUnknownScopes(t *testing.T) {
	snap := &InventorySnapshot{
		Interfaces: []Interface{{Name: "lan", IP: "10.0.0.1", Subnet: 24}},
	}
	out := RenderInventory(snap, "opnsense-firewall")
	if !strings.Contains(out, "unknown (fetch failed)") {
		t.Errorf("rules fetch failure must render unknown:\n%s", out)
	}
	if !strings.Contains(out, "0 active clients") {
		t.Errorf("lease fetch failure must render 0 clients:\n%s", out)
	}
	if strings.Contains(out, "Controller: ") {
		t.Errorf("no system info → no Controller line at all:\n%s", out)
	}
}

func TestRenderInventoryNoArch(t *testing.T) {
	snap := &InventorySnapshot{
		System: &SystemInformation{Versions: []string{"OPNsense 24.1.7_2", "FreeBSD 14.2"}},
	}
	out := RenderInventory(snap, "opnsense-firewall")
	if strings.Contains(out, "Controller: 24.1.7_2 (") {
		t.Errorf("arch without a recognisable suffix must not render a parenthetical:\n%s", out)
	}
	if !strings.Contains(out, "Controller: 24.1.7_2\n") {
		t.Errorf("version without arch must render bare:\n%s", out)
	}
}

func TestBuildSpecInventory(t *testing.T) {
	snap := &InventorySnapshot{
		System: mustSystemInfo(t),
		Interfaces: []Interface{
			{Name: "lan", Description: "LAN", IP: "10.0.0.1", Subnet: 24, Gateway: "10.0.0.254"},
			{Name: "wan", Description: "WAN", IP: "203.0.113.1", Subnet: 24, Gateway: "203.0.113.254"},
			{Name: "no-ip", IP: "", Subnet: 0},
			{Name: "bad-cidr", IP: "999.1.1.1", Subnet: 33},
		},
	}
	inv := BuildSpecInventory(snap)
	if inv.ControllerVersion != "24.1.7_2" {
		t.Errorf("ControllerVersion = %q, want 24.1.7_2", inv.ControllerVersion)
	}
	if len(inv.Devices) != 2 {
		t.Fatalf("Devices = %+v, want 2 (lan + wan; no-ip and bad-cidr excluded)", inv.Devices)
	}
	if inv.Devices[0].Name != "lan" || inv.Devices[0].Type != "gateway" || inv.Devices[0].IP != "10.0.0.1" {
		t.Errorf("device[0] = %+v", inv.Devices[0])
	}
	if len(inv.Devices[0].Networks) != 1 || inv.Devices[0].Networks[0] != "lan" {
		t.Errorf("device[0].Networks = %v, want [lan]", inv.Devices[0].Networks)
	}
	if inv.NetworkGateways["lan"] != "10.0.0.254" || inv.NetworkGateways["wan"] != "203.0.113.254" {
		t.Errorf("NetworkGateways = %v", inv.NetworkGateways)
	}
	// OPNsense exposes no managed-device inventory — model/firmware/upgrade
	// must stay empty, and there are no ACL scopes to report.
	for _, d := range inv.Devices {
		if d.Model != "" || d.Firmware != "" || d.Upgrade {
			t.Errorf("device %+v must not carry model/firmware/upgrade (not exposed)", d)
		}
	}
	if len(inv.ACLScopes) != 0 {
		t.Errorf("ACLScopes = %+v, want none (OPNsense has no Omada-style scopes)", inv.ACLScopes)
	}
}

func TestBuildSpecInventoryNoSystem(t *testing.T) {
	snap := &InventorySnapshot{
		Interfaces: []Interface{{Name: "lan", IP: "10.0.0.1", Subnet: 24}},
	}
	inv := BuildSpecInventory(snap)
	if inv.ControllerVersion != "" {
		t.Errorf("ControllerVersion = %q, want empty when system info is absent", inv.ControllerVersion)
	}
}

func TestLeaseCount(t *testing.T) {
	if got := (&InventorySnapshot{Leases: []DHCPLease{{}, {}}, LeasesOK: true}).LeaseCount(); got != 2 {
		t.Errorf("LeaseCount = %d, want 2", got)
	}
	if got := (&InventorySnapshot{Leases: []DHCPLease{{}, {}}, LeasesOK: false}).LeaseCount(); got != 0 {
		t.Errorf("LeaseCount with LeasesOK=false = %d, want 0", got)
	}
}

// mustSystemInfo builds a SystemInformation with a known product version and arch.
func mustSystemInfo(t *testing.T) *SystemInformation {
	t.Helper()
	return &SystemInformation{Versions: []string{"OPNsense 24.1.7_2-amd64", "FreeBSD 14.2-RELEASE-p1", "OpenSSL 3.0.13"}}
}
