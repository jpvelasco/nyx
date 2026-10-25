package opnsense

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/testutil"
)

func TestFilterAliasWritesAndHelpers(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "add_") {
			testutil.WriteBody(w, `{"result":"saved","uuid":"new"}`)
			return
		}
		testutil.WriteBody(w, `{"result":"saved"}`)
	}))
	id, err := c.CreateFilterRule(context.Background(), FilterWrite{Action: "block", Source: "lan", Destination: "iot", Enabled: true, Description: "isolate"})
	if err != nil || id != "new" {
		t.Fatalf("create filter = %q %v", id, err)
	}
	if err := c.SetFilterRule(context.Background(), "r1", FilterWrite{Action: "pass", Source: "lan", Destination: "any"}); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteFilterRule(context.Background(), "r1"); err != nil {
		t.Fatal(err)
	}
	id, err = c.CreateAlias(context.Background(), AliasWrite{Name: "iot_net", Type: "network", Addresses: []string{"10.0.60.0/24"}, Enabled: true})
	if err != nil || id != "new" {
		t.Fatalf("create alias = %q %v", id, err)
	}
	if err := c.SetAlias(context.Background(), "a1", AliasWrite{Name: "iot_net", Addresses: []string{"10.0.60.0/24"}}); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteAlias(context.Background(), "a1"); err != nil {
		t.Fatal(err)
	}
	if err := c.ReconfigureAliases(context.Background()); err != nil {
		t.Fatal(err)
	}

	rules := []FirewallRule{{RuleUUID: "r1", Action: "block", Source: "lan", Destination: "iot", Label: "isolate"}}
	if got, ok := FindFilterRule(rules, "r1", ""); !ok || got.Label != "isolate" {
		t.Fatal("uuid match")
	}
	if got, ok := FindFilterRule(rules, "", "isolate"); !ok || got.RuleUUID != "r1" {
		t.Fatal("label match")
	}
	if !FilterMatchesWrite(rules[0], FilterWrite{Action: "block", Source: "lan", Destination: "iot", Description: "isolate", Enabled: true}) {
		t.Fatal("want match")
	}
	if FilterMatchesWrite(rules[0], FilterWrite{Action: "pass", Source: "lan", Destination: "iot"}) {
		t.Fatal("want action mismatch")
	}
	aliases := []Alias{{UUID: "a1", Name: "iot_net", Type: "network", Addresses: []string{"10.0.60.0/24"}}}
	if got, ok := FindAlias(aliases, "", "iot_net"); !ok || got.UUID != "a1" {
		t.Fatal("alias name match")
	}
	// The wire payload always carries the enabled state; a match must
	// request the same state (Disabled=false ⇔ Enabled=true).
	if !AliasMatchesWrite(aliases[0], AliasWrite{Name: "iot_net", Type: "network", Addresses: []string{"10.0.60.0/24"}, Enabled: true}) {
		t.Fatal("want alias match")
	}
	if _, ok := FindFilterRule(rules, "", "missing"); ok {
		t.Fatal("want filter miss")
	}
	if _, ok := FindAlias(aliases, "a1", ""); !ok {
		t.Fatal("want alias uuid match")
	}
	if _, ok := FindAlias(aliases, "", "missing"); ok {
		t.Fatal("want alias miss")
	}
	if FilterMatchesWrite(rules[0], FilterWrite{Action: "block", Source: "guest", Destination: "iot", Enabled: true}) {
		t.Fatal("want source mismatch")
	}
	if FilterMatchesWrite(rules[0], FilterWrite{Action: "block", Source: "lan", Destination: "guest", Enabled: true}) {
		t.Fatal("want dest mismatch")
	}
	if AliasMatchesWrite(aliases[0], AliasWrite{Name: "other"}) {
		t.Fatal("want alias name mismatch")
	}
	if FilterMatchesWrite(rules[0], FilterWrite{Action: "block", Source: "lan", Destination: "iot", Description: "other", Enabled: true}) {
		t.Fatal("want description mismatch")
	}
	if AliasMatchesWrite(aliases[0], AliasWrite{Name: "iot_net", Type: "host", Addresses: []string{"10.0.60.0/24"}}) {
		t.Fatal("want alias type mismatch")
	}
	w := FilterWrite{Action: "block", Interface: "lan", Protocol: "tcp", SourcePort: "any", DestPort: "443", Direction: "in", IPProtocol: "inet", Description: "https"}
	if _, err := filterWire(w); err != nil {
		t.Fatal(err)
	}
	if _, err := aliasWire(AliasWrite{Name: "x", Description: "y"}); err != nil {
		t.Fatal(err)
	}
}

// TestFindFilterRule_UUIDAuthoritative reproduces #168: an explicitly
// selected UUID must win over an earlier row's natural-key (label) match,
// and a non-empty UUID that is absent must not silently fall back to a
// label match on a different object.
func TestFindFilterRule_UUIDAuthoritative(t *testing.T) {
	rows := []FirewallRule{
		{RuleUUID: "rule-first", Label: "isolate"},
		{RuleUUID: "rule-target", Label: "isolate"},
	}
	got, ok := FindFilterRule(rows, "rule-target", "isolate")
	if !ok {
		t.Fatal("expected a match")
	}
	if got.RuleUUID != "rule-target" {
		t.Errorf("got = %q, want the explicitly selected rule-target", got.RuleUUID)
	}
	// A requested UUID that is absent is a miss — never another object
	// that happens to share the natural key.
	if _, ok := FindFilterRule(rows, "rule-missing", "isolate"); ok {
		t.Error("a missing UUID must not fall back to a label match")
	}
}

// TestFindAlias_UUIDAuthoritative mirrors the UUID precedence for aliases.
func TestFindAlias_UUIDAuthoritative(t *testing.T) {
	rows := []Alias{
		{UUID: "a-first", Name: "iot_net"},
		{UUID: "a-target", Name: "iot_net"},
	}
	got, ok := FindAlias(rows, "a-target", "iot_net")
	if !ok || got.UUID != "a-target" {
		t.Errorf("got = %+v, want the explicitly selected a-target", got)
	}
	if _, ok := FindAlias(rows, "a-missing", "iot_net"); ok {
		t.Error("a missing UUID must not fall back to a name match")
	}
}

// TestFilterMatchesWrite_ComparableFields reproduces #169: a write that
// changes protocol, interface, ports, or direction must not read as a
// no-op — every field the write model carries participates in the
// comparison.
func TestFilterMatchesWrite_ComparableFields(t *testing.T) {
	r := FirewallRule{RuleUUID: "r1", Action: "block", Interface: []string{"trusted"},
		Protocol: "tcp", Source: "trusted", Destination: "iot",
		SourcePort: "any", DestPort: "443", Direction: "in", IPProtocol: "inet", Label: "isolate", Enabled: "1"}
	base := FilterWrite{Action: "block", Interface: "trusted", Protocol: "tcp",
		Source: "trusted", Destination: "iot",
		SourcePort: "any", DestPort: "443", Direction: "in", IPProtocol: "inet",
		Description: "isolate", Enabled: true}
	if !FilterMatchesWrite(r, base) {
		t.Fatal("identical write must match")
	}

	protoChanged := base
	protoChanged.Protocol = "udp"
	if FilterMatchesWrite(r, protoChanged) {
		t.Error("protocol-only change must not be a no-op")
	}

	ifaceChanged := base
	ifaceChanged.Interface = "guest"
	if FilterMatchesWrite(r, ifaceChanged) {
		t.Error("interface-only change must not be a no-op")
	}

	srcPortChanged := base
	srcPortChanged.SourcePort = "8000"
	if FilterMatchesWrite(r, srcPortChanged) {
		t.Error("source-port-only change must not be a no-op")
	}

	dstPortChanged := base
	dstPortChanged.DestPort = "8443"
	if FilterMatchesWrite(r, dstPortChanged) {
		t.Error("destination-port-only change must not be a no-op")
	}

	dirChanged := base
	dirChanged.Direction = "out"
	if FilterMatchesWrite(r, dirChanged) {
		t.Error("direction-only change must not be a no-op")
	}
}

// TestAliasMatchesWrite_EnabledAndDescription reproduces #169: enabling a
// disabled alias or changing its description must not read as a no-op —
// the wire payload always carries the enabled state.
func TestAliasMatchesWrite_EnabledAndDescription(t *testing.T) {
	disabled := Alias{UUID: "a1", Name: "iot_net", Type: "network", Addresses: []string{"10.0.60.0/24"}, Disabled: true}
	base := AliasWrite{Name: "iot_net", Type: "network", Addresses: []string{"10.0.60.0/24"}, Enabled: true}
	if AliasMatchesWrite(disabled, base) {
		t.Error("enabling a disabled alias must not be a no-op (the wire always carries enabled)")
	}

	described := Alias{UUID: "a1", Name: "iot_net", Type: "network", Addresses: []string{"10.0.60.0/24"}, Description: "current", Disabled: false}
	changed := base
	changed.Description = "updated"
	if AliasMatchesWrite(described, changed) {
		t.Error("description change on an existing description must not be a no-op")
	}
	if !AliasMatchesWrite(described, base) {
		t.Error("identical write (no description requested, existing description kept) must match")
	}
}

// TestFindHelpers_UUIDAuthoritative pins the UUID precedence for the DHCP
// and Unbound mutation lookups: a missing UUID never falls back to a
// natural-key match on a different object (#168).
func TestFindHelpers_UUIDAuthoritative(t *testing.T) {
	ranges := []DnsmasqRange{{UUID: "r-first", Interface: "lan", Start: "10.0.10.100", End: "10.0.10.200"}, {UUID: "r-target", Interface: "lan", Start: "10.0.10.100", End: "10.0.10.200"}}
	if got, ok := FindDnsmasqRange(ranges, "r-target", "lan", "10.0.10.100", "10.0.10.200"); !ok || got.UUID != "r-target" {
		t.Errorf("dnsmasq range = %+v ok=%v, want r-target", got, ok)
	}
	if _, ok := FindDnsmasqRange(ranges, "r-missing", "lan", "10.0.10.100", "10.0.10.200"); ok {
		t.Error("dnsmasq range: missing UUID must not fall back")
	}

	hosts := []DnsmasqHost{{UUID: "h-first", Host: "nas", IP: "10.0.40.1"}, {UUID: "h-target", Host: "nas", IP: "10.0.40.1"}}
	if got, ok := FindDnsmasqHost(hosts, "h-target", "nas", "10.0.40.1"); !ok || got.UUID != "h-target" {
		t.Errorf("dnsmasq host = %+v ok=%v, want h-target", got, ok)
	}
	if _, ok := FindDnsmasqHost(hosts, "h-missing", "nas", "10.0.40.1"); ok {
		t.Error("dnsmasq host: missing UUID must not fall back")
	}

	subnets := []KeaSubnet{{UUID: "s-first", Subnet: "10.0.10.0/24"}, {UUID: "s-target", Subnet: "10.0.10.0/24"}}
	if got, ok := FindKeaSubnet(subnets, "s-target", "10.0.10.0/24"); !ok || got.UUID != "s-target" {
		t.Errorf("kea subnet = %+v ok=%v, want s-target", got, ok)
	}
	if _, ok := FindKeaSubnet(subnets, "s-missing", "10.0.10.0/24"); ok {
		t.Error("kea subnet: missing UUID must not fall back")
	}

	reservations := []KeaReservation{{UUID: "k-first", IP: "10.0.40.1", MAC: "02:00:00:00:00:01"}, {UUID: "k-target", IP: "10.0.40.1", MAC: "02:00:00:00:00:01"}}
	if got, ok := FindKeaReservation(reservations, "k-target", "10.0.40.1", "02:00:00:00:00:01"); !ok || got.UUID != "k-target" {
		t.Errorf("kea reservation = %+v ok=%v, want k-target", got, ok)
	}
	if _, ok := FindKeaReservation(reservations, "k-missing", "10.0.40.1", "02:00:00:00:00:01"); ok {
		t.Error("kea reservation: missing UUID must not fall back")
	}

	overrides := []UnboundHostOverride{{UUID: "o-first", Hostname: "nas", Domain: "home.example", IP: "10.0.40.1"}, {UUID: "o-target", Hostname: "nas", Domain: "home.example", IP: "10.0.40.1"}}
	if got, ok := FindUnboundOverride(overrides, "o-target", "nas", "home.example"); !ok || got.UUID != "o-target" {
		t.Errorf("unbound override = %+v ok=%v, want o-target", got, ok)
	}
	if _, ok := FindUnboundOverride(overrides, "o-missing", "nas", "home.example"); ok {
		t.Error("unbound override: missing UUID must not fall back")
	}
}
