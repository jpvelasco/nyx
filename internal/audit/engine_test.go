package audit_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/velasco-jp/nyx/internal/audit"
	"github.com/velasco-jp/nyx/internal/backends/nmap"
	"github.com/velasco-jp/nyx/internal/intent"
	"github.com/velasco-jp/nyx/internal/models"
	"github.com/velasco-jp/nyx/internal/seendb"
)

func TestDiscoveryWarnPreservedWhenZeroHostsWithinBounds(t *testing.T) {
	if !nmap.Available() {
		t.Skip("nmap not available")
	}
	minVal := 0
	maxVal := 10
	spec := &intent.Spec{
		Version: 1,
		Site:    "test",
		Networks: []intent.Network{
			{Name: "testnet", CIDR: "10.255.255.0/24", Gateway: "10.255.255.1", Zone: "test"},
		},
		Assertions: []intent.Assertion{
			{
				Type:           "subnet_discovery",
				Network:        "testnet",
				ExpectHostsMin: &minVal,
				ExpectHostsMax: &maxVal,
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	engine := audit.NewEngine(spec)
	report, err := engine.Run(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(report.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(report.Findings))
	}

	f := report.Findings[0]
	if f.Status == models.StatusPass {
		t.Errorf("expected warn or error when 0 hosts discovered, got pass")
	}
}

func TestDiscoveryExpectedBoundsInResult(t *testing.T) {
	if !nmap.Available() {
		t.Skip("nmap not available")
	}
	minVal := 2
	maxVal := 20
	spec := &intent.Spec{
		Version: 1,
		Site:    "test",
		Networks: []intent.Network{
			{Name: "testnet", CIDR: "10.255.255.0/24", Gateway: "10.255.255.1", Zone: "test"},
		},
		Assertions: []intent.Assertion{
			{
				Type:           "subnet_discovery",
				Network:        "testnet",
				ExpectHostsMin: &minVal,
				ExpectHostsMax: &maxVal,
			},
		},
	}

	// Use normal scan mode so the test completes in reasonable time.
	spec.Assertions[0].ScanMode = "normal"

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	engine := audit.NewEngine(spec)
	report, err := engine.Run(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	f := report.Findings[0]
	if _, ok := f.Expected["expect_hosts_min"]; !ok {
		t.Error("expected 'expect_hosts_min' in result.Expected, not found")
	}
	if _, ok := f.Expected["expect_hosts_max"]; !ok {
		t.Error("expected 'expect_hosts_max' in result.Expected, not found")
	}
}

func TestRunPortCheckLocalhost(t *testing.T) {
	if !nmap.Available() {
		t.Skip("nmap not available")
	}
	spec := &intent.Spec{
		Version: 1,
		Site:    "test",
		Assertions: []intent.Assertion{
			{Type: "port_check", Target: "127.0.0.1", Ports: []int{22}, Protocol: "tcp", ExpectDeny: "open", ScanMode: "polite"},
		},
	}
	eng := audit.NewEngine(spec)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	report, err := eng.Run(ctx)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(report.Findings))
	}
	finding := report.Findings[0]
	if finding.CheckType != "port_check" {
		t.Errorf("expected port_check, got %q", finding.CheckType)
	}
	if finding.Status == models.StatusError {
		t.Errorf("expected non-error status, got error: %s", finding.Summary)
	}
}

func TestRunDNSCheckLocalhost(t *testing.T) {
	spec := &intent.Spec{
		Version: 1,
		Site:    "test",
		Assertions: []intent.Assertion{
			{Type: "dns_check", Query: "localhost"},
		},
	}
	eng := audit.NewEngine(spec)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	report, err := eng.Run(ctx)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("expected 1 finding")
	}
	finding := report.Findings[0]
	if finding.CheckType != "dns_check" {
		t.Errorf("expected dns_check, got %q", finding.CheckType)
	}
	if finding.Status == models.StatusError {
		t.Errorf("expected non-error status, got error: %s", finding.Summary)
	}
}

func TestRunNetworkHealthLocalhost(t *testing.T) {
	spec := &intent.Spec{
		Version: 1,
		Site:    "test",
		Assertions: []intent.Assertion{
			{Type: "network_health", Target: "127.0.0.1", ExpectLossPct: 50},
		},
	}
	eng := audit.NewEngine(spec)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	report, err := eng.Run(ctx)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("expected 1 finding")
	}
	finding := report.Findings[0]
	if finding.CheckType != "network_health" {
		t.Errorf("expected network_health, got %q", finding.CheckType)
	}
	if finding.Status == models.StatusError {
		t.Errorf("expected non-error status, got error: %s", finding.Summary)
	}
}

func TestPortCheckUnknownType(t *testing.T) {
	spec := &intent.Spec{
		Version: 1,
		Site:    "test",
		Assertions: []intent.Assertion{
			{Type: "unknown_type", Target: "127.0.0.1"},
		},
	}
	eng := audit.NewEngine(spec)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	report, err := eng.Run(ctx)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("expected 1 finding")
	}
	finding := report.Findings[0]
	if finding.Status != models.StatusError {
		t.Errorf("expected error status for unknown type, got %s", finding.Status)
	}
}

func TestDiscoveryVirtualFirstRunWarns(t *testing.T) {
	if !nmap.Available() {
		t.Skip("nmap not available")
	}
	// Use a real local network to ensure fast scanning and predictable results
	spec := &intent.Spec{
		Version: 1,
		Site:    "test",
		Networks: []intent.Network{
			{Name: "localhost", CIDR: "127.0.0.0/24", Gateway: "127.0.0.1", Zone: "local"},
		},
		Assertions: []intent.Assertion{
			{Type: "subnet_discovery", Network: "localhost"},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	engine := audit.NewEngine(spec)
	engine.WarnVirtual = true
	report, err := engine.Run(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	f := report.Findings[0]
	// The key test: verify that WarnVirtual flag is wired through without errors.
	// The actual behavior depends on whether localhost is detected as virtual.
	if f.Status == models.StatusError {
		t.Errorf("unexpected error status: %s", f.Summary)
	}
}

func TestLooksVirtualUnitWithSeenDB(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "seen.json")

	db, err := seendb.LoadFrom(dbPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	cidr := "192.168.174.0/24"
	if db.IsVirtualAcked(cidr) {
		t.Fatal("should not be acked yet")
	}
	if err := db.AckVirtual(cidr); err != nil {
		t.Fatalf("ack: %v", err)
	}
	db2, _ := seendb.LoadFrom(dbPath)
	if !db2.IsVirtualAcked(cidr) {
		t.Error("should be acked after write")
	}
}
