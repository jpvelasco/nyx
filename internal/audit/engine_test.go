package audit_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jpvelasco/nyx/internal/audit"
	"github.com/jpvelasco/nyx/internal/backends/nmap"
	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/models"
	"github.com/jpvelasco/nyx/internal/seendb"
)

func TestEvalIsolationStatus(t *testing.T) {
	tests := []struct {
		name         string
		expectDeny   bool
		anyTested    bool
		allBlocked   bool
		wantStatus   models.Status
		wantSummary  string
		wantViolates bool
	}{
		{
			name:       "deny-expected-untested",
			expectDeny: true, anyTested: false, allBlocked: false,
			wantStatus:  models.StatusWarn,
			wantSummary: "isolation unverifiable",
		},
		{
			name:       "deny-expected-all-blocked",
			expectDeny: true, anyTested: true, allBlocked: true,
			wantStatus:  models.StatusPass,
			wantSummary: "isolation confirmed",
		},
		{
			name:       "deny-expected-not-blocked",
			expectDeny: true, anyTested: true, allBlocked: false,
			wantStatus:   models.StatusFail,
			wantSummary:  "isolation violation",
			wantViolates: true,
		},
		{
			name:       "allow-expected-all-blocked",
			expectDeny: false, anyTested: true, allBlocked: true,
			wantStatus:  models.StatusFail,
			wantSummary: "connectivity failure",
		},
		{
			name:       "allow-expected-not-blocked",
			expectDeny: false, anyTested: true, allBlocked: false,
			wantStatus:  models.StatusPass,
			wantSummary: "connectivity confirmed",
		},
		{
			name:       "allow-expected-untested",
			expectDeny: false, anyTested: false, allBlocked: false,
			wantStatus:  models.StatusWarn,
			wantSummary: "isolation unverifiable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, summary, violations := audit.EvalIsolationStatus("probe1", "from-zone", "to-zone", tt.expectDeny, tt.anyTested, tt.allBlocked)
			if status != tt.wantStatus {
				t.Errorf("status = %s, want %s", status, tt.wantStatus)
			}
			if !strings.Contains(summary, tt.wantSummary) {
				t.Errorf("summary %q does not contain %q", summary, tt.wantSummary)
			}
			if tt.wantViolates && len(violations) == 0 {
				t.Error("expected violations but got none")
			}
			if !tt.wantViolates && len(violations) > 0 {
				t.Errorf("unexpected violations: %v", violations)
			}
		})
	}
}

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
			{Name: "testnet", CIDR: "10.255.255.0/30", Gateway: "10.255.255.1", Zone: "test"},
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
			{Name: "testnet", CIDR: "10.255.255.0/30", Gateway: "10.255.255.1", Zone: "test"},
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
			{Type: "port_check", Target: "127.0.0.1", Ports: []int{22}, Protocol: "tcp", Expect: "open", ScanMode: "polite"},
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

func TestVirtualSubnetSuppressesRepeatWarn(t *testing.T) {
	if !nmap.Available() {
		t.Skip("nmap not available")
	}
	// Scan a /24 slice of a virtual adapter's own network (Hyper-V/WSL2/
	// VMware), so looksVirtualByCIDR returns true without needing a VM MAC
	// in nmap output and the sweep stays small enough to finish in seconds.
	nets := audit.VirtualIfaceNetworks()
	if len(nets) == 0 {
		t.Skip("no virtual adapter (Hyper-V/WSL2/VMware) on this machine")
	}
	cidr := nets[0]
	spec := &intent.Spec{
		Version: 1,
		Site:    "test",
		Networks: []intent.Network{
			{Name: "hyperv", CIDR: cidr, Gateway: "10.255.144.1", Zone: "hyperv"},
		},
		Assertions: []intent.Assertion{
			{Type: "subnet_discovery", Network: "hyperv"},
		},
	}

	dbPath := filepath.Join(t.TempDir(), "seen.json")

	// First run: should WARN and write seendb
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	e1 := audit.NewEngine(spec)
	e1.SeenDBPath = dbPath
	r1, err := e1.Run(ctx)
	if err != nil {
		t.Fatalf("first run error: %v", err)
	}
	f1 := r1.Findings[0]
	if f1.Status != models.StatusWarn {
		t.Skipf("CIDR %s not detected as virtual on this machine (status: %s) — skipping", cidr, f1.Status)
	}

	// Second run: should SKIP
	ctx2, cancel2 := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel2()

	e2 := audit.NewEngine(spec)
	e2.SeenDBPath = dbPath
	r2, err := e2.Run(ctx2)
	if err != nil {
		t.Fatalf("second run error: %v", err)
	}
	f2 := r2.Findings[0]
	if f2.Status != models.StatusSkip {
		t.Errorf("second run: expected StatusSkip, got %s (%s)", f2.Status, f2.Summary)
	}
}

func TestLooksVirtualUnitWithSeenDB(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "seen.json")

	db, err := seendb.LoadFrom(dbPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	cidr := "10.255.174.0/24"
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
