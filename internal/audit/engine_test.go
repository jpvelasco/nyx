package audit_test

import (
	"context"
	"testing"
	"time"

	"github.com/velasco-jp/nyx/internal/audit"
	"github.com/velasco-jp/nyx/internal/intent"
	"github.com/velasco-jp/nyx/internal/models"
)

func TestDiscoveryWarnPreservedWhenZeroHostsWithinBounds(t *testing.T) {
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
