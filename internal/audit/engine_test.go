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
