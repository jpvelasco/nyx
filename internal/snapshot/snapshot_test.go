package snapshot

import (
	"testing"
	"time"

	"github.com/jpvelasco/nyx/internal/models"
)

// TestNewSnapshot tests creating a new snapshot
func TestNewSnapshot(t *testing.T) {
	report := &models.AuditReport{
		Audit:   "test",
		Status:  models.StatusPass,
		Summary: models.ReportSummary{},
		Runner:  models.RunnerContext{},
	}

	snapshot := NewSnapshot("test.spec", report)
	if snapshot == nil {
		t.Fatal("expected non-nil snapshot")
	}
}

// TestLoadBaseline tests loading baseline from file
func TestLoadBaseline(t *testing.T) {
	baseline, err := LoadBaseline()
	if err != nil {
		t.Skipf("no baseline found (may be expected): %v", err)
		return
	}

	if baseline == nil {
		t.Error("expected non-nil baseline")
	}
}

// TestComputeDrift tests computing drift between snapshots
func TestComputeDrift(t *testing.T) {
	snapshot := &Snapshot{
		SpecPath: "test.spec",
		RunAt:    time.Now(),
		Runner:   models.RunnerContext{},
	}

	drift := ComputeDrift(snapshot, snapshot)
	if drift == nil {
		t.Fatal("expected non-nil drift result")
	}
}

// TestStatusWorsened tests status worsened detection
func TestStatusWorsened(t *testing.T) {
	tests := []struct {
		name     string
		old      models.Status
		new      models.Status
		expected bool
	}{
		{"pass_to_fail", models.StatusPass, models.StatusFail, true},
		{"fail_to_pass", models.StatusFail, models.StatusPass, false},
		{"pass_to_warn", models.StatusPass, models.StatusWarn, true},
		{"warn_to_pass", models.StatusWarn, models.StatusPass, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := statusWorsened(tt.old, tt.new)
			if result != tt.expected {
				t.Errorf("statusWorsened(%v, %v) = %v; want %v", tt.old, tt.new, result, tt.expected)
			}
		})
	}
}

// TestStatusImproved tests status improved detection
func TestStatusImproved(t *testing.T) {
	tests := []struct {
		name     string
		old      models.Status
		new      models.Status
		expected bool
	}{
		{"fail_to_pass", models.StatusFail, models.StatusPass, true},
		{"pass_to_fail", models.StatusPass, models.StatusFail, false},
		{"warn_to_pass", models.StatusWarn, models.StatusPass, true},
		{"pass_to_warn", models.StatusPass, models.StatusWarn, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := statusImproved(tt.old, tt.new)
			if result != tt.expected {
				t.Errorf("statusImproved(%v, %v) = %v; want %v", tt.old, tt.new, result, tt.expected)
			}
		})
	}
}

// TestComputeNetChange tests computing net change between snapshots
func TestComputeNetChange(t *testing.T) {
	baseline := &models.ReportSummary{Pass: 10, Fail: 0, Warn: 0, Error: 0, Skip: 0}
	current := &models.ReportSummary{Pass: 10, Fail: 0, Warn: 0, Error: 0, Skip: 0}

	result := computeNetChange(baseline, current)
	if result != "no change" {
		t.Errorf("computeNetChange(identical summaries) = %q; want \"no change\"", result)
	}
}
