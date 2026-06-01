package snapshot

import (
	"os"
	"testing"
	"time"

	"github.com/jpvelasco/nyx/internal/models"
)

func TestNewSnapshot(t *testing.T) {
	report := &models.AuditReport{
		Audit:  "test-site",
		Status: models.StatusPass,
		Summary: models.ReportSummary{
			Pass: 3,
			Fail: 1,
		},
		Findings: []models.CheckResult{
			{
				CheckType: "subnet_discovery",
				Target:    "192.168.1.0/24",
				Status:    models.StatusPass,
				Summary:   "3 hosts discovered",
			},
		},
	}

	snap := NewSnapshot("test.yaml", report)
	if snap.SpecPath != "test.yaml" {
		t.Errorf("expected spec_path test.yaml, got %s", snap.SpecPath)
	}
	if snap.Status != models.StatusPass {
		t.Errorf("expected status pass, got %s", snap.Status)
	}
	if len(snap.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(snap.Findings))
	}
}

func TestSnapshotDir(t *testing.T) {
	dir, err := SnapshotDir()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dir == "" {
		t.Fatal("expected non-empty snapshot directory")
	}
	// Verify directory exists
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Fatal("snapshot directory does not exist")
	}
}

func TestSaveAndList(t *testing.T) {
	// Clean up after test
	dir, err := SnapshotDir()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	report := &models.AuditReport{
		Audit:  "test-site",
		Status: models.StatusPass,
		Summary: models.ReportSummary{
			Pass: 2,
			Fail: 1,
		},
	}

	path, err := Save("test.yaml", report)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if path == "" {
		t.Fatal("expected non-empty snapshot path")
	}

	snaps, err := ListSnapshots()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(snaps) == 0 {
		t.Fatal("expected at least 1 snapshot")
	}
}

func TestSetBaselineAndLoad(t *testing.T) {
	// Clean up after test
	dir, err := SnapshotDir()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	report := &models.AuditReport{
		Audit:  "test-site",
		Status: models.StatusFail,
		Summary: models.ReportSummary{
			Pass: 1,
			Fail: 3,
		},
	}

	if err := SetBaseline("test.yaml", report); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	baseline, err := LoadBaseline()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if baseline.Status != models.StatusFail {
		t.Errorf("expected status fail, got %s", baseline.Status)
	}
	if baseline.Summary.Fail != 3 {
		t.Errorf("expected 3 failures, got %d", baseline.Summary.Fail)
	}
}

func TestComputeDrift_NoDrift(t *testing.T) {
	baseline := &Snapshot{
		RunAt:  time.Now().Add(-1 * time.Hour),
		Status: models.StatusPass,
		Summary: models.ReportSummary{
			Pass: 3,
			Fail: 0,
		},
		Findings: []models.CheckResult{
			{CheckType: "subnet_discovery", Target: "192.168.1.0/24", Status: models.StatusPass, Summary: "3 hosts"},
		},
	}

	current := &Snapshot{
		RunAt:  time.Now(),
		Status: models.StatusPass,
		Summary: models.ReportSummary{
			Pass: 3,
			Fail: 0,
		},
		Findings: []models.CheckResult{
			{CheckType: "subnet_discovery", Target: "192.168.1.0/24", Status: models.StatusPass, Summary: "3 hosts"},
		},
	}

	drift := ComputeDrift(baseline, current)
	if len(drift.NewFailures) > 0 {
		t.Errorf("expected no new failures, got %d", len(drift.NewFailures))
	}
	if len(drift.Degraded) > 0 {
		t.Errorf("expected no degraded, got %d", len(drift.Degraded))
	}
}

func TestComputeDrift_NewFailures(t *testing.T) {
	baseline := &Snapshot{
		RunAt:  time.Now().Add(-1 * time.Hour),
		Status: models.StatusPass,
		Summary: models.ReportSummary{
			Pass: 3,
			Fail: 0,
		},
		Findings: []models.CheckResult{
			{CheckType: "subnet_discovery", Target: "192.168.1.0/24", Status: models.StatusPass, Summary: "3 hosts"},
		},
	}

	current := &Snapshot{
		RunAt:  time.Now(),
		Status: models.StatusFail,
		Summary: models.ReportSummary{
			Pass: 2,
			Fail: 1,
		},
		Findings: []models.CheckResult{
			{CheckType: "subnet_discovery", Target: "192.168.1.0/24", Status: models.StatusPass, Summary: "3 hosts"},
			{CheckType: "isolation", Target: "iot->clients", Status: models.StatusFail, Summary: "isolation breach detected"},
		},
	}

	drift := ComputeDrift(baseline, current)
	if len(drift.NewFailures) != 1 {
		t.Errorf("expected 1 new failure, got %d", len(drift.NewFailures))
	}
	if drift.Summary.NetChange == "" {
		t.Error("expected non-empty net change")
	}
}

func TestComputeDrift_FixedFailures(t *testing.T) {
	baseline := &Snapshot{
		RunAt:  time.Now().Add(-1 * time.Hour),
		Status: models.StatusFail,
		Summary: models.ReportSummary{
			Pass: 2,
			Fail: 1,
		},
		Findings: []models.CheckResult{
			{CheckType: "subnet_discovery", Target: "192.168.1.0/24", Status: models.StatusPass, Summary: "3 hosts"},
			{CheckType: "isolation", Target: "iot->clients", Status: models.StatusFail, Summary: "isolation breach detected"},
		},
	}

	current := &Snapshot{
		RunAt:  time.Now(),
		Status: models.StatusPass,
		Summary: models.ReportSummary{
			Pass: 3,
			Fail: 0,
		},
		Findings: []models.CheckResult{
			{CheckType: "subnet_discovery", Target: "192.168.1.0/24", Status: models.StatusPass, Summary: "3 hosts"},
			{CheckType: "isolation", Target: "iot->clients", Status: models.StatusPass, Summary: "isolation verified"},
		},
	}

	drift := ComputeDrift(baseline, current)
	if len(drift.FixedFailures) != 1 {
		t.Errorf("expected 1 fixed failure, got %d", len(drift.FixedFailures))
	}
}

func TestComputeDrift_Degraded(t *testing.T) {
	baseline := &Snapshot{
		RunAt:  time.Now().Add(-1 * time.Hour),
		Status: models.StatusPass,
		Summary: models.ReportSummary{
			Pass: 3,
			Fail: 0,
		},
		Findings: []models.CheckResult{
			{CheckType: "subnet_discovery", Target: "192.168.1.0/24", Status: models.StatusPass, Summary: "3 hosts"},
		},
	}

	current := &Snapshot{
		RunAt:  time.Now(),
		Status: models.StatusFail,
		Summary: models.ReportSummary{
			Pass: 2,
			Fail: 1,
		},
		Findings: []models.CheckResult{
			{CheckType: "subnet_discovery", Target: "192.168.1.0/24", Status: models.StatusFail, Summary: "only 1 host found"},
		},
	}

	drift := ComputeDrift(baseline, current)
	if len(drift.Degraded) != 1 {
		t.Errorf("expected 1 degraded, got %d", len(drift.Degraded))
	}
}

func TestStatusWorsened(t *testing.T) {
	tests := []struct {
		old  models.Status
		new  models.Status
		want bool
	}{
		{models.StatusPass, models.StatusWarn, true},
		{models.StatusPass, models.StatusFail, true},
		{models.StatusWarn, models.StatusFail, true},
		{models.StatusFail, models.StatusError, true},
		{models.StatusPass, models.StatusPass, false},
		{models.StatusFail, models.StatusPass, false},
		{models.StatusWarn, models.StatusPass, false},
	}

	for _, tt := range tests {
		got := statusWorsened(tt.old, tt.new)
		if got != tt.want {
			t.Errorf("statusWorsened(%s, %s) = %v, want %v", tt.old, tt.new, got, tt.want)
		}
	}
}
