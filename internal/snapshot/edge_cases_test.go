package snapshot

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jpvelasco/nyx/internal/models"
)

// --- Dir() error: UserHomeDir fails ---

func TestDir_HomeDirError(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	_, err := Dir()
	if err == nil {
		t.Error("expected error when HOME/USERPROFILE unset")
	}
}

// --- BaselinePath() error: Dir() fails ---

func TestBaselinePath_DirError(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	path := BaselinePath()
	if path != "" {
		t.Errorf("expected empty path on Dir error, got %q", path)
	}
}

// --- SetBaseline() error: Dir() fails ---

func TestSetBaseline_DirError(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	report := makeReport(models.StatusPass, 1, 0, 0, 0)
	err := SetBaseline("test.spec", report)
	if err == nil {
		t.Error("expected error when baseline path is empty")
	}
}

// --- SetBaseline() serialization error: Snapshot with unserializable data ---

func TestSetBaseline_SerializationError(t *testing.T) {
	// Create a report with a channel in Findings to make JSON serialization fail
	report := &models.AuditReport{
		Audit:   "test-audit",
		Status:  models.StatusPass,
		Summary: models.ReportSummary{Pass: 1},
		Findings: []models.CheckResult{
			{
				CheckType: "subnet_discovery",
				Target:    "10.0.0.0/24",
				Status:    models.StatusPass,
				Observed:  map[string]interface{}{"bad": make(chan int)},
			},
		},
	}

	err := SetBaseline("test.spec", report)
	if err == nil {
		t.Error("expected serialization error")
	}
}

// --- LoadBaseline() error: Dir() fails ---

func TestLoadBaseline_DirError(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	_, err := LoadBaseline()
	if err == nil {
		t.Error("expected error when HOME/USERPROFILE unset")
	}
}

// --- LoadBaseline() error: invalid JSON in baseline file ---

func TestLoadBaseline_InvalidJSON(t *testing.T) {
	// Ensure we have a baseline file with invalid content
	err := SetBaseline("valid.spec", makeReport(models.StatusPass, 1, 0, 0, 0))
	if err != nil {
		t.Fatalf("SetBaseline failed: %v", err)
	}

	// Overwrite with invalid JSON
	bp := BaselinePath()
	if bp == "" {
		t.Skip("cannot determine baseline path")
	}
	if err := os.WriteFile(bp, []byte("not valid json {{{"), 0600); err != nil {
		t.Fatalf("could not write invalid baseline: %v", err)
	}

	_, err = LoadBaseline()
	if err == nil {
		t.Error("expected error for invalid JSON baseline")
	}
	if !strings.Contains(err.Error(), "parsing baseline") {
		t.Errorf("expected 'parsing baseline' error, got: %v", err)
	}
}

// --- LoadBaseline() error: file read error (not IsNotExist) ---

func TestLoadBaseline_ReadError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file permission error test skipped on Windows")
	}
	// Ensure baseline exists first
	err := SetBaseline("test.spec", makeReport(models.StatusPass, 1, 0, 0, 0))
	if err != nil {
		t.Fatalf("SetBaseline failed: %v", err)
	}

	bp := BaselinePath()
	if bp == "" {
		t.Skip("cannot determine baseline path")
	}
	// Remove read permission
	if err := os.Chmod(bp, 0000); err != nil {
		t.Skipf("could not chmod baseline: %v", err)
	}
	t.Cleanup(func() { os.Chmod(bp, 0600) })

	_, err = LoadBaseline()
	if err == nil {
		t.Error("expected read error for unreadable baseline")
	}
}

// --- Save() error: serialization fails ---

func TestSave_SerializationError(t *testing.T) {
	report := &models.AuditReport{
		Audit:   "test-audit",
		Status:  models.StatusPass,
		Summary: models.ReportSummary{Pass: 1},
		Findings: []models.CheckResult{
			{
				CheckType: "subnet_discovery",
				Target:    "10.0.0.0/24",
				Status:    models.StatusPass,
				Observed:  map[string]interface{}{"bad": make(chan int)},
			},
		},
	}

	_, err := Save("test.spec", report)
	if err == nil {
		t.Error("expected serialization error")
	}
}

// --- Save() error: write fails ---

func TestSave_WriteError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("write permission error test skipped on Windows")
	}
	// Make the snapshots directory read-only
	tmpDir := t.TempDir()
	snapDir := filepath.Join(tmpDir, ".nyx", "snapshots")
	os.MkdirAll(snapDir, 0700)
	// Make the directory read-only so WriteFile fails
	os.Chmod(snapDir, 0444)
	t.Cleanup(func() { os.Chmod(snapDir, 0700) })

	t.Setenv("HOME", tmpDir)
	t.Setenv("USERPROFILE", tmpDir)

	_, err := Save("test.spec", makeReport(models.StatusPass, 1, 0, 0, 0))
	if err == nil {
		t.Error("expected write error for read-only directory")
	}
}

// --- LoadSnapshot() error: read fails ---

func TestLoadSnapshot_ReadError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file permission error test skipped on Windows")
	}
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "snapshot.json")
	if err := os.WriteFile(path, []byte("{}"), 0000); err != nil {
		t.Fatalf("could not create file: %v", err)
	}
	t.Cleanup(func() { os.Chmod(path, 0600) })

	_, err := LoadSnapshot(path)
	if err == nil {
		t.Error("expected read error for unreadable file")
	}
}

// --- ListSnapshots() error: read dir fails (not a directory) ---

func TestListSnapshots_NotADirectory(t *testing.T) {
	tmpDir := t.TempDir()
	// Create a FILE where the snapshots dir would be
	snapDir := filepath.Join(tmpDir, ".nyx", "snapshots")
	os.MkdirAll(filepath.Dir(snapDir), 0700)
	if err := os.WriteFile(snapDir, []byte("blocker"), 0600); err != nil {
		t.Fatalf("could not create blocker file: %v", err)
	}
	t.Setenv("HOME", tmpDir)
	t.Setenv("USERPROFILE", tmpDir)

	_, err := ListSnapshots()
	if err == nil {
		t.Error("expected error when snapshots path is a file")
	}
}

// --- rotate() error: os.Remove fails on nonexistent path ---

func TestRotate_RemoveError(t *testing.T) {
	// Create a real snapshot so ListSnapshots returns entries
	report := makeReport(models.StatusPass, 1, 0, 0, 0)
	path, err := Save("test.spec", report)
	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}
	t.Cleanup(func() { os.Remove(path) })

	// Call rotate with a nonexistent dir — Remove will fail on the non-existent path
	// but the function ignores the error (best-effort)
	rotate("/nonexistent/path/that/does/not/exist", 0)
}

// --- rotate() error: ListSnapshots fails ---

func TestRotate_ListSnapshotsError(t *testing.T) {
	// Create a snapshot first (with valid HOME)
	report := makeReport(models.StatusPass, 1, 0, 0, 0)
	path, err := Save("test.spec", report)
	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}
	t.Cleanup(func() { os.Remove(path) })

	// Now call rotate with HOME unset — ListSnapshots inside rotate will fail
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	rotate("/nonexistent", 0)
}

// --- ComputeDrift: new warning (Warn status check not in baseline) ---

func TestComputeDrift_TotallyNewWarning(t *testing.T) {
	base := &Snapshot{
		RunAt:   parseTime("2025-01-01"),
		Status:  models.StatusPass,
		Summary: models.ReportSummary{Pass: 1, Warn: 0, Fail: 0},
		Findings: []models.CheckResult{
			{CheckType: "subnet_discovery", Target: "10.0.0.0/24", Status: models.StatusPass,
				Expected: map[string]interface{}{"expect_hosts_min": 1}},
		},
	}
	current := &Snapshot{
		RunAt:   parseTime("2025-01-02"),
		Status:  models.StatusWarn,
		Summary: models.ReportSummary{Pass: 1, Warn: 1, Fail: 0},
		Findings: []models.CheckResult{
			{CheckType: "subnet_discovery", Target: "10.0.0.0/24", Status: models.StatusPass,
				Expected: map[string]interface{}{"expect_hosts_min": 1}},
			{CheckType: "dns_check", Target: "new-target", Status: models.StatusWarn,
				Expected: map[string]interface{}{"query": "example.com"}},
		},
	}

	dr := ComputeDrift(base, current)
	if dr == nil {
		t.Fatal("expected non-nil drift result")
	}
	if len(dr.NewWarnings) != 1 {
		t.Errorf("expected 1 new warning, got %d", len(dr.NewWarnings))
	}
	if len(dr.NewWarnings) > 0 && dr.NewWarnings[0].CheckType != "dns_check" {
		t.Errorf("expected new warning for dns_check, got %q", dr.NewWarnings[0].CheckType)
	}
}

// --- ComputeDrift: degraded pass→fail (already in existing test) ---
// This covers the statusWorsened + cur.Status == StatusFail path

// --- ComputeDrift: improvement on non-fail status ---

func TestComputeDrift_ImprovedFromWarn(t *testing.T) {
	base := &Snapshot{
		RunAt:   parseTime("2025-01-01"),
		Status:  models.StatusWarn,
		Summary: models.ReportSummary{Pass: 0, Warn: 1, Fail: 0},
		Findings: []models.CheckResult{
			{CheckType: "port_check", Target: "10.0.0.1", Status: models.StatusWarn,
				Expected: map[string]interface{}{"ports": 443}},
		},
	}
	current := &Snapshot{
		RunAt:   parseTime("2025-01-02"),
		Status:  models.StatusPass,
		Summary: models.ReportSummary{Pass: 1, Warn: 0, Fail: 0},
		Findings: []models.CheckResult{
			{CheckType: "port_check", Target: "10.0.0.1", Status: models.StatusPass,
				Expected: map[string]interface{}{"ports": 443}},
		},
	}

	dr := ComputeDrift(base, current)
	if dr == nil {
		t.Fatal("expected non-nil drift result")
	}
	if len(dr.Improved) != 1 {
		t.Errorf("expected 1 improved check, got %d", len(dr.Improved))
	}
	if len(dr.FixedFailures) != 0 {
		t.Errorf("expected 0 fixed failures (base was warn not fail), got %d", len(dr.FixedFailures))
	}
}

func parseTime(s string) time.Time {
	t, _ := time.Parse("2006-01-02", s)
	return t
}
