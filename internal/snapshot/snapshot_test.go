package snapshot

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jpvelasco/nyx/internal/models"
)

func TestMain(m *testing.M) {
	// Isolate all snapshot tests from the real ~/.nyx/snapshots directory.
	tmpDir := tempDir()
	_ = os.Setenv("HOME", tmpDir)
	_ = os.Setenv("USERPROFILE", tmpDir)
	code := m.Run()
	_ = os.RemoveAll(tmpDir)
	os.Exit(code)
}

func tempDir() string {
	d, err := os.MkdirTemp("", "nyx-snapshot-test-*")
	if err != nil {
		panic(err)
	}
	return d
}

// =====================================================================
// Helpers
// =====================================================================

func makeReport(status models.Status, pass, fail, warn, errCount int) *models.AuditReport {
	return &models.AuditReport{
		Audit:  "test-audit",
		Status: status,
		Summary: models.ReportSummary{
			Pass:  pass,
			Fail:  fail,
			Warn:  warn,
			Error: errCount,
		},
		Runner: models.RunnerContext{
			LocalIPs: []string{"192.168.1.10"},
			Networks: []string{"lan"},
		},
	}
}

func makeFinding(checkType, target string, status models.Status) models.CheckResult {
	return models.CheckResult{
		Tool:      "nmap",
		CheckType: checkType,
		Runner:    "local",
		Target:    target,
		Status:    status,
		Summary:   checkType + " on " + target,
		Observed:  map[string]interface{}{"hosts": 5},
		Expected:  map[string]interface{}{"expect_hosts_min": 1},
	}
}

// =====================================================================
// Filename
// =====================================================================

func TestFilename(t *testing.T) {
	name := Filename()
	if !strings.HasPrefix(name, "snapshot-") {
		t.Errorf("filename should start with 'snapshot-', got %q", name)
	}
	if !strings.HasSuffix(name, ".json") {
		t.Errorf("filename should end with '.json', got %q", name)
	}

	// Check format: snapshot-YYYYMMDD-HHMMSS.mmm.json
	withoutPrefix := strings.TrimPrefix(name, "snapshot-")
	withoutExt := strings.TrimSuffix(withoutPrefix, ".json")
	_, err := time.Parse("20060102-150405.000", withoutExt)
	if err != nil {
		t.Errorf("filename date portion should parse as 20060102-150405.000, got %q: %v", withoutExt, err)
	}
}

func TestFilenameUniqueness(t *testing.T) {
	// Two filenames generated at different seconds should differ
	name1 := Filename()
	time.Sleep(1 * time.Second)
	name2 := Filename()
	if name1 == name2 {
		t.Errorf("expected unique filenames, got identical: %q", name1)
	}
}

func TestSave_SameMillisecondCollision(t *testing.T) {
	// Freeze the clock so Save must hit the O_EXCL collision-retry path.
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	fixed := time.Date(2025, 6, 1, 14, 0, 0, 0, time.UTC)
	origNow := filenameNow
	filenameNow = func() time.Time { return fixed }
	defer func() { filenameNow = origNow }()

	report := makeReport(models.StatusPass, 1, 0, 0, 0)
	dir, err := Dir()
	if err != nil {
		t.Fatalf("Dir(): %v", err)
	}
	blocked := filepath.Join(dir, "snapshot-20250601-140000.000.json")
	if err := os.WriteFile(blocked, []byte("occupied"), 0600); err != nil {
		t.Fatalf("seeding colliding file: %v", err)
	}

	path, err := Save("test.spec", report)
	if err != nil {
		t.Fatalf("Save() with collision should retry, got error: %v", err)
	}
	if path == blocked {
		t.Errorf("Save must not overwrite the existing snapshot, wrote %s", path)
	}
	// Reading back through the dynamic path is the point of the test: verify
	// Save did not touch the seeded fixture file.
	data, err := os.ReadFile(blocked) // nosemgrep: go.filesystem.rule-fileread
	if err != nil {
		t.Fatalf("original snapshot replaced: %v", err)
	}
	if string(data) != "occupied" {
		t.Errorf("original snapshot content changed: %q", data)
	}
}

func TestSave_FilenameExhaustion(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	fixed := time.Date(2025, 6, 1, 14, 0, 0, 0, time.UTC)
	origNow := filenameNow
	filenameNow = func() time.Time { return fixed }
	defer func() { filenameNow = origNow }()

	report := makeReport(models.StatusPass, 1, 0, 0, 0)
	dir, err := Dir()
	if err != nil {
		t.Fatalf("Dir(): %v", err)
	}
	// Occupy every name the retry loop will attempt: the base and 99 suffixes.
	for i := 0; i < 100; i++ {
		name := "snapshot-20250601-140000.000.json"
		if i > 0 {
			name = fmt.Sprintf("snapshot-20250601-140000.000-%d.json", i)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte("occupied"), 0600); err != nil {
			t.Fatalf("seeding: %v", err)
		}
	}
	if _, err := Save("test.spec", report); err == nil {
		t.Fatal("expected error when every filename attempt is occupied")
	}
}

// =====================================================================
// Dir
// =====================================================================

func TestDir(t *testing.T) {
	dir, err := Dir()
	if err != nil {
		t.Fatalf("Dir() returned error: %v", err)
	}

	// Verify the directory exists
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("snapshot directory does not exist: %v", err)
	}
	if !info.IsDir() {
		t.Error("Dir() should return a directory path")
	}

	// Verify it ends with .nyx/snapshots
	if !strings.HasSuffix(dir, ".nyx"+string(filepath.Separator)+"snapshots") {
		t.Errorf("expected dir to end with '.nyx/snapshots', got %q", dir)
	}
}

// =====================================================================
// Save
// =====================================================================

func TestSave(t *testing.T) {
	report := makeReport(models.StatusPass, 5, 0, 0, 0)
	report.Findings = []models.CheckResult{
		makeFinding("subnet_discovery", "10.0.0.0/24", models.StatusPass),
	}

	path, err := Save("test.spec", report)
	if err != nil {
		t.Fatalf("Save() returned error: %v", err)
	}
	if path == "" {
		t.Fatal("Save() returned empty path")
	}

	// Verify file exists
	data, err := os.ReadFile(path) //nosemgrep: go_filesystem_rule-fileread
	if err != nil {
		t.Fatalf("saved file not readable: %v", err)
	}

	// Verify it parses as a valid snapshot
	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		t.Fatalf("saved file is not valid JSON: %v", err)
	}

	if snap.SpecPath != "test.spec" {
		t.Errorf("expected spec_path 'test.spec', got %q", snap.SpecPath)
	}
	if snap.Status != models.StatusPass {
		t.Errorf("expected status pass, got %q", snap.Status)
	}
	if snap.Summary.Pass != 5 {
		t.Errorf("expected 5 pass, got %d", snap.Summary.Pass)
	}
	if len(snap.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(snap.Findings))
	}

	// Clean up
	t.Cleanup(func() { os.Remove(path) })
}

func TestSaveWithFailures(t *testing.T) {
	report := makeReport(models.StatusFail, 3, 2, 1, 0)
	report.Findings = []models.CheckResult{
		makeFinding("port_check", "10.0.0.1", models.StatusFail),
		makeFinding("dns_check", "example.com", models.StatusPass),
	}

	path, err := Save("fail.spec", report)
	if err != nil {
		t.Fatalf("Save() returned error: %v", err)
	}

	snap, err := LoadSnapshot(path)
	if err != nil {
		t.Fatalf("LoadSnapshot failed: %v", err)
	}
	if snap.Status != models.StatusFail {
		t.Errorf("expected status fail, got %q", snap.Status)
	}
	if snap.Summary.Fail != 2 {
		t.Errorf("expected 2 fail, got %d", snap.Summary.Fail)
	}

	t.Cleanup(func() { os.Remove(path) })
}

func TestSaveWithRecommendations(t *testing.T) {
	report := makeReport(models.StatusFail, 2, 1, 0, 0)
	report.Recommendations = []models.Recommendation{
		{Priority: 1, Category: "network", Title: "Fix subnet", Description: "Add missing network"},
	}

	path, err := Save("rec.spec", report)
	if err != nil {
		t.Fatalf("Save() returned error: %v", err)
	}

	snap, err := LoadSnapshot(path)
	if err != nil {
		t.Fatalf("LoadSnapshot failed: %v", err)
	}
	if len(snap.Recommendations) != 1 {
		t.Errorf("expected 1 recommendation, got %d", len(snap.Recommendations))
	}
	if snap.Recommendations[0].Title != "Fix subnet" {
		t.Errorf("expected recommendation title 'Fix subnet', got %q", snap.Recommendations[0].Title)
	}

	t.Cleanup(func() { os.Remove(path) })
}

// =====================================================================
// BaselinePath
// =====================================================================

func TestBaselinePath(t *testing.T) {
	path := BaselinePath()
	if path == "" {
		t.Fatal("BaselinePath() returned empty string")
	}
	if !strings.HasSuffix(path, "baseline.json") {
		t.Errorf("expected path ending with 'baseline.json', got %q", path)
	}
}

// =====================================================================
// SetBaseline
// =====================================================================

func TestSetBaseline(t *testing.T) {
	report := makeReport(models.StatusPass, 10, 0, 0, 0)
	report.Findings = []models.CheckResult{
		makeFinding("subnet_discovery", "10.0.0.0/24", models.StatusPass),
	}

	err := SetBaseline("baseline.spec", report)
	if err != nil {
		t.Fatalf("SetBaseline() returned error: %v", err)
	}

	// Verify file exists
	bp := BaselinePath()
	data, err := os.ReadFile(bp)
	if err != nil {
		t.Fatalf("baseline file not readable: %v", err)
	}

	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		t.Fatalf("baseline is not valid JSON: %v", err)
	}
	if snap.SpecPath != "baseline.spec" {
		t.Errorf("expected spec_path 'baseline.spec', got %q", snap.SpecPath)
	}
}

func TestSetBaselineMultipleTimes(t *testing.T) {
	// Setting baseline twice should overwrite
	report1 := makeReport(models.StatusPass, 10, 0, 0, 0)
	err := SetBaseline("first.spec", report1)
	if err != nil {
		t.Fatalf("first SetBaseline failed: %v", err)
	}

	report2 := makeReport(models.StatusFail, 5, 5, 0, 0)
	report2.Findings = []models.CheckResult{
		makeFinding("port_check", "10.0.0.1", models.StatusFail),
	}
	err = SetBaseline("second.spec", report2)
	if err != nil {
		t.Fatalf("second SetBaseline failed: %v", err)
	}

	snap, err := LoadBaseline()
	if err != nil {
		t.Fatalf("LoadBaseline failed: %v", err)
	}
	if snap.SpecPath != "second.spec" {
		t.Errorf("expected overwritten baseline spec 'second.spec', got %q", snap.SpecPath)
	}
	if snap.Status != models.StatusFail {
		t.Errorf("expected status fail after overwrite, got %q", snap.Status)
	}
}

// =====================================================================
// LoadBaseline
// =====================================================================

func TestLoadBaseline(t *testing.T) {
	// Ensure there's a baseline to load
	report := makeReport(models.StatusPass, 5, 1, 0, 0)
	report.Findings = []models.CheckResult{
		makeFinding("subnet_discovery", "10.0.0.0/24", models.StatusPass),
	}
	if err := SetBaseline("test.spec", report); err != nil {
		t.Fatalf("SetBaseline failed: %v", err)
	}

	snap, err := LoadBaseline()
	if err != nil {
		t.Fatalf("LoadBaseline() returned error: %v", err)
	}
	if snap == nil {
		t.Fatal("LoadBaseline returned nil")
	}
	if snap.SpecPath != "test.spec" {
		t.Errorf("expected spec_path 'test.spec', got %q", snap.SpecPath)
	}
	if snap.Summary.Pass != 5 {
		t.Errorf("expected 5 pass, got %d", snap.Summary.Pass)
	}
}

func TestLoadBaselineNotFound(t *testing.T) {
	// We can't mock UserHomeDir, so we temporarily rename the baseline
	snapDir, err := Dir()
	if err != nil {
		t.Skip("cannot determine snapshot dir")
	}
	bp := filepath.Join(snapDir, "baseline.json")

	// Check if baseline exists
	_, statErr := os.Stat(bp)
	hadBaseline := !os.IsNotExist(statErr)

	if hadBaseline {
		// Back up and remove
		backup := filepath.Join(snapDir, "baseline.json.bak")
		if err := os.Rename(bp, backup); err != nil {
			t.Skipf("could not rename baseline: %v", err)
		}
		t.Cleanup(func() { os.Rename(backup, bp) })
	}

	_, err = LoadBaseline()
	if err == nil {
		t.Error("expected error when baseline not found")
	}
	if !strings.Contains(err.Error(), "no baseline snapshot found") {
		t.Errorf("expected 'no baseline snapshot found' in error, got: %v", err)
	}
}

// =====================================================================
// LoadSnapshot
// =====================================================================

func TestLoadSnapshot_Valid(t *testing.T) {
	tmpDir := t.TempDir()

	snap := &Snapshot{
		SpecPath: "test.spec",
		RunAt:    time.Date(2025, 6, 15, 10, 30, 0, 0, time.UTC),
		Status:   models.StatusPass,
		Summary:  models.ReportSummary{Pass: 3, Fail: 1},
		Findings: []models.CheckResult{
			{CheckType: "subnet_discovery", Target: "10.0.0.0/24", Status: models.StatusPass},
		},
	}

	data, _ := json.MarshalIndent(snap, "", "  ")
	path := filepath.Join(tmpDir, "snapshot-test.json")
	os.WriteFile(path, data, 0600) //nolint:errcheck,gosec

	loaded, err := LoadSnapshot(path)
	if err != nil {
		t.Fatalf("LoadSnapshot() returned error: %v", err)
	}
	if loaded.SpecPath != "test.spec" {
		t.Errorf("expected spec_path 'test.spec', got %q", loaded.SpecPath)
	}
	if loaded.Status != models.StatusPass {
		t.Errorf("expected status pass, got %q", loaded.Status)
	}
	if loaded.Summary.Pass != 3 {
		t.Errorf("expected 3 pass, got %d", loaded.Summary.Pass)
	}
	if !loaded.RunAt.Equal(time.Date(2025, 6, 15, 10, 30, 0, 0, time.UTC)) {
		t.Errorf("expected run_at 2025-06-15T10:30:00Z, got %v", loaded.RunAt)
	}
}

func TestLoadSnapshot_MissingFile(t *testing.T) {
	_, err := LoadSnapshot("/nonexistent/path/snapshot.json")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadSnapshot_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "bad.json")
	os.WriteFile(path, []byte("not json at all"), 0600) //nolint:errcheck,gosec

	_, err := LoadSnapshot(path)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
	if !strings.Contains(err.Error(), "parsing snapshot") {
		t.Errorf("expected 'parsing snapshot' in error, got: %v", err)
	}
}

// =====================================================================
// ListSnapshots
// =====================================================================

func TestListSnapshots(t *testing.T) {
	// Save a few snapshots (one per second to ensure unique filenames)
	savedPaths := make([]string, 3)
	for i := 0; i < 3; i++ {
		report := makeReport(models.StatusPass, 5, 0, 0, 0)
		var saveErr error
		savedPaths[i], saveErr = Save("test.spec", report)
		if saveErr != nil {
			t.Fatalf("Save() error: %v", saveErr)
		}
		t.Cleanup(func() { os.Remove(savedPaths[i]) })
		if i < 2 {
			time.Sleep(1100 * time.Millisecond)
		}
	}

	list, err := ListSnapshots()
	if err != nil {
		t.Fatalf("ListSnapshots() error: %v", err)
	}

	// Should have at least our 3
	if len(list) < 3 {
		t.Errorf("expected at least 3 snapshots, got %d", len(list))
	}

	// Verify baseline.json is excluded
	for _, name := range list {
		if name == "baseline.json" {
			t.Error("baseline.json should be excluded from ListSnapshots")
		}
	}

	// Verify sorted (oldest first)
	if len(list) >= 2 {
		if list[0] > list[1] {
			t.Errorf("snapshots should be sorted oldest first, got %q before %q", list[0], list[1])
		}
	}
}

func TestListSnapshots_ExcludesNonJSON(t *testing.T) {
	dir, err := Dir()
	if err != nil {
		t.Skip("cannot determine snapshot dir")
	}

	// Create a non-JSON file in the snapshots dir
	nonJSON := filepath.Join(dir, "notes.txt")
	os.WriteFile(nonJSON, []byte("some notes"), 0600) //nolint:errcheck,gosec
	t.Cleanup(func() { os.Remove(nonJSON) })

	list, err := ListSnapshots()
	if err != nil {
		t.Fatalf("ListSnapshots() error: %v", err)
	}

	for _, name := range list {
		if name == "notes.txt" {
			t.Error("non-JSON file should be excluded from ListSnapshots")
		}
	}
}

// =====================================================================
// Rotate
// =====================================================================

// rotate() calls ListSnapshots() internally, which reads from the real
// snapshots directory via Dir(). We test it by writing to the real dir
// and cleaning up afterwards.

func TestRotate_NoRotationNeeded(t *testing.T) {
	snapDir, err := Dir()
	if err != nil {
		t.Skipf("cannot determine snapshot dir: %v", err)
	}

	// Create 5 test snapshots
	testFiles := make([]string, 5)
	for i := 0; i < 5; i++ {
		name := fmt.Sprintf("snapshot-rot-test-%02d.json", i)
		testFiles[i] = filepath.Join(snapDir, name)
		os.WriteFile(testFiles[i], []byte("{}"), 0600) //nolint:errcheck,gosec
	}
	t.Cleanup(func() {
		for _, f := range testFiles {
			os.Remove(f)
		}
	})

	// Count snapshots before rotation
	before, _ := ListSnapshots()
	beforeCount := 0
	for _, n := range before {
		if strings.Contains(n, "rot-test-") {
			beforeCount++
		}
	}

	rotate(snapDir, 50)

	// All 5 test snapshots should still exist
	after, _ := ListSnapshots()
	afterCount := 0
	for _, n := range after {
		if strings.Contains(n, "rot-test-") {
			afterCount++
		}
	}
	if afterCount != beforeCount {
		t.Errorf("expected %d test snapshots unchanged, got %d", beforeCount, afterCount)
	}
}

func TestRotate_ExceedsLimit(t *testing.T) {
	snapDir, err := Dir()
	if err != nil {
		t.Skipf("cannot determine snapshot dir: %v", err)
	}

	// Create 10 test snapshots
	testFiles := make([]string, 10)
	for i := 0; i < 10; i++ {
		name := fmt.Sprintf("snapshot-rot-exceed-%02d.json", i)
		testFiles[i] = filepath.Join(snapDir, name)
		os.WriteFile(testFiles[i], []byte("{}"), 0600) //nolint:errcheck,gosec
	}
	t.Cleanup(func() {
		for _, f := range testFiles {
			os.Remove(f)
		}
	})

	// Count existing test snapshots before rotation
	beforeList, _ := ListSnapshots()
	beforeCount := 0
	for _, n := range beforeList {
		if strings.Contains(n, "rot-exceed-") {
			beforeCount++
		}
	}
	// We need to remove enough to get down to 3 total test snapshots
	// Since rotate removes oldest first (alphabetically sorted), we verify
	// that after rotation the test snapshot count is <= 3

	// Use a limit that accounts for other snapshots in the dir
	otherCount := len(beforeList) - beforeCount
	limit := otherCount + 3

	rotate(snapDir, limit)

	afterList, _ := ListSnapshots()
	afterCount := 0
	for _, n := range afterList {
		if strings.Contains(n, "rot-exceed-") {
			afterCount++
		}
	}
	if afterCount > 3 {
		t.Errorf("expected at most 3 test snapshots after rotation, got %d", afterCount)
	}
}

func TestRotate_ExactLimit(t *testing.T) {
	snapDir, err := Dir()
	if err != nil {
		t.Skipf("cannot determine snapshot dir: %v", err)
	}

	// Create 2 test snapshots
	testFiles := []string{
		filepath.Join(snapDir, "snapshot-rot-exact-01.json"),
		filepath.Join(snapDir, "snapshot-rot-exact-02.json"),
	}
	for _, f := range testFiles {
		os.WriteFile(f, []byte("{}"), 0600) //nolint:errcheck,gosec
	}
	t.Cleanup(func() {
		for _, f := range testFiles {
			os.Remove(f)
		}
	})

	// Count existing test snapshots
	beforeList, _ := ListSnapshots()
	beforeCount := 0
	for _, n := range beforeList {
		if strings.Contains(n, "rot-exact-") {
			beforeCount++
		}
	}

	// Set limit to total count (no rotation needed)
	rotate(snapDir, len(beforeList))

	afterList, _ := ListSnapshots()
	afterCount := 0
	for _, n := range afterList {
		if strings.Contains(n, "rot-exact-") {
			afterCount++
		}
	}
	if afterCount != beforeCount {
		t.Errorf("expected %d test snapshots unchanged at exact limit, got %d", beforeCount, afterCount)
	}
}

func TestRotate_RemovesOldestFirst(t *testing.T) {
	snapDir, err := Dir()
	if err != nil {
		t.Skipf("cannot determine snapshot dir: %v", err)
	}

	// Create 6 test snapshots with names that sort first (oldest)
	// Using "aaaa" prefix to ensure they sort before existing snapshots
	testFiles := make([]string, 6)
	for i := 1; i <= 6; i++ {
		name := fmt.Sprintf("snapshot-aaaa%02d.json", i)
		testFiles[i-1] = filepath.Join(snapDir, name)
		os.WriteFile(testFiles[i-1], []byte("{}"), 0600) //nolint:errcheck,gosec
	}
	t.Cleanup(func() {
		for _, f := range testFiles {
			os.Remove(f)
		}
	})

	// Count all snapshots before rotation
	beforeList, _ := ListSnapshots()
	totalBefore := len(beforeList)
	// Limit to total-2, so 2 should be removed
	rotate(snapDir, totalBefore-2)

	afterList, _ := ListSnapshots()
	totalAfter := len(afterList)

	if totalAfter != totalBefore-2 {
		t.Errorf("expected %d snapshots after rotation, got %d (had %d before)", totalBefore-2, totalAfter, totalBefore)
	}

	// The 2 removed should be the alphabetically first (oldest)
	// Our aaaa01 and aaaa02 should be gone
	remaining := make([]string, 0)
	for _, n := range afterList {
		if strings.Contains(n, "aaaa") {
			remaining = append(remaining, n)
		}
	}

	// Oldest two (aaaa01, aaaa02) should be removed
	for _, name := range remaining {
		if strings.Contains(name, "aaaa01") || strings.Contains(name, "aaaa02") {
			t.Errorf("oldest snapshot should have been removed, found: %s", name)
		}
	}
}

func TestRotate_WithNonSnapshotFiles(t *testing.T) {
	snapDir, err := Dir()
	if err != nil {
		t.Skipf("cannot determine snapshot dir: %v", err)
	}

	// Create a non-snapshot file to verify it's not touched
	nonSnapFile := filepath.Join(snapDir, "rot-test-notes.txt")
	os.WriteFile(nonSnapFile, []byte("test notes"), 0600) //nolint:errcheck,gosec
	t.Cleanup(func() { os.Remove(nonSnapFile) })

	// Count snapshots before creating test files
	beforeList, _ := ListSnapshots()
	beforeCount := len(beforeList)

	// Create 5 test snapshot files
	testFiles := make([]string, 5)
	for i := 0; i < 5; i++ {
		name := fmt.Sprintf("snapshot-bbbb%02d.json", i)
		testFiles[i] = filepath.Join(snapDir, name)
		os.WriteFile(testFiles[i], []byte("{}"), 0600) //nolint:errcheck,gosec
	}
	t.Cleanup(func() {
		for _, f := range testFiles {
			os.Remove(f)
		}
	})

	// Set limit to the count before we added test files — this forces rotation
	// to remove all 5 test files (they're the oldest alphabetically since bbbb sorts first)
	rotate(snapDir, beforeCount)

	// Verify non-snapshot file still exists
	if _, err := os.Stat(nonSnapFile); os.IsNotExist(err) {
		t.Error("non-JSON file should not be removed by rotation")
	}

	// All test snapshots should have been removed
	afterList, _ := ListSnapshots()
	afterCount := 0
	for _, n := range afterList {
		if strings.Contains(n, "bbbb") {
			afterCount++
		}
	}
	if afterCount != 0 {
		t.Errorf("expected 0 test snapshots after rotation, got %d", afterCount)
	}
}

// =====================================================================
// ComputeDrift
// =====================================================================

func TestComputeDrift_NoChange(t *testing.T) {
	finding := models.CheckResult{
		CheckType: "subnet_discovery", Target: "10.0.0.0/24",
		Status: models.StatusPass, Summary: "ok",
		Expected: map[string]interface{}{"expect_hosts_min": 1},
	}

	base := &Snapshot{
		RunAt:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		Status:   models.StatusPass,
		Summary:  models.ReportSummary{Pass: 1, Fail: 0, Warn: 0},
		Findings: []models.CheckResult{finding},
	}
	current := &Snapshot{
		RunAt:    time.Date(2025, 1, 2, 0, 0, 0, 0, time.UTC),
		Status:   models.StatusPass,
		Summary:  models.ReportSummary{Pass: 1, Fail: 0, Warn: 0},
		Findings: []models.CheckResult{finding},
	}

	dr := ComputeDrift(base, current)
	if dr == nil {
		t.Fatal("expected non-nil drift result")
	}
	if len(dr.NewFailures) != 0 {
		t.Errorf("expected 0 new failures, got %d", len(dr.NewFailures))
	}
	if len(dr.FixedFailures) != 0 {
		t.Errorf("expected 0 fixed failures, got %d", len(dr.FixedFailures))
	}
	if dr.Summary.NetChange != "no change" {
		t.Errorf("expected 'no change', got %q", dr.Summary.NetChange)
	}
}

func TestComputeDrift_PassToSkipIsNotImprovement(t *testing.T) {
	// A check that was passing and is now skipped did not improve — it no
	// longer ran at all. Regression for the skip-rank bug (#164) that listed
	// pass→skip under Improved.
	base := &Snapshot{
		RunAt:   time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		Status:  models.StatusPass,
		Summary: models.ReportSummary{Pass: 1, Fail: 0, Warn: 0},
		Findings: []models.CheckResult{
			{CheckType: "port_check", Target: "10.0.0.5", Status: models.StatusPass,
				Expected: map[string]interface{}{"ports": "[22]"}},
		},
	}
	current := &Snapshot{
		RunAt:   time.Date(2025, 1, 2, 0, 0, 0, 0, time.UTC),
		Status:  models.StatusPass,
		Summary: models.ReportSummary{Pass: 0, Fail: 0, Warn: 0},
		Findings: []models.CheckResult{
			{CheckType: "port_check", Target: "10.0.0.5", Status: models.StatusSkip,
				Expected: map[string]interface{}{"ports": "[22]"}},
		},
	}

	dr := ComputeDrift(base, current)
	if dr == nil {
		t.Fatal("expected non-nil drift result")
	}
	if len(dr.Improved) != 0 {
		t.Errorf("expected 0 improved checks, got %d", len(dr.Improved))
	}
	if len(dr.Degraded) != 0 {
		t.Errorf("expected 0 degraded checks, got %d", len(dr.Degraded))
	}
}

func TestComputeDrift_NewFailure(t *testing.T) {
	base := &Snapshot{
		RunAt:   time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		Status:  models.StatusPass,
		Summary: models.ReportSummary{Pass: 1, Fail: 0, Warn: 0},
		Findings: []models.CheckResult{
			{CheckType: "subnet_discovery", Target: "10.0.0.0/24", Status: models.StatusPass,
				Expected: map[string]interface{}{"expect_hosts_min": 1}},
		},
	}
	current := &Snapshot{
		RunAt:   time.Date(2025, 1, 2, 0, 0, 0, 0, time.UTC),
		Status:  models.StatusFail,
		Summary: models.ReportSummary{Pass: 0, Fail: 1, Warn: 0},
		Findings: []models.CheckResult{
			{CheckType: "subnet_discovery", Target: "10.0.0.0/24", Status: models.StatusFail,
				Expected: map[string]interface{}{"expect_hosts_min": 1}},
		},
	}

	dr := ComputeDrift(base, current)
	if dr == nil {
		t.Fatal("expected non-nil drift result")
	}
	if len(dr.Degraded) != 1 {
		t.Errorf("expected 1 degraded check, got %d", len(dr.Degraded))
	}
	if dr.Degraded[0].CheckType != "subnet_discovery" {
		t.Errorf("expected degraded check to be subnet_discovery, got %q", dr.Degraded[0].CheckType)
	}
}

func TestComputeDrift_NewWarning(t *testing.T) {
	base := &Snapshot{
		RunAt:   time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		Status:  models.StatusPass,
		Summary: models.ReportSummary{Pass: 1, Fail: 0, Warn: 0},
		Findings: []models.CheckResult{
			{CheckType: "subnet_discovery", Target: "10.0.0.0/24", Status: models.StatusPass,
				Expected: map[string]interface{}{"expect_hosts_min": 1}},
		},
	}
	current := &Snapshot{
		RunAt:   time.Date(2025, 1, 2, 0, 0, 0, 0, time.UTC),
		Status:  models.StatusWarn,
		Summary: models.ReportSummary{Pass: 0, Fail: 0, Warn: 1},
		Findings: []models.CheckResult{
			{CheckType: "subnet_discovery", Target: "10.0.0.0/24", Status: models.StatusWarn,
				Expected: map[string]interface{}{"expect_hosts_min": 1}},
		},
	}

	dr := ComputeDrift(base, current)
	if dr == nil {
		t.Fatal("expected non-nil drift result")
	}
	// A pass→warn on an existing check is neither a new warning (new warnings
	// are checks that didn't exist in baseline) nor a hard degradation — the
	// drift loops only capture fail/error degradations, so nothing lands here.
	if len(dr.NewWarnings) != 0 {
		t.Errorf("expected 0 new warnings, got %d", len(dr.NewWarnings))
	}
	if len(dr.Degraded) != 0 {
		t.Errorf("expected 0 degraded, got %d", len(dr.Degraded))
	}
	// Let's verify the summary at least
	if dr.Summary.BaselinePass != 1 {
		t.Errorf("expected baseline pass 1, got %d", dr.Summary.BaselinePass)
	}
	if dr.Summary.CurrentWarn != 1 {
		t.Errorf("expected current warn 1, got %d", dr.Summary.CurrentWarn)
	}
}

func TestComputeDrift_FailToErrorDegradation(t *testing.T) {
	base := &Snapshot{
		RunAt:   time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		Status:  models.StatusFail,
		Summary: models.ReportSummary{Pass: 0, Fail: 1, Warn: 0},
		Findings: []models.CheckResult{
			{CheckType: "subnet_discovery", Target: "10.0.0.0/24", Status: models.StatusFail,
				Expected: map[string]interface{}{"expect_hosts_min": 1}},
		},
	}
	current := &Snapshot{
		RunAt:   time.Date(2025, 1, 2, 0, 0, 0, 0, time.UTC),
		Status:  models.StatusError,
		Summary: models.ReportSummary{Pass: 0, Fail: 0, Error: 1},
		Findings: []models.CheckResult{
			{CheckType: "subnet_discovery", Target: "10.0.0.0/24", Status: models.StatusError,
				Expected: map[string]interface{}{"expect_hosts_min": 1}},
		},
	}

	dr := ComputeDrift(base, current)
	if dr == nil {
		t.Fatal("expected non-nil drift result")
	}
	// FAIL -> ERROR must be visible as a degradation, not silently dropped.
	if len(dr.Degraded) != 1 {
		t.Errorf("expected 1 degraded check, got %d", len(dr.Degraded))
	}
	if dr.Degraded[0].Status != models.StatusError {
		t.Errorf("expected degraded status error, got %s", dr.Degraded[0].Status)
	}
}

func TestComputeDrift_PassToErrorDegradation(t *testing.T) {
	base := &Snapshot{
		RunAt:   time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		Status:  models.StatusPass,
		Summary: models.ReportSummary{Pass: 1, Fail: 0, Warn: 0},
		Findings: []models.CheckResult{
			{CheckType: "subnet_discovery", Target: "10.0.0.0/24", Status: models.StatusPass,
				Expected: map[string]interface{}{"expect_hosts_min": 1}},
		},
	}
	current := &Snapshot{
		RunAt:   time.Date(2025, 1, 2, 0, 0, 0, 0, time.UTC),
		Status:  models.StatusError,
		Summary: models.ReportSummary{Pass: 0, Fail: 0, Error: 1},
		Findings: []models.CheckResult{
			{CheckType: "subnet_discovery", Target: "10.0.0.0/24", Status: models.StatusError,
				Expected: map[string]interface{}{"expect_hosts_min": 1}},
		},
	}

	dr := ComputeDrift(base, current)
	if dr == nil {
		t.Fatal("expected non-nil drift result")
	}
	if len(dr.Degraded) != 1 {
		t.Errorf("expected 1 degraded check, got %d", len(dr.Degraded))
	}
	if len(dr.NewFailures) != 0 {
		t.Errorf("expected 0 new failures (exists in baseline), got %d", len(dr.NewFailures))
	}
}

func TestComputeDrift_FixedFailure(t *testing.T) {
	base := &Snapshot{
		RunAt:   time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		Status:  models.StatusFail,
		Summary: models.ReportSummary{Pass: 0, Fail: 1, Warn: 0},
		Findings: []models.CheckResult{
			{CheckType: "port_check", Target: "10.0.0.1", Status: models.StatusFail,
				Expected: map[string]interface{}{"ports": 443}},
		},
	}
	current := &Snapshot{
		RunAt:   time.Date(2025, 1, 2, 0, 0, 0, 0, time.UTC),
		Status:  models.StatusPass,
		Summary: models.ReportSummary{Pass: 1, Fail: 0, Warn: 0},
		Findings: []models.CheckResult{
			{CheckType: "port_check", Target: "10.0.0.1", Status: models.StatusPass,
				Expected: map[string]interface{}{"ports": 443}},
		},
	}

	dr := ComputeDrift(base, current)
	if dr == nil {
		t.Fatal("expected non-nil drift result")
	}
	if len(dr.FixedFailures) != 1 {
		t.Errorf("expected 1 fixed failure, got %d", len(dr.FixedFailures))
	}
	if dr.FixedFailures[0].CheckType != "port_check" {
		t.Errorf("expected fixed check to be port_check, got %q", dr.FixedFailures[0].CheckType)
	}
	// FAIL -> PASS is reported as a fixed failure only — it must not also
	// appear under Improved (no double-reporting).
	if len(dr.Improved) != 0 {
		t.Errorf("expected 0 improved checks (fixed already reported), got %d", len(dr.Improved))
	}
}

func TestComputeDrift_CompletelyNewFailure(t *testing.T) {
	base := &Snapshot{
		RunAt:   time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		Status:  models.StatusPass,
		Summary: models.ReportSummary{Pass: 1, Fail: 0, Warn: 0},
		Findings: []models.CheckResult{
			{CheckType: "subnet_discovery", Target: "10.0.0.0/24", Status: models.StatusPass,
				Expected: map[string]interface{}{"expect_hosts_min": 1}},
		},
	}
	current := &Snapshot{
		RunAt:   time.Date(2025, 1, 2, 0, 0, 0, 0, time.UTC),
		Status:  models.StatusFail,
		Summary: models.ReportSummary{Pass: 1, Fail: 1, Warn: 0},
		Findings: []models.CheckResult{
			{CheckType: "subnet_discovery", Target: "10.0.0.0/24", Status: models.StatusPass,
				Expected: map[string]interface{}{"expect_hosts_min": 1}},
			{CheckType: "port_check", Target: "10.0.0.2", Status: models.StatusFail,
				Expected: map[string]interface{}{"ports": 8080}},
		},
	}

	dr := ComputeDrift(base, current)
	if dr == nil {
		t.Fatal("expected non-nil drift result")
	}
	if len(dr.NewFailures) != 1 {
		t.Errorf("expected 1 new failure, got %d", len(dr.NewFailures))
	}
	if dr.NewFailures[0].Target != "10.0.0.2" {
		t.Errorf("expected new failure target '10.0.0.2', got %q", dr.NewFailures[0].Target)
	}
}

// TestComputeDrift_NewErrorIsFailure verifies that a brand-new ERROR-status
// finding is surfaced in the drift report (it used to be invisible).
func TestComputeDrift_NewErrorIsFailure(t *testing.T) {
	base := &Snapshot{
		RunAt:   time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		Status:  models.StatusPass,
		Summary: models.ReportSummary{Pass: 1, Fail: 0, Warn: 0},
		Findings: []models.CheckResult{
			{CheckType: "subnet_discovery", Target: "10.0.0.0/24", Status: models.StatusPass},
		},
	}
	current := &Snapshot{
		RunAt:   time.Date(2025, 1, 2, 0, 0, 0, 0, time.UTC),
		Status:  models.StatusError,
		Summary: models.ReportSummary{Pass: 1, Error: 1},
		Findings: []models.CheckResult{
			{CheckType: "subnet_discovery", Target: "10.0.0.0/24", Status: models.StatusPass},
			{CheckType: "acl_check", Target: "policy1", Status: models.StatusError,
				Summary: "acl_check requires OMADA_HOST environment variables"},
		},
	}

	dr := ComputeDrift(base, current)
	if dr == nil {
		t.Fatal("expected non-nil drift result")
	}
	if len(dr.NewFailures) != 1 {
		t.Errorf("expected 1 new failure from error finding, got %d", len(dr.NewFailures))
	}
	if dr.NewFailures[0].CheckType != "acl_check" {
		t.Errorf("expected new failure to be the acl_check error, got %q", dr.NewFailures[0].CheckType)
	}
	if len(dr.NewWarnings) != 0 {
		t.Errorf("expected 0 new warnings, got %d", len(dr.NewWarnings))
	}
}

// TestComputeDrift_PortCheckDisambiguation verifies that two port_check
// assertions on the same target with different ports do not collide
// (regression: the Expected["ports"] disambiguator was never populated).
func TestComputeDrift_PortCheckDisambiguation(t *testing.T) {
	base := &Snapshot{
		RunAt:   time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		Status:  models.StatusPass,
		Summary: models.ReportSummary{Pass: 2},
		Findings: []models.CheckResult{
			{CheckType: "port_check", Target: "10.0.0.1", Status: models.StatusPass,
				Expected: map[string]interface{}{"ports": []interface{}{float64(80)}}},
			{CheckType: "port_check", Target: "10.0.0.1", Status: models.StatusPass,
				Expected: map[string]interface{}{"ports": []interface{}{float64(22)}}},
		},
	}
	current := &Snapshot{
		RunAt:   time.Date(2025, 1, 2, 0, 0, 0, 0, time.UTC),
		Status:  models.StatusFail,
		Summary: models.ReportSummary{Pass: 1, Fail: 1},
		Findings: []models.CheckResult{
			{CheckType: "port_check", Target: "10.0.0.1", Status: models.StatusPass,
				Expected: map[string]interface{}{"ports": []interface{}{float64(80)}}},
			{CheckType: "port_check", Target: "10.0.0.1", Status: models.StatusFail,
				Expected: map[string]interface{}{"ports": []interface{}{float64(22)}},
				Summary:  "port check failed on 10.0.0.1"},
		},
	}

	dr := ComputeDrift(base, current)
	if dr == nil {
		t.Fatal("expected non-nil drift result")
	}
	if len(dr.NewFailures) != 0 {
		t.Errorf("expected 0 new failures, got %d", len(dr.NewFailures))
	}
	// The port 22 check Pass→Fail must surface as a degradation — with the
	// collision bug, one of the two same-target checks was dropped entirely.
	if len(dr.Degraded) != 1 {
		t.Errorf("expected exactly 1 degraded check (port 22), got %d", len(dr.Degraded))
	}
	if len(dr.FixedFailures) != 0 {
		t.Errorf("expected 0 fixed failures, got %d", len(dr.FixedFailures))
	}
}

func TestComputeDrift_GoneEntirely(t *testing.T) {
	base := &Snapshot{
		RunAt:   time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		Status:  models.StatusFail,
		Summary: models.ReportSummary{Pass: 0, Fail: 1},
		Findings: []models.CheckResult{
			{CheckType: "port_check", Target: "10.0.0.1", Status: models.StatusFail,
				Expected: map[string]interface{}{"ports": 443}},
		},
	}
	current := &Snapshot{
		RunAt:    time.Date(2025, 1, 2, 0, 0, 0, 0, time.UTC),
		Status:   models.StatusPass,
		Summary:  models.ReportSummary{Pass: 0, Fail: 0},
		Findings: []models.CheckResult{},
	}

	dr := ComputeDrift(base, current)
	if dr == nil {
		t.Fatal("expected non-nil drift result")
	}
	if len(dr.FixedFailures) != 1 {
		t.Errorf("expected 1 fixed failure (gone entirely), got %d", len(dr.FixedFailures))
	}
}

func TestComputeDrift_EmptySnapshots(t *testing.T) {
	base := &Snapshot{
		RunAt:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		Status:   models.StatusPass,
		Summary:  models.ReportSummary{},
		Findings: []models.CheckResult{},
	}
	current := &Snapshot{
		RunAt:    time.Date(2025, 1, 2, 0, 0, 0, 0, time.UTC),
		Status:   models.StatusPass,
		Summary:  models.ReportSummary{},
		Findings: []models.CheckResult{},
	}

	dr := ComputeDrift(base, current)
	if dr == nil {
		t.Fatal("expected non-nil drift result")
	}
	if dr.Summary.NetChange != "no change" {
		t.Errorf("expected 'no change' for empty snapshots, got %q", dr.Summary.NetChange)
	}
}

func TestComputeDrift_SummaryFields(t *testing.T) {
	base := &Snapshot{
		RunAt:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		Status:   models.StatusFail,
		Summary:  models.ReportSummary{Pass: 10, Fail: 3, Warn: 2, Error: 1},
		Findings: []models.CheckResult{},
	}
	current := &Snapshot{
		RunAt:    time.Date(2025, 1, 2, 0, 0, 0, 0, time.UTC),
		Status:   models.StatusWarn,
		Summary:  models.ReportSummary{Pass: 12, Fail: 1, Warn: 3, Error: 0},
		Findings: []models.CheckResult{},
	}

	dr := ComputeDrift(base, current)
	if dr == nil {
		t.Fatal("expected non-nil drift result")
	}
	if dr.BaselineTime != base.RunAt {
		t.Errorf("wrong baseline time")
	}
	if dr.CurrentTime != current.RunAt {
		t.Errorf("wrong current time")
	}
	if dr.BaselineStatus != models.StatusFail {
		t.Errorf("expected baseline status fail, got %q", dr.BaselineStatus)
	}
	if dr.CurrentStatus != models.StatusWarn {
		t.Errorf("expected current status warn, got %q", dr.CurrentStatus)
	}
	if dr.Summary.BaselinePass != 10 {
		t.Errorf("expected baseline pass 10, got %d", dr.Summary.BaselinePass)
	}
	if dr.Summary.CurrentFail != 1 {
		t.Errorf("expected current fail 1, got %d", dr.Summary.CurrentFail)
	}
}

// =====================================================================
// buildLookup
// =====================================================================

func TestBuildLookup_Basic(t *testing.T) {
	findings := []models.CheckResult{
		{CheckType: "subnet_discovery", Target: "10.0.0.0/24", Status: models.StatusPass},
		{CheckType: "port_check", Target: "10.0.0.1", Status: models.StatusFail},
	}
	lookup := buildLookup(findings)
	if len(lookup) != 2 {
		t.Errorf("expected 2 entries, got %d", len(lookup))
	}
	if r, ok := lookup["subnet_discovery:10.0.0.0/24"]; !ok || r.Status != models.StatusPass {
		t.Error("expected subnet_discovery entry with pass status")
	}
	if r, ok := lookup["port_check:10.0.0.1"]; !ok || r.Status != models.StatusFail {
		t.Error("expected port_check entry with fail status")
	}
}

func TestBuildLookup_PortCheckDisambiguation(t *testing.T) {
	findings := []models.CheckResult{
		{CheckType: "port_check", Target: "10.0.0.1", Status: models.StatusPass,
			Expected: map[string]interface{}{"ports": 443}},
		{CheckType: "port_check", Target: "10.0.0.1", Status: models.StatusFail,
			Expected: map[string]interface{}{"ports": 8080}},
	}
	lookup := buildLookup(findings)
	// Two different ports on same target should produce different keys
	if len(lookup) != 2 {
		t.Errorf("expected 2 entries with port disambiguation, got %d", len(lookup))
	}
}

func TestBuildLookup_DNSCheckDisambiguation(t *testing.T) {
	findings := []models.CheckResult{
		{CheckType: "dns_check", Target: "ns1", Status: models.StatusPass,
			Expected: map[string]interface{}{"query": "example.com"}},
		{CheckType: "dns_check", Target: "ns1", Status: models.StatusFail,
			Expected: map[string]interface{}{"query": "other.com"}},
	}
	lookup := buildLookup(findings)
	if len(lookup) != 2 {
		t.Errorf("expected 2 entries with DNS query disambiguation, got %d", len(lookup))
	}
}

func TestBuildLookup_IsolationDisambiguation(t *testing.T) {
	findings := []models.CheckResult{
		{CheckType: "isolation", Target: "vlan10", Status: models.StatusPass,
			Expected: map[string]interface{}{"expect": "isolated"}},
		{CheckType: "isolation", Target: "vlan10", Status: models.StatusFail,
			Expected: map[string]interface{}{"expect": "connected"}},
	}
	lookup := buildLookup(findings)
	if len(lookup) != 2 {
		t.Errorf("expected 2 entries with isolation expect disambiguation, got %d", len(lookup))
	}
}

func TestBuildLookup_SubnetDiscoveryDisambiguation(t *testing.T) {
	findings := []models.CheckResult{
		{CheckType: "subnet_discovery", Target: "10.0.0.0/24", Status: models.StatusPass,
			Expected: map[string]interface{}{"expect_hosts_min": 1, "expect_hosts_max": 10}},
		{CheckType: "subnet_discovery", Target: "10.0.0.0/24", Status: models.StatusWarn,
			Expected: map[string]interface{}{"expect_hosts_min": 5, "expect_hosts_max": 20}},
	}
	lookup := buildLookup(findings)
	if len(lookup) != 2 {
		t.Errorf("expected 2 entries with subnet_discovery disambiguation, got %d", len(lookup))
	}
}

func TestBuildLookup_Empty(t *testing.T) {
	lookup := buildLookup(nil)
	if len(lookup) != 0 {
		t.Errorf("expected empty lookup, got %d entries", len(lookup))
	}
}

func TestBuildLookup_DuplicateOverwrite(t *testing.T) {
	// Same key should overwrite
	findings := []models.CheckResult{
		{CheckType: "subnet_discovery", Target: "10.0.0.0/24", Status: models.StatusPass},
		{CheckType: "subnet_discovery", Target: "10.0.0.0/24", Status: models.StatusFail},
	}
	lookup := buildLookup(findings)
	if len(lookup) != 1 {
		t.Errorf("expected 1 entry (duplicate overwritten), got %d", len(lookup))
	}
	// Last writer wins
	if lookup["subnet_discovery:10.0.0.0/24"].Status != models.StatusFail {
		t.Error("expected last writer to win")
	}
}

// =====================================================================
// statusWorsened
// =====================================================================

func TestStatusWorsened(t *testing.T) {
	tests := []struct {
		name     string
		old      models.Status
		newVal   models.Status
		expected bool
	}{
		{"pass_to_fail", models.StatusPass, models.StatusFail, true},
		{"pass_to_warn", models.StatusPass, models.StatusWarn, true},
		{"pass_to_error", models.StatusPass, models.StatusError, true},
		{"warn_to_fail", models.StatusWarn, models.StatusFail, true},
		{"warn_to_error", models.StatusWarn, models.StatusError, true},
		{"fail_to_error", models.StatusFail, models.StatusError, true},
		{"fail_to_pass", models.StatusFail, models.StatusPass, false},
		{"warn_to_pass", models.StatusWarn, models.StatusPass, false},
		{"error_to_fail", models.StatusError, models.StatusFail, false},
		{"pass_to_pass", models.StatusPass, models.StatusPass, false},
		{"fail_to_fail", models.StatusFail, models.StatusFail, false},
		{"skip_to_pass", models.StatusSkip, models.StatusPass, false},
		{"pass_to_skip", models.StatusPass, models.StatusSkip, false},
		{"skip_to_fail", models.StatusSkip, models.StatusFail, false},
		{"fail_to_skip", models.StatusFail, models.StatusSkip, false},
		{"warn_to_skip", models.StatusWarn, models.StatusSkip, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := statusWorsened(tt.old, tt.newVal)
			if result != tt.expected {
				t.Errorf("statusWorsened(%v, %v) = %v; want %v", tt.old, tt.newVal, result, tt.expected)
			}
		})
	}
}

// =====================================================================
// statusImproved
// =====================================================================

func TestStatusImproved(t *testing.T) {
	tests := []struct {
		name     string
		old      models.Status
		newVal   models.Status
		expected bool
	}{
		{"fail_to_pass", models.StatusFail, models.StatusPass, true},
		{"fail_to_warn", models.StatusFail, models.StatusWarn, true},
		{"error_to_fail", models.StatusError, models.StatusFail, true},
		{"error_to_pass", models.StatusError, models.StatusPass, true},
		{"warn_to_pass", models.StatusWarn, models.StatusPass, true},
		{"pass_to_fail", models.StatusPass, models.StatusFail, false},
		{"pass_to_warn", models.StatusPass, models.StatusWarn, false},
		{"fail_to_error", models.StatusFail, models.StatusError, false},
		{"pass_to_pass", models.StatusPass, models.StatusPass, false},
		{"skip_to_pass", models.StatusSkip, models.StatusPass, false}, // skip carries no status — not an improvement
		{"pass_to_skip", models.StatusPass, models.StatusSkip, false}, // a skipped check is not better
		{"fail_to_skip", models.StatusFail, models.StatusSkip, false}, // hiding a failure is not a fix
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := statusImproved(tt.old, tt.newVal)
			if result != tt.expected {
				t.Errorf("statusImproved(%v, %v) = %v; want %v", tt.old, tt.newVal, result, tt.expected)
			}
		})
	}
}

// =====================================================================
// computeNetChange
// =====================================================================

func TestComputeNetChange_NoChange(t *testing.T) {
	base := &models.ReportSummary{Pass: 10, Fail: 0, Warn: 0, Error: 0}
	current := &models.ReportSummary{Pass: 10, Fail: 0, Warn: 0, Error: 0}
	result := computeNetChange(base, current)
	if result != "no change" {
		t.Errorf("computeNetChange(identical) = %q; want \"no change\"", result)
	}
}

func TestComputeNetChange_MoreFailures(t *testing.T) {
	base := &models.ReportSummary{Pass: 10, Fail: 0, Warn: 0, Error: 0}
	current := &models.ReportSummary{Pass: 8, Fail: 2, Warn: 0, Error: 0}
	result := computeNetChange(base, current)
	if !strings.Contains(result, "2 more failures") {
		t.Errorf("expected '2 more failures' in %q", result)
	}
}

func TestComputeNetChange_FewerFailures(t *testing.T) {
	base := &models.ReportSummary{Pass: 8, Fail: 3, Warn: 0, Error: 0}
	current := &models.ReportSummary{Pass: 10, Fail: 1, Warn: 0, Error: 0}
	result := computeNetChange(base, current)
	if !strings.Contains(result, "2 fewer failures") {
		t.Errorf("expected '2 fewer failures' in %q", result)
	}
}

func TestComputeNetChange_MoreWarnings(t *testing.T) {
	base := &models.ReportSummary{Pass: 10, Fail: 0, Warn: 0, Error: 0}
	current := &models.ReportSummary{Pass: 8, Fail: 0, Warn: 2, Error: 0}
	result := computeNetChange(base, current)
	if !strings.Contains(result, "2 more warnings") {
		t.Errorf("expected '2 more warnings' in %q", result)
	}
}

func TestComputeNetChange_FewerWarnings(t *testing.T) {
	base := &models.ReportSummary{Pass: 8, Fail: 0, Warn: 3, Error: 0}
	current := &models.ReportSummary{Pass: 10, Fail: 0, Warn: 1, Error: 0}
	result := computeNetChange(base, current)
	if !strings.Contains(result, "2 fewer warnings") {
		t.Errorf("expected '2 fewer warnings' in %q", result)
	}
}

func TestComputeNetChange_MoreErrors(t *testing.T) {
	base := &models.ReportSummary{Pass: 10, Fail: 0, Warn: 0, Error: 0}
	current := &models.ReportSummary{Pass: 8, Fail: 0, Warn: 0, Error: 2}
	result := computeNetChange(base, current)
	if !strings.Contains(result, "2 more errors") {
		t.Errorf("expected '2 more errors' in %q", result)
	}
}

func TestComputeNetChange_FewerErrors(t *testing.T) {
	base := &models.ReportSummary{Pass: 8, Fail: 0, Warn: 0, Error: 3}
	current := &models.ReportSummary{Pass: 10, Fail: 0, Warn: 0, Error: 1}
	result := computeNetChange(base, current)
	if !strings.Contains(result, "2 fewer errors") {
		t.Errorf("expected '2 fewer errors' in %q", result)
	}
}

func TestComputeNetChange_MixedChanges(t *testing.T) {
	base := &models.ReportSummary{Pass: 5, Fail: 3, Warn: 2, Error: 2}
	current := &models.ReportSummary{Pass: 7, Fail: 1, Warn: 4, Error: 0}
	result := computeNetChange(base, current)
	if !strings.Contains(result, "2 fewer failures") {
		t.Errorf("expected '2 fewer failures' in %q", result)
	}
	if !strings.Contains(result, "2 more warnings") {
		t.Errorf("expected '2 more warnings' in %q", result)
	}
	if !strings.Contains(result, "2 fewer errors") {
		t.Errorf("expected '2 fewer errors' in %q", result)
	}
}

func TestComputeNetChange_AllZero(t *testing.T) {
	base := &models.ReportSummary{}
	current := &models.ReportSummary{}
	result := computeNetChange(base, current)
	if result != "no change" {
		t.Errorf("computeNetChange(zero summaries) = %q; want \"no change\"", result)
	}
}

// =====================================================================
// Integration: Save → Load → Drift
// =====================================================================

func TestIntegration_SaveLoadDrift(t *testing.T) {
	// Save a baseline
	baseReport := makeReport(models.StatusPass, 5, 0, 0, 0)
	baseReport.Findings = []models.CheckResult{
		{CheckType: "subnet_discovery", Target: "10.0.0.0/24", Status: models.StatusPass,
			Expected: map[string]interface{}{"expect_hosts_min": 1}},
		{CheckType: "port_check", Target: "10.0.0.1", Status: models.StatusPass,
			Expected: map[string]interface{}{"ports": 443}},
	}
	err := SetBaseline("baseline.spec", baseReport)
	if err != nil {
		t.Fatalf("SetBaseline failed: %v", err)
	}

	// Save a current snapshot with a new failure
	curReport := makeReport(models.StatusFail, 4, 1, 0, 0)
	curReport.Findings = []models.CheckResult{
		{CheckType: "subnet_discovery", Target: "10.0.0.0/24", Status: models.StatusPass,
			Expected: map[string]interface{}{"expect_hosts_min": 1}},
		{CheckType: "port_check", Target: "10.0.0.1", Status: models.StatusFail,
			Expected: map[string]interface{}{"ports": 443}},
	}
	savedPath, err := Save("current.spec", curReport)
	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}
	t.Cleanup(func() { os.Remove(savedPath) })

	// Load both
	baseline, err := LoadBaseline()
	if err != nil {
		t.Fatalf("LoadBaseline failed: %v", err)
	}
	current, err := LoadSnapshot(savedPath)
	if err != nil {
		t.Fatalf("LoadSnapshot failed: %v", err)
	}

	// Compute drift
	dr := ComputeDrift(baseline, current)
	if dr == nil {
		t.Fatal("ComputeDrift returned nil")
	}
	if dr.BaselineStatus != models.StatusPass {
		t.Errorf("expected baseline status pass, got %q", dr.BaselineStatus)
	}
	if dr.CurrentStatus != models.StatusFail {
		t.Errorf("expected current status fail, got %q", dr.CurrentStatus)
	}
	if len(dr.Degraded) != 1 {
		t.Errorf("expected 1 degraded (pass→fail on port_check), got %d", len(dr.Degraded))
	}
}
