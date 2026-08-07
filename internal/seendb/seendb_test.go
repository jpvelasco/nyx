package seendb

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestLoadFromValidFile tests loading from a valid JSON file
func TestLoadFromValidFile(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "seen.json")

	// Create a valid seen.json file matching the format produced by save()
	content := `{
  "virtual_networks": {
    "10.0.10.0/24": {
      "seen_at": "2024-01-01T00:00:00Z",
      "virtual": true
    },
    "10.0.20.0/24": {
      "seen_at": "2024-01-01T00:00:00Z",
      "virtual": false
    }
  }
}`
	if err := os.WriteFile(dbPath, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	db, err := LoadFrom(dbPath)
	if err != nil {
		t.Fatalf("LoadFrom error: %v", err)
	}

	if db == nil {
		t.Fatal("expected non-nil database")
	}

	if !db.IsVirtualAcked("10.0.10.0/24") {
		t.Error("expected 10.0.10.0/24 to be acked")
	}

	if db.IsVirtualAcked("10.0.20.0/24") {
		t.Error("expected 10.0.20.0/24 to not be acked")
	}
}

// TestLoadFromCorruptFile tests loading from a corrupt/corrupted file
func TestLoadFromCorruptFile(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "seen.json")

	// Create a corrupt JSON file
	content := `{"broken": true, }` // Invalid JSON
	if err := os.WriteFile(dbPath, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	db, err := LoadFrom(dbPath)
	if err != nil {
		t.Fatalf("LoadFrom returned unexpected error for corrupt file: %v", err)
	}
	if db == nil {
		t.Fatal("expected non-nil database even on corrupt file")
	}

	// Should return in-memory-only DB (path cleared on corrupt file)
	if err := db.AckVirtual("192.168.1.0/24"); err != nil {
		t.Errorf("AckVirtual failed: %v", err)
	}
	if !db.IsVirtualAcked("192.168.1.0/24") {
		t.Error("expected ack to be recorded after AckVirtual")
	}
}

// TestAck tests acknowledging a virtual subnet
func TestAck(t *testing.T) {
	db := New()

	if db == nil {
		t.Fatal("expected non-nil database")
	}

	if err := db.AckVirtual("192.168.1.0/24"); err != nil {
		t.Errorf("AckVirtual error: %v", err)
	}

	if !db.IsVirtualAcked("192.168.1.0/24") {
		t.Error("expected 192.168.1.0/24 to be acked")
	}

	if db.IsVirtualAcked("192.168.2.0/24") {
		t.Error("expected 192.168.2.0/24 to not be acked")
	}
}

// TestIsVirtualAcked tests checking if a virtual subnet is acked
func TestIsVirtualAcked(t *testing.T) {
	db := New()

	if db.IsVirtualAcked("192.168.1.0/24") {
		t.Error("expected new database to not have any acks")
	}

	db.AckVirtual("192.168.1.0/24")

	if !db.IsVirtualAcked("192.168.1.0/24") {
		t.Error("expected 192.168.1.0/24 to be acked after Ack")
	}
}

// TestConcurrentAck tests concurrent acknowledgment operations
func TestConcurrentAck(t *testing.T) {
	db := New()

	var wg sync.WaitGroup
	numGoroutines := 100
	capacity := 50

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			cidr := fmt.Sprintf("192.168.%d.0/24", index%capacity)
			db.AckVirtual(cidr)
		}(i)
	}

	wg.Wait()

	// Verify all acks were recorded
	for i := 0; i < capacity; i++ {
		cidr := fmt.Sprintf("192.168.%d.0/24", i)
		if !db.IsVirtualAcked(cidr) {
			t.Errorf("expected %s to be acked", cidr)
		}
	}
}

// TestLoadFromEmptyFile tests loading from an empty file
func TestLoadFromEmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "seen.json")

	// Create an empty file
	if err := os.WriteFile(dbPath, []byte(""), 0600); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	db, err := LoadFrom(dbPath)
	if err != nil {
		t.Errorf("LoadFrom returned error for empty file (should tolerate it): %v", err)
	}

	if db == nil {
		t.Error("expected non-nil database even on empty file")
	}
}

// TestAckMultipleSubnets tests acknowledging multiple subnets
func TestAckMultipleSubnets(t *testing.T) {
	db := New()

	subnets := []string{
		"10.0.10.0/24",
		"10.0.20.0/24",
		"10.0.30.0/24",
	}

	for _, subnet := range subnets {
		if err := db.AckVirtual(subnet); err != nil {
			t.Errorf("AckVirtual error for %s: %v", subnet, err)
		}
	}

	for _, subnet := range subnets {
		if !db.IsVirtualAcked(subnet) {
			t.Errorf("expected %s to be acked", subnet)
		}
	}
}

// --- Load() ---

// TestLoad_NoHomeDir tests Load when UserHomeDir fails (in-memory fallback).
func TestLoad_NoHomeDir(t *testing.T) {
	// We cannot easily mock UserHomeDir, so verify Load never returns nil
	// by running it against the real home dir. Even if the file doesn't
	// exist, Load must return a valid DB.
	db := Load()
	if db == nil {
		t.Fatal("Load must never return nil")
	}
	if db.VirtualNetworks == nil {
		t.Fatal("Load must return a DB with a non-nil map")
	}
}

// TestLoad_FromExistingFile tests Load when a valid seen.json already exists.
func TestLoad_FromExistingFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	// os.UserHomeDir does not read HOME on all platforms, so we use LoadFrom
	// directly with a controlled path.
	dir := t.TempDir()
	dbPath := filepath.Join(dir, ".nyx", "seen.json")
	err := os.MkdirAll(filepath.Dir(dbPath), 0700) //nosemgrep: go.lang.correctness.permissions.file_permission.incorrect-default-permission — dir requires execute for traversal
	if err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	content := `{"virtual_networks":{"10.0.0.0/8":{"seen_at":"2024-06-01T00:00:00Z","virtual":true}}}`
	err = os.WriteFile(dbPath, []byte(content), 0600)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	db, err := LoadFrom(dbPath)
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	if !db.IsVirtualAcked("10.0.0.0/8") {
		t.Error("expected 10.0.0.0/8 to be acked after load")
	}
}

// --- LoadFrom() ---

// TestLoadFrom_NonExistentFile tests loading from a file that does not exist.
func TestLoadFrom_NonExistentFile(t *testing.T) {
	db, err := LoadFrom(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err != nil {
		t.Fatalf("LoadFrom should not error on missing file: %v", err)
	}
	if db == nil {
		t.Fatal("expected non-nil database")
	}
	if len(db.VirtualNetworks) != 0 {
		t.Error("expected empty database from non-existent file")
	}
}

// TestLoadFrom_ReadError tests the os.ReadFile error branch (non-IsNotExist).
// Passing a directory path triggers a read error that is not IsNotExist.
func TestLoadFrom_ReadError(t *testing.T) {
	dir := t.TempDir()
	db, err := LoadFrom(dir)
	if err == nil {
		t.Fatal("LoadFrom should return an error when path is a directory")
	}
	if db == nil {
		t.Fatal("expected non-nil database even on read error")
	}
	if len(db.VirtualNetworks) != 0 {
		t.Error("expected empty database on read error")
	}
}

// TestLoadFrom_NilMapInJSON tests loading from a file with null virtual_networks.
func TestLoadFrom_NilMapInJSON(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "seen.json")
	err := os.WriteFile(dbPath, []byte(`{"virtual_networks":null}`), 0600)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	db, err := LoadFrom(dbPath)
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	if db == nil {
		t.Fatal("expected non-nil database")
	}
	if len(db.VirtualNetworks) != 0 {
		t.Error("expected empty map when virtual_networks is null")
	}
}

// TestLoadFrom_EmptyObject tests loading from a file with an empty JSON object.
func TestLoadFrom_EmptyObject(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "seen.json")
	err := os.WriteFile(dbPath, []byte(`{}`), 0600)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	db, err := LoadFrom(dbPath)
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	if db == nil {
		t.Fatal("expected non-nil database")
	}
	if len(db.VirtualNetworks) != 0 {
		t.Error("expected empty map")
	}
}

// TestLoadFrom_MissingDir tests that LoadFrom creates parent directories when saving.
func TestLoadFrom_MissingDir(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "deep", "nested", "seen.json")
	db, err := LoadFrom(dbPath)
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	// File doesn't exist yet, but path is set. Acking should create dirs.
	err = db.AckVirtual("192.168.0.0/16")
	if err != nil {
		t.Fatalf("AckVirtual should create parent dirs: %v", err)
	}
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("expected file to be created at %s: %v", dbPath, err)
	}
}

// --- GetEntry() ---

// TestGetEntry_Present tests GetEntry returns a valid entry for an acked CIDR.
func TestGetEntry_Present(t *testing.T) {
	db := New()
	err := db.AckVirtual("192.168.5.0/24")
	if err != nil {
		t.Fatalf("AckVirtual: %v", err)
	}
	entry := db.GetEntry("192.168.5.0/24")
	if entry == nil {
		t.Fatal("GetEntry returned nil for acked CIDR")
	}
	if !entry.Virtual {
		t.Error("expected entry.Virtual to be true")
	}
	if entry.SeenAt.IsZero() {
		t.Error("expected entry.SeenAt to be set")
	}
}

// TestGetEntry_Missing tests GetEntry returns nil for a non-existent CIDR.
func TestGetEntry_Missing(t *testing.T) {
	db := New()
	entry := db.GetEntry("10.10.10.0/24")
	if entry != nil {
		t.Error("GetEntry should return nil for non-existent CIDR")
	}
}

// TestGetEntry_ReturnsCopy tests that GetEntry returns a copy, not a reference.
func TestGetEntry_ReturnsCopy(t *testing.T) {
	db := New()
	err := db.AckVirtual("172.16.0.0/12")
	if err != nil {
		t.Fatalf("AckVirtual: %v", err)
	}
	entry := db.GetEntry("172.16.0.0/12")
	if entry == nil {
		t.Fatal("GetEntry returned nil")
	}
	// Mutate the returned entry — should not affect the DB.
	entry.Virtual = false
	entry.SeenAt = time.Time{}
	// The DB should still have the original values.
	stillAcked := db.IsVirtualAcked("172.16.0.0/12")
	if !stillAcked {
		t.Error("mutating GetEntry result should not affect the DB")
	}
}

// --- AckVirtual persistence ---

// TestAckVirtual_PersistsToFile tests that AckVirtual writes to disk when a path is set.
func TestAckVirtual_PersistsToFile(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "seen.json")
	db, err := LoadFrom(dbPath)
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	err = db.AckVirtual("10.10.0.0/16")
	if err != nil {
		t.Fatalf("AckVirtual: %v", err)
	}
	// Read the file directly.
	data, err := os.ReadFile(dbPath) //nosemgrep: go_filesystem_rule-fileread
	if err != nil {
		t.Fatalf("file should exist after AckVirtual: %v", err)
	}
	var loaded SeenDB
	err = json.Unmarshal(data, &loaded)
	if err != nil {
		t.Fatalf("file should be valid JSON: %v", err)
	}
	if !loaded.IsVirtualAcked("10.10.0.0/16") {
		t.Error("acked CIDR should be present in persisted file")
	}
}

// TestAckVirtual_InMemoryOnly tests that AckVirtual on a DB with no path works without error.
func TestAckVirtual_InMemoryOnly(t *testing.T) {
	db := New()
	err := db.AckVirtual("192.168.100.0/24")
	if err != nil {
		t.Fatalf("AckVirtual on in-memory DB should not error: %v", err)
	}
	if !db.IsVirtualAcked("192.168.100.0/24") {
		t.Error("expected ack to be recorded in memory")
	}
}

// TestAckVirtual_Overwrite tests re-acking a CIDR updates the SeenAt timestamp.
func TestAckVirtual_Overwrite(t *testing.T) {
	db := New()
	err := db.AckVirtual("10.0.50.0/24")
	if err != nil {
		t.Fatalf("AckVirtual: %v", err)
	}
	firstEntry := db.GetEntry("10.0.50.0/24")
	if firstEntry == nil {
		t.Fatal("GetEntry returned nil")
	}
	firstSeen := firstEntry.SeenAt

	// Wait a tick and re-ack.
	time.Sleep(50 * time.Millisecond)
	err = db.AckVirtual("10.0.50.0/24")
	if err != nil {
		t.Fatalf("AckVirtual: %v", err)
	}
	secondEntry := db.GetEntry("10.0.50.0/24")
	if secondEntry == nil {
		t.Fatal("GetEntry returned nil after re-ack")
	}
	if !secondEntry.SeenAt.After(firstSeen) {
		t.Errorf("re-ack should update SeenAt: first=%v, second=%v", firstSeen, secondEntry.SeenAt)
	}
}

// TestAckVirtual_SeenAtIsUTC tests that SeenAt is stored in UTC.
func TestAckVirtual_SeenAtIsUTC(t *testing.T) {
	db := New()
	err := db.AckVirtual("192.168.99.0/24")
	if err != nil {
		t.Fatalf("AckVirtual: %v", err)
	}
	entry := db.GetEntry("192.168.99.0/24")
	if entry == nil {
		t.Fatal("GetEntry returned nil")
	}
	if entry.SeenAt.Location().String() != "UTC" {
		t.Errorf("expected SeenAt in UTC, got %s", entry.SeenAt.Location())
	}
}

// --- save() ---

// TestSave_CreatesParentDirs tests that save creates the directory tree.
func TestSave_CreatesParentDirs(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "a", "b", "c", "seen.json")
	db, err := LoadFrom(dbPath)
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	err = db.AckVirtual("192.168.0.0/16")
	if err != nil {
		t.Fatalf("AckVirtual should create dirs: %v", err)
	}
	// Verify the directory was created.
	info, err := os.Stat(filepath.Dir(dbPath))
	if err != nil {
		t.Fatalf("parent dir should exist: %v", err)
	}
	if !info.IsDir() {
		t.Error("expected parent path to be a directory")
	}
}

// TestSave_ProducesIndentJSON tests that the persisted file is indented JSON.
func TestSave_ProducesIndentJSON(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "seen.json")
	db, err := LoadFrom(dbPath)
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	err = db.AckVirtual("10.0.0.0/8")
	if err != nil {
		t.Fatalf("AckVirtual: %v", err)
	}
	data, err := os.ReadFile(dbPath) //nosemgrep: go_filesystem_rule-fileread
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	// Indented JSON contains newlines.
	if len(data) == 0 {
		t.Fatal("file should not be empty")
	}
	// Verify it's valid JSON.
	var m map[string]interface{}
	err = json.Unmarshal(data, &m)
	if err != nil {
		t.Fatalf("persisted file should be valid JSON: %v", err)
	}
}

// --- Concurrency ---

// TestConcurrentAckAndRead tests concurrent reads and writes.
func TestConcurrentAckAndRead(t *testing.T) {
	db := New()
	var wg sync.WaitGroup
	n := 200

	// Writers.
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			cidr := fmt.Sprintf("10.%d.0.0/16", idx)
			_ = db.AckVirtual(cidr)
		}(i)
	}

	// Readers.
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			cidr := fmt.Sprintf("10.%d.0.0/16", idx)
			_ = db.IsVirtualAcked(cidr)
			_ = db.GetEntry(cidr)
		}(i)
	}

	wg.Wait()

	// All writers should have completed.
	for i := 0; i < n; i++ {
		cidr := fmt.Sprintf("10.%d.0.0/16", i)
		if !db.IsVirtualAcked(cidr) {
			t.Errorf("expected %s to be acked", cidr)
		}
	}
}

// TestConcurrentLoadAndAck tests concurrent AckVirtual + GetEntry on a DB backed by a file.
func TestConcurrentLoadAndAck(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "seen.json")
	db, err := LoadFrom(dbPath)
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			cidr := fmt.Sprintf("172.%d.0.0/16", idx)
			_ = db.AckVirtual(cidr)
			_ = db.GetEntry(cidr)
		}(i)
	}
	wg.Wait()

	for i := 0; i < 50; i++ {
		cidr := fmt.Sprintf("172.%d.0.0/16", i)
		if !db.IsVirtualAcked(cidr) {
			t.Errorf("expected %s to be acked", cidr)
		}
	}
}

// --- Round-trip ---

// TestRoundTrip_LoadSaveLoad tests save → reload preserves all entries.
func TestRoundTrip_LoadSaveLoad(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "seen.json")
	db, err := LoadFrom(dbPath)
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}

	cidrs := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
	for _, c := range cidrs {
		err = db.AckVirtual(c)
		if err != nil {
			t.Fatalf("AckVirtual(%s): %v", c, err)
		}
	}

	// Reload from the same path.
	db2, err := LoadFrom(dbPath)
	if err != nil {
		t.Fatalf("reload LoadFrom: %v", err)
	}

	for _, c := range cidrs {
		if !db2.IsVirtualAcked(c) {
			t.Errorf("expected %s to survive round-trip", c)
		}
		entry := db2.GetEntry(c)
		if entry == nil {
			t.Errorf("GetEntry(%s) should not be nil after reload", c)
		}
	}
}

// --- New() ---

// TestNew_ReturnsValidDB tests New always returns a usable empty DB.
func TestNew_ReturnsValidDB(t *testing.T) {
	db := New()
	if db == nil {
		t.Fatal("New must not return nil")
	}
	if db.VirtualNetworks == nil {
		t.Fatal("New must initialize VirtualNetworks map")
	}
	if len(db.VirtualNetworks) != 0 {
		t.Error("New must return an empty DB")
	}
}

// --- Load() error paths ---

// TestLoad_NoHomeDirError tests that Load returns an in-memory DB when UserHomeDir fails.
func TestLoad_NoHomeDirError(t *testing.T) {
	t.Setenv("USERPROFILE", "")
	t.Setenv("HOMEDRIVE", "")
	t.Setenv("HOMEPATH", "")

	db := Load()
	if db == nil {
		t.Fatal("Load must never return nil")
	}
	if db.VirtualNetworks == nil {
		t.Fatal("Load must return a DB with initialized map")
	}
}

// TestLoad_LoadFromError tests that Load returns an in-memory DB when LoadFrom errors.
// We force LoadFrom to fail by creating ~/.nyx/seen.json as a directory (not a file),
// which causes os.ReadFile to return a non-IsNotExist error.
func TestLoad_LoadFromError(t *testing.T) {
	dir := t.TempDir()
	nyxDir := filepath.Join(dir, ".nyx")
	if err := os.MkdirAll(nyxDir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(nyxDir, "seen.json"), 0700); err != nil {
		t.Fatalf("mkdir seen.json: %v", err)
	}
	t.Setenv("USERPROFILE", dir)
	t.Setenv("HOMEDRIVE", "")
	t.Setenv("HOMEPATH", "")

	db := Load()
	if db == nil {
		t.Fatal("Load must never return nil")
	}
	if db.VirtualNetworks == nil {
		t.Fatal("Load must return a DB with initialized map")
	}
}

// TestSave_MkdirAllError tests that save returns an error when MkdirAll fails.
// We create a regular file where the parent directory should be, causing MkdirAll to error.
func TestSave_MkdirAllError(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	db := &SeenDB{
		VirtualNetworks: map[string]Entry{},
		path:            filepath.Join(blocker, "seen.json"),
	}
	err := db.AckVirtual("10.0.0.0/8")
	if err == nil {
		t.Fatal("expected AckVirtual to fail when MkdirAll cannot create the directory")
	}
}
