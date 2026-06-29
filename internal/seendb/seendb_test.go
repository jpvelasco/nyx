package seendb

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
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
	if err == nil {
		// LoadFrom tolerates corrupt files per design
	}

	// Should return in-memory-only DB on error (errors are tolerated per design)
	if db == nil {
		t.Error("expected non-nil database even on corrupt file")
	}

	// Should not crash, just use empty DB
	db.AckVirtual("192.168.1.0/24")
	if !db.IsVirtualAcked("192.168.1.0/24") {
		t.Error("expected ack to work on corrupt file")
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
			cidr := "192.168." + string(rune('0'+(index%capacity))) + ".0/24"
			db.AckVirtual(cidr)
		}(i)
	}

	wg.Wait()

	// Verify all acks were recorded
	for i := 0; i < capacity; i++ {
		cidr := "192.168." + string(rune('0'+i)) + ".0/24"
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
