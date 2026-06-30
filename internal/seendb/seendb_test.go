package seendb

import (
	"fmt"
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
