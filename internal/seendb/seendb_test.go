package seendb_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/velasco-jp/nyx/internal/seendb"
)

func TestLoadMissingFileReturnsEmpty(t *testing.T) {
	db, err := seendb.LoadFrom(filepath.Join(t.TempDir(), "notexist.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if db.IsVirtualAcked("192.168.1.0/24") {
		t.Error("expected false for unacked CIDR")
	}
}

func TestAckAndReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "seen.json")
	db, _ := seendb.LoadFrom(path)
	if err := db.AckVirtual("10.0.0.0/24"); err != nil {
		t.Fatalf("ack failed: %v", err)
	}
	db2, err := seendb.LoadFrom(path)
	if err != nil {
		t.Fatalf("reload failed: %v", err)
	}
	if !db2.IsVirtualAcked("10.0.0.0/24") {
		t.Error("expected CIDR to be acked after reload")
	}
}

func TestAckUnwritablePathIsGraceful(t *testing.T) {
	// Use NUL (Windows reserved device) or an empty path to trigger error
	db, _ := seendb.LoadFrom("NUL\\seen.json")
	err := db.AckVirtual("10.0.0.0/24")
	if err == nil {
		t.Error("expected error when writing to unwritable path")
	}
}

func TestSeenAtIsPopulated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "seen.json")
	db, _ := seendb.LoadFrom(path)
	_ = db.AckVirtual("10.0.0.0/24")
	db2, _ := seendb.LoadFrom(path)
	entry := db2.GetEntry("10.0.0.0/24")
	if entry == nil {
		t.Fatal("expected entry to exist")
	}
	if entry.SeenAt.IsZero() {
		t.Error("expected SeenAt to be populated")
	}
	if time.Since(entry.SeenAt) > 5*time.Second {
		t.Error("SeenAt should be recent")
	}
}
