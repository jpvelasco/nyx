package seendb_test

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jpvelasco/nyx/internal/seendb"
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
	// Portable way to force a write error: point path at an existing directory.
	// os.WriteFile on a dir path fails ("is a directory") on all platforms.
	tmp := t.TempDir()
	dirAsFile := filepath.Join(tmp, "seen.json")
	if err := os.Mkdir(dirAsFile, 0o700); err != nil {
		t.Fatalf("setup: %v", err)
	}

	db, _ := seendb.LoadFrom(dirAsFile)
	err := db.AckVirtual("10.0.0.0/24")
	if err == nil {
		t.Error("expected error when writing to unwritable path (directory)")
	}

	// Critical: ack must still succeed in memory (the graceful part).
	// Callers do ` _ = db.AckVirtual(...) ` and continue.
	if !db.IsVirtualAcked("10.0.0.0/24") {
		t.Error("virtual CIDR should be acked in-memory even when persist fails")
	}
}

func TestConcurrentAcksNoPanic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "seen.json")
	db, _ := seendb.LoadFrom(path)

	var wg sync.WaitGroup
	cidrs := []string{
		"192.168.1.0/24", "192.168.2.0/24", "192.168.3.0/24",
		"10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24",
	}
	for _, cidr := range cidrs {
		cidr := cidr
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = db.AckVirtual(cidr)
			_ = db.IsVirtualAcked(cidr)
		}()
	}
	wg.Wait()

	// All CIDRs must be acked after concurrent writes
	db2, err := seendb.LoadFrom(path)
	if err != nil {
		t.Fatalf("reload failed: %v", err)
	}
	for _, cidr := range cidrs {
		if !db2.IsVirtualAcked(cidr) {
			t.Errorf("CIDR %s not acked after concurrent writes", cidr)
		}
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
