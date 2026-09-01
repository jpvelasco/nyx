package logger

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestRotatingWriterWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nyx.log")
	w, err := newRotatingWriter(path, 1024, 3)
	if err != nil {
		t.Fatalf("newRotatingWriter: %v", err)
	}
	defer w.Close()

	if n, _ := w.Write([]byte("line1\n")); n != 6 {
		t.Errorf("Write returned n=%d, want 6", n)
	}
	data, err := os.ReadFile(path) // nosemgrep: go_filesystem_rule-fileread — path is under t.TempDir()
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Contains(data, []byte("line1")) {
		t.Errorf("expected line1 in %q", data)
	}
}

func TestRotatingWriterRotates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nyx.log")
	w, err := newRotatingWriter(path, 50, 3)
	if err != nil {
		t.Fatalf("newRotatingWriter: %v", err)
	}
	defer w.Close()

	for i := 0; i < 20; i++ {
		_, _ = w.Write([]byte("0123456789\n"))
	}

	if _, err := os.Stat(path + ".1"); err != nil {
		t.Error("expected rotated file nyx.log.1 after overflow writes")
	}
}

func TestRotatingWriterKeepsGenerations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nyx.log")
	w, err := newRotatingWriter(path, 64, 3)
	if err != nil {
		t.Fatalf("newRotatingWriter: %v", err)
	}
	defer w.Close()

	// Each write exceeds maxSize, so every write triggers a rotation and
	// each generation holds exactly one entry.
	for i := 0; i < 7; i++ {
		_, _ = w.Write([]byte(strings.Repeat("x", 100) + "\n"))
	}

	rotated, _ := filepath.Glob(filepath.Join(filepath.Dir(path), "nyx.log.*"))
	if len(rotated) != 3 {
		t.Errorf("expected exactly 3 rotated files, got %d: %v", len(rotated), rotated)
	}
}

func TestRotatingWriterConcurrentWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nyx.log")
	w, err := newRotatingWriter(path, 1024, 3)
	if err != nil {
		t.Fatalf("newRotatingWriter: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_, _ = w.Write([]byte("payload\n"))
			}
		}()
	}
	wg.Wait()
	w.Close()

	data, err := os.ReadFile(path) // nosemgrep: go_filesystem_rule-fileread — path is under t.TempDir()
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	// Concurrent writers must not corrupt the stream: every line is whole.
	if !bytes.Equal(data[0:8], []byte("payload")) && strings.Count(string(data), "payload\n") == 0 {
		t.Errorf("corrupted log content: %q", string(data))
	}
}

func TestRotatingWriterDropAfterClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nyx.log")
	w, err := newRotatingWriter(path, 1024, 3)
	if err != nil {
		t.Fatalf("newRotatingWriter: %v", err)
	}
	w.Close()
	// Writes after close are silently dropped, never an error.
	if n, err := w.Write([]byte("after-close\n")); n != 0 || err != nil {
		t.Errorf("Write after Close = (%d, %v), want (0, nil)", n, err)
	}
	w.Close() // double close must be safe
}

func TestNewRotatingWriter_MkdirAllError(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("file"), 0600); err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	_, err := newRotatingWriter(filepath.Join(blocker, "nyx.log"), 1024, 3)
	if err == nil {
		t.Fatal("expected error when the log directory cannot be created")
	}
	if !strings.Contains(err.Error(), "creating log directory") {
		t.Errorf("expected error to mention log directory, got: %s", err)
	}
}

func TestNewRotatingWriter_OpenFileError(t *testing.T) {
	tmpDir := t.TempDir()
	_, err := newRotatingWriter(tmpDir, 1024, 3)
	if err == nil {
		t.Fatal("expected error when the log path is a directory")
	}
	if !strings.Contains(err.Error(), "opening log file") {
		t.Errorf("expected error to mention opening log file, got: %s", err)
	}
}

func TestDefaultPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	got := DefaultPath()
	want := filepath.Join(home, ".nyx", "nyx.log")
	if got != want {
		t.Errorf("DefaultPath() = %q, want %q", got, want)
	}
}

func TestDefaultPath_NoHome(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	t.Setenv("HOMEDRIVE", "")
	t.Setenv("HOMEPATH", "")
	if got := DefaultPath(); got != "nyx.log" {
		t.Errorf("DefaultPath() without home = %q, want %q", got, "nyx.log")
	}
}
