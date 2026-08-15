package logger

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoggerInfo(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "nyx.log")
	log, err := New(path, 1024, 3)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer log.Close()

	log.Info("audit", map[string]interface{}{"action": "check"})

	content, err := os.ReadFile(path) // nosemgrep: go_filesystem_rule-fileread
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	if !contains(string(content), `"level":"info"`) || !contains(string(content), `"action":"check"`) {
		t.Error("expected info message with action field in output")
	}
}

func TestLoggerError(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "nyx.log")
	log, err := New(path, 1024, 3)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer log.Close()

	testErr := os.ErrNotExist
	log.Error("audit", testErr)

	content, err := os.ReadFile(path) // nosemgrep: go_filesystem_rule-fileread
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	if !contains(string(content), `"level":"error"`) {
		t.Error("expected error level in output")
	}
}

func TestLoggerRotation(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "nyx.log")
	log, err := New(path, 50, 3)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer log.Close()

	for i := 0; i < 20; i++ {
		log.Info("audit", map[string]interface{}{"idx": i})
	}

	files, _ := os.ReadDir(tmpDir)
	if len(files) == 0 {
		t.Error("expected log files to exist after rotation")
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Error("expected rotated file nyx.log.1 to exist after overflow writes")
	}
}

func TestLoggerRotationKeepsGenerations(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "nyx.log")
	log, err := New(path, 64, 3)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer log.Close()

	// Each entry exceeds maxSize, so every write triggers a rotation and
	// each generation holds exactly one entry.
	for i := 0; i < 7; i++ {
		log.Info("audit", map[string]interface{}{"idx": i})
	}

	for _, tc := range []struct {
		name   string
		marker string
	}{
		{"nyx.log", `"idx":6`},
		{"nyx.log.1", `"idx":5`},
		{"nyx.log.2", `"idx":4`},
		{"nyx.log.3", `"idx":3`},
	} {
		content, err := os.ReadFile(filepath.Join(tmpDir, tc.name)) // nosemgrep: go_filesystem_rule-fileread
		if err != nil {
			t.Fatalf("ReadFile(%s) failed: %v", tc.name, err)
		}
		if !contains(string(content), tc.marker) {
			t.Errorf("%s expected to contain %s, got: %s", tc.name, tc.marker, content)
		}
	}

	rotated, _ := filepath.Glob(filepath.Join(tmpDir, "nyx.log.*"))
	if len(rotated) != 3 {
		t.Errorf("expected exactly 3 rotated files, got %d: %v", len(rotated), rotated)
	}
}

func TestNew_MkdirAllError(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("file"), 0600); err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	_, err := New(filepath.Join(blocker, "nyx.log"), 1024, 3)
	if err == nil {
		t.Fatal("expected error when the log directory cannot be created")
	}
	if !strings.Contains(err.Error(), "creating log directory") {
		t.Errorf("expected error to mention log directory, got: %s", err.Error())
	}
}

func TestNew_OpenFileError(t *testing.T) {
	tmpDir := t.TempDir()
	_, err := New(tmpDir, 1024, 3)
	if err == nil {
		t.Fatal("expected error when the log path is a directory")
	}
	if !strings.Contains(err.Error(), "opening log file") {
		t.Errorf("expected error to mention opening log file, got: %s", err.Error())
	}
}

func TestLoggerWriteWithoutFile(t *testing.T) {
	// A Logger without an open file must silently drop writes.
	log := &Logger{path: filepath.Join(t.TempDir(), "nyx.log"), maxSize: 1024, maxFiles: 3}
	log.Info("audit", map[string]interface{}{"action": "check"})
	log.Error("audit", os.ErrNotExist)
	log.Close()
}

func TestLoggerWrite_MarshalError(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "nyx.log")
	log, err := New(path, 1024, 3)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer log.Close()

	// A channel is not JSON-serialisable — write must fail silently.
	log.Info("audit", map[string]interface{}{"bad": make(chan int)})

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if len(content) != 0 {
		t.Errorf("expected no output for un-marshalable entry, got: %s", content)
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

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
