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
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
