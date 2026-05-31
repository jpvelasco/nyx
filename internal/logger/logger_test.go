package logger_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/velasco-jp/nyx/internal/logger"
)

func TestLogWritesJSONLine(t *testing.T) {
	dir := t.TempDir()
	l, err := logger.New(filepath.Join(dir, "nyx.log"), 1024*1024, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	l.Info("audit", map[string]interface{}{
		"status":      "pass",
		"duration_ms": 100,
	})

	content, err := os.ReadFile(filepath.Join(dir, "nyx.log"))
	if err != nil {
		t.Fatal(err)
	}

	var entry map[string]interface{}
	if err := json.Unmarshal(content[:len(content)-1], &entry); err != nil {
		t.Fatalf("not valid JSON: %v\ncontent: %s", err, content)
	}
	if entry["cmd"] != "audit" {
		t.Errorf("expected cmd=audit, got %v", entry["cmd"])
	}
	if entry["level"] != "info" {
		t.Errorf("expected level=info, got %v", entry["level"])
	}
}

func TestLogRotation(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "nyx.log")
	l, err := logger.New(logPath, 100, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	for i := 0; i < 20; i++ {
		l.Info("test", map[string]interface{}{"i": i})
	}

	if _, err := os.Stat(filepath.Join(dir, "nyx.log.1")); os.IsNotExist(err) {
		t.Error("expected rotated file nyx.log.1 to exist")
	}
}
