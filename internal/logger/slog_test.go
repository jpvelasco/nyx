package logger

import (
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestSlogWritesJSONLines(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "nyx.log")
	sl, err := NewSlog(path, 4096, 3, slog.LevelDebug)
	if err != nil {
		t.Fatalf("NewSlog failed: %v", err)
	}
	defer CloseSlog(sl)

	sl.Info("audit", slog.String("status", "pass"), slog.Int("count", 3))

	content, err := os.ReadFile(path) // nosemgrep: go_filesystem_rule-fileread
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	line := strings.TrimSpace(string(content))
	for _, want := range []string{`"level":"info"`, `"msg":"audit"`, `"status":"pass"`, `"count":3`} {
		if !strings.Contains(line, want) {
			t.Errorf("expected %s in output line, got: %s", want, line)
		}
	}
}

func TestSlogLevelFiltering(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "nyx.log")
	sl, err := NewSlog(path, 4096, 3, slog.LevelInfo)
	if err != nil {
		t.Fatalf("NewSlog failed: %v", err)
	}
	defer CloseSlog(sl)

	sl.Debug("should be dropped")
	sl.Warn("kept", slog.String("action", "check"))

	content, err := os.ReadFile(path) // nosemgrep: go_filesystem_rule-fileread
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if strings.Contains(string(content), "should be dropped") {
		t.Error("debug record below info level should be discarded")
	}
	if !strings.Contains(string(content), "kept") {
		t.Error("warn record should be written")
	}
}

func TestSlogWithAttrs(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "nyx.log")
	sl, err := NewSlog(path, 4096, 3, slog.LevelInfo)
	if err != nil {
		t.Fatalf("NewSlog failed: %v", err)
	}
	defer CloseSlog(sl)

	withTrace := sl.With("trace_id", "abc123")
	withTrace.Info("run")

	content, err := os.ReadFile(path) // nosemgrep: go_filesystem_rule-fileread
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if !strings.Contains(string(content), `"trace_id":"abc123"`) {
		t.Errorf("expected attached attr in output, got: %s", strings.TrimSpace(string(content)))
	}
}

func TestSlogRotatesSharedFile(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "nyx.log")
	sl, err := NewSlog(path, 200, 3, slog.LevelInfo)
	if err != nil {
		t.Fatalf("NewSlog failed: %v", err)
	}
	defer CloseSlog(sl)

	for i := 0; i < 200; i++ {
		sl.Info("entry", slog.Int("i", i))
	}

	if _, err := os.Stat(path + ".1"); err != nil {
		t.Errorf("expected a rotated log file after the threshold was crossed: %v", err)
	}
}

func TestEnvLevel(t *testing.T) {
	cases := []struct {
		env   string
		level slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"DEBUG", slog.LevelDebug},
		{"info", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"warning", slog.LevelWarn},
		{"error", slog.LevelError},
		{"", slog.LevelInfo},
		{"bogus", slog.LevelInfo},
	}
	for _, c := range cases {
		t.Run(c.env, func(t *testing.T) {
			t.Setenv("NYX_LOG_LEVEL", c.env)
			if got := EnvLevel(); got != c.level {
				t.Errorf("EnvLevel(%q) = %v, want %v", c.env, got, c.level)
			}
		})
	}
}

func TestEnvLogFile(t *testing.T) {
	t.Setenv("NYX_LOG_FILE", "")
	if got := EnvLogFile(); got != DefaultPath() {
		t.Errorf("EnvLogFile() without env = %q, want default %q", got, DefaultPath())
	}

	override := filepath.Join(t.TempDir(), "custom.log")
	t.Setenv("NYX_LOG_FILE", override)
	if got := EnvLogFile(); got != override {
		t.Errorf("EnvLogFile() with env = %q, want %q", got, override)
	}
}

func TestSlogWithGroup(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "nyx.log")
	sl, err := NewSlog(path, 4096, 3, slog.LevelInfo)
	if err != nil {
		t.Fatalf("NewSlog failed: %v", err)
	}
	defer CloseSlog(sl)

	// Groups are flattened into the JSON entry.
	sl.WithGroup("ignored").Info("grouped", slog.String("k", "v"))

	content, err := os.ReadFile(path) // nosemgrep: go_filesystem_rule-fileread
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	line := strings.TrimSpace(string(content))
	if !strings.Contains(line, `"k":"v"`) {
		t.Errorf("expected group attrs flattened into output, got: %s", line)
	}
}

func TestNewSlogError(t *testing.T) {
	tmpDir := t.TempDir()
	blocker := filepath.Join(tmpDir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	if _, err := NewSlog(filepath.Join(blocker, "nyx.log"), 4096, 3, slog.LevelInfo); err == nil {
		t.Error("NewSlog over a file-as-directory should fail")
	}
}

func TestNewTraceID(t *testing.T) {
	id := NewTraceID()
	if !regexp.MustCompile(`^[0-9a-f]{8}$`).MatchString(id) {
		t.Errorf("NewTraceID() = %q, want 8 hex chars", id)
	}
}
