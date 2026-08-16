package logger

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"os"
	"strings"
	"sync"
)

// slogHandler writes slog records as JSON lines to the rotating log file
// owned by the shared Logger, mirroring the shape of its hand-written
// entries so both pipelines produce a single consistent audit trail.
type slogHandler struct {
	l     *Logger
	level slog.Level
	attrs []slog.Attr
	mu    sync.Mutex
}

// NewSlog returns a structured logger writing JSON lines to the rotating
// file at path. Records below level are discarded. Best-effort: a logging
// failure never fails a nyx command.
func NewSlog(path string, maxSize int64, maxFiles int, level slog.Level) (*slog.Logger, error) {
	l, err := New(path, maxSize, maxFiles)
	if err != nil {
		return nil, err
	}
	return slog.New(&slogHandler{l: l, level: level}), nil
}

// EnvLogFile returns the log file path from NYX_LOG_FILE, falling back to
// the default ~/.nyx/nyx.log.
func EnvLogFile() string {
	if p := os.Getenv("NYX_LOG_FILE"); p != "" {
		return p
	}
	return DefaultPath()
}

// EnvLevel parses NYX_LOG_LEVEL (debug|info|warn|error), defaulting to
// slog.LevelInfo.
func EnvLevel() slog.Level {
	switch strings.ToLower(os.Getenv("NYX_LOG_LEVEL")) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// NewTraceID returns a short random hex trace ID for correlating log lines
// across one CLI/MCP run.
func NewTraceID() string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (h *slogHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

func (h *slogHandler) Handle(_ context.Context, r slog.Record) error {
	fields := make(map[string]interface{}, r.NumAttrs()+len(h.attrs)+1)
	fields["msg"] = r.Message
	r.Attrs(func(a slog.Attr) bool {
		fields[a.Key] = a.Value.Any()
		return true
	})
	for _, a := range h.attrs {
		fields[a.Key] = a.Value.Any()
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.l.write(strings.ToLower(r.Level.String()), "slog", fields)
	return nil
}

func (h *slogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	combined := make([]slog.Attr, 0, len(h.attrs)+len(attrs))
	combined = append(combined, h.attrs...)
	combined = append(combined, attrs...)
	return &slogHandler{l: h.l, level: h.level, attrs: combined}
}

func (h *slogHandler) WithGroup(_ string) slog.Handler {
	// Groups are flattened into the JSON entry; nested keys are not
	// supported by the legacy entry shape.
	return h
}

// CloseSlog closes the underlying rotating log file. No-op when the logger
// was not created by NewSlog.
func CloseSlog(sl *slog.Logger) {
	if h, ok := sl.Handler().(*slogHandler); ok {
		h.l.Close()
	}
}
