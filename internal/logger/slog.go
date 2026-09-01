package logger

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"os"
	"strings"

	"go.opentelemetry.io/contrib/bridges/otelslog"
)

// NewSlog returns the single structured-logging pipeline: a *slog.Logger
// bridged through OpenTelemetry (otelslog) into an sdk/log provider that
// writes flat JSON lines to the rotating file at path. Records below level
// are discarded. Best-effort: a logging failure never fails a nyx command.
func NewSlog(path string, maxSize int64, maxFiles int, level slog.Level) (*slog.Logger, error) {
	p, err := newNyxProvider(path, maxSize, maxFiles)
	if err != nil {
		return nil, err
	}
	registerProvider(p)
	return slog.New(&bridgeHandler{
		inner:    otelslog.NewHandler(defaultLogScope, otelslog.WithLoggerProvider(p.provider)),
		level:    level,
		provider: p,
	}), nil
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

// CloseSlog flushes and closes the pipeline behind a logger created by
// NewSlog. It reaches the handler through the logger's With-derived
// variants, so it works regardless of how the logger was passed around.
// A logger whose handler does not implement Close is a no-op, and the
// underlying provider shutdown is idempotent.
func CloseSlog(sl *slog.Logger) {
	if h, ok := sl.Handler().(interface{ Close() error }); ok {
		// Best-effort: a logging failure never fails a nyx command.
		_ = h.Close()
	}
}
