// Package logger implements nyx's single structured-logging pipeline: a
// *slog.Logger bridged through OpenTelemetry (contrib/bridges/otelslog) into
// an sdk/log provider that writes flat JSON lines to a rotating file. The
// pipeline is best-effort — a logging failure never fails a nyx command.
package logger

import (
	"os"
	"path/filepath"
)

// DefaultPath returns ~/.nyx/nyx.log
func DefaultPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "nyx.log"
	}
	return filepath.Join(home, ".nyx", "nyx.log")
}
