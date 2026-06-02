// Package logger implements a simple JSON-lines rotating logger used by the CLI for audit trails.
package logger

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/jpvelasco/nyx/internal/version"
)

// Logger writes JSON-line entries to a rotating log file.
// All writes are best-effort — errors are silently discarded so that a
// logging failure never fails a nyx command.
type Logger struct {
	mu       sync.Mutex
	path     string
	maxSize  int64
	maxFiles int
	file     *os.File
	size     int64
}

// New opens (or creates) the log file at path.
// maxSize is the max bytes per file before rotation.
// maxFiles is the number of rotated files to keep.
func New(path string, maxSize int64, maxFiles int) (*Logger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return nil, fmt.Errorf("creating log directory: %w", err)
	}
	l := &Logger{path: path, maxSize: maxSize, maxFiles: maxFiles}
	if err := l.openFile(); err != nil {
		return nil, err
	}
	return l, nil
}

// Info logs an info-level entry. fields must not contain IP addresses,
// hostnames, credentials, or raw command output.
func (l *Logger) Info(cmd string, fields map[string]interface{}) {
	l.write("info", cmd, fields)
}

// Error logs an error-level entry.
func (l *Logger) Error(cmd string, err error) {
	l.write("error", cmd, map[string]interface{}{"error": err.Error()})
}

// Close closes the underlying log file.
func (l *Logger) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		_ = l.file.Close()
	}
}

func (l *Logger) write(level, cmd string, fields map[string]interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file == nil {
		return
	}

	entry := map[string]interface{}{
		"ts":      time.Now().UTC().Format(time.RFC3339),
		"level":   level,
		"cmd":     cmd,
		"version": version.Version,
	}
	for k, v := range fields {
		entry[k] = v
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	data = append(data, '\n')

	if l.size+int64(len(data)) > l.maxSize {
		_ = l.file.Close()
		l.rotate()
		if err := l.openFile(); err != nil {
			l.file = nil
			return
		}
	}

	n, err := l.file.Write(data)
	if err == nil {
		l.size += int64(n)
	}
}

func (l *Logger) openFile() error {
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return fmt.Errorf("opening log file: %w", err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("stat log file: %w", err)
	}
	l.file = f
	l.size = info.Size()
	return nil
}

func (l *Logger) rotate() {
	for i := l.maxFiles - 1; i >= 1; i-- {
		old := fmt.Sprintf("%s.%d", l.path, i)
		newPath := fmt.Sprintf("%s.%d", l.path, i+1)
		if i == l.maxFiles-1 {
			_ = os.Remove(old)
		} else {
			_ = os.Rename(old, newPath)
		}
	}
	_ = os.Rename(l.path, l.path+".1")
}

// DefaultPath returns ~/.nyx/nyx.log
func DefaultPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "nyx.log"
	}
	return filepath.Join(home, ".nyx", "nyx.log")
}
