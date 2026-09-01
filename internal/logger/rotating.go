package logger

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// rotatingWriter owns a single log file and rotates it in place once it
// exceeds maxSize, keeping at most maxFiles rotated generations
// (<path>.1 .. <path>.N, .1 newest). All writes are best-effort — a
// failure is silently dropped so a logging problem never fails a nyx
// command.
type rotatingWriter struct {
	mu       sync.Mutex
	path     string
	maxSize  int64
	maxFiles int
	file     *os.File
	size     int64
}

// newRotatingWriter opens (or creates) the file at path, creating the
// parent directory when needed.
func newRotatingWriter(path string, maxSize int64, maxFiles int) (*rotatingWriter, error) {
	//nolint:gosec
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil { // nosemgrep
		return nil, fmt.Errorf("creating log directory: %w", err)
	}
	w := &rotatingWriter{path: path, maxSize: maxSize, maxFiles: maxFiles}
	if err := w.open(); err != nil {
		return nil, err
	}
	return w, nil
}

// Write appends p, rotating first if the file would exceed maxSize.
func (w *rotatingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return 0, nil
	}
	if w.size+int64(len(p)) > w.maxSize {
		_ = w.file.Close()
		w.rotate()
		if err := w.open(); err != nil {
			w.file = nil
			return 0, nil
		}
	}
	// Surface write errors: io.Writer requires n < len(p) to carry an error.
	// Best-effort behaviour lives at the caller — fileExporter.Export
	// discards the result so a logging failure never fails a nyx command.
	n, err := w.file.Write(p)
	if err != nil {
		return n, err
	}
	w.size += int64(n)
	return n, nil
}

// Close closes the underlying file. Safe to call more than once.
func (w *rotatingWriter) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file != nil {
		_ = w.file.Close()
		w.file = nil
	}
}

func (w *rotatingWriter) open() error {
	f, err := os.OpenFile(w.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("opening log file: %w", err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("stat log file: %w", err)
	}
	w.file = f
	w.size = info.Size()
	return nil
}

func (w *rotatingWriter) rotate() {
	_ = os.Remove(fmt.Sprintf("%s.%d", w.path, w.maxFiles))
	for i := w.maxFiles - 1; i >= 1; i-- {
		old := fmt.Sprintf("%s.%d", w.path, i)
		newPath := fmt.Sprintf("%s.%d", w.path, i+1)
		_ = os.Rename(old, newPath)
	}
	_ = os.Rename(w.path, w.path+".1")
}
