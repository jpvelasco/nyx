package filewrite

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type writeSource func(io.Writer) (int64, error)

func (s writeSource) Read([]byte) (int, error) {
	return 0, errors.New("source must be copied through WriteTo")
}

func (s writeSource) WriteTo(w io.Writer) (int64, error) { return s(w) }

func TestWriteReplacesOwnerOnlyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "output")
	if err := os.WriteFile(path, []byte("original"), 0644); err != nil { // nosemgrep — fixture starts with broader permissions to verify replacement
		t.Fatal(err)
	}
	if err := Write(path, strings.NewReader("replacement")); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path) // nosemgrep: go_filesystem_rule-fileread — fixed test fixture
	if err != nil || string(got) != "replacement" {
		t.Fatalf("replacement = %q, error = %v", got, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Errorf("permissions = %o, want 600", info.Mode().Perm())
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("unexpected temporary files: %v, error = %v", entries, err)
	}
}

func TestWriteFailurePreservesDestination(t *testing.T) {
	failure := errors.New("source failed")
	for _, tc := range []struct {
		name       string
		closeEarly bool
	}{
		{"write failure", false},
		{"write and close failure", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "output")
			if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
				t.Fatal(err)
			}
			source := writeSource(func(w io.Writer) (int64, error) {
				n, err := io.WriteString(w, "partial")
				if err != nil {
					return int64(n), err
				}
				if tc.closeEarly {
					if err := w.(io.Closer).Close(); err != nil {
						return int64(n), err
					}
				}
				return int64(n), failure
			})
			err := Write(path, source)
			if !errors.Is(err, failure) {
				t.Fatalf("write error lost: %v", err)
			}
			if tc.closeEarly && !errors.Is(err, os.ErrClosed) {
				t.Errorf("close error lost: %v", err)
			}
			got, readErr := os.ReadFile(path) // nosemgrep: go_filesystem_rule-fileread — fixed test fixture
			if readErr != nil || string(got) != "original" {
				t.Fatalf("original changed: %q, error = %v", got, readErr)
			}
			entries, readErr := os.ReadDir(dir)
			if readErr != nil || len(entries) != 1 {
				t.Fatalf("temporary file remained: %v, error = %v", entries, readErr)
			}
		})
	}
}

func TestWriteReportsCleanupFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory permissions are not enforced on Windows")
	}
	dir := t.TempDir()
	t.Cleanup(func() {
		if err := os.Chmod(dir, 0700); err != nil { // nosemgrep — restore owner access for test cleanup
			t.Error(err)
		}
	})
	failure := errors.New("source failed")
	source := writeSource(func(w io.Writer) (int64, error) {
		n, err := io.WriteString(w, "partial")
		if err != nil {
			return int64(n), err
		}
		if err := os.Chmod(dir, 0500); err != nil {
			return int64(n), err
		}
		return int64(n), failure
	})
	err := Write(filepath.Join(dir, "output"), source)
	if !errors.Is(err, failure) || !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("expected source and cleanup errors, got %v", err)
	}
}

func TestCreateExclusive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	if err := Create(path, strings.NewReader("original")); err != nil {
		t.Fatal(err)
	}
	if err := Create(path, strings.NewReader("replacement")); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("existing file was accepted: %v", err)
	}
	got, err := os.ReadFile(path) // nosemgrep: go_filesystem_rule-fileread — fixed test fixture
	if err != nil || string(got) != "original" {
		t.Fatalf("existing file changed: %q, %v", got, err)
	}
	if err := Create(filepath.Join(dir, "missing", "key"), strings.NewReader("new")); err == nil {
		t.Fatal("missing parent should fail")
	}
}

func TestCreateFailureRemovesPartialFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	failure := errors.New("source failed")
	source := writeSource(func(w io.Writer) (int64, error) {
		n, err := io.WriteString(w, "partial")
		if err != nil {
			return int64(n), err
		}
		return int64(n), failure
	})
	if err := Create(path, source); !errors.Is(err, failure) {
		t.Fatalf("source error lost: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("partial file remained: %v", err)
	}
}

func TestWriteDestinationFailures(t *testing.T) {
	dir := t.TempDir()
	if err := Write(filepath.Join(dir, "missing", "output"), strings.NewReader("new")); err == nil {
		t.Fatal("missing parent should fail")
	}
	path := filepath.Join(dir, "output")
	if err := os.Mkdir(path, 0700); err != nil { // nosemgrep — owner-only fixture directory
		t.Fatal(err)
	}
	if err := Write(path, strings.NewReader("new")); err == nil {
		t.Fatal("replacing a directory should fail")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || !entries[0].IsDir() {
		t.Fatalf("failed replacement changed destination or left a temporary file: %v, %v", entries, err)
	}
	if runtime.GOOS == "windows" {
		return
	}
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(dir, 0700); err != nil { // nosemgrep — restore owner access for test cleanup
			t.Error(err)
		}
	})
	if err := Write(filepath.Join(dir, "unwritable"), strings.NewReader("new")); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("unwritable parent error = %v", err)
	}
}
