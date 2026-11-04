// Package filewrite creates and atomically replaces owner-only files.
package filewrite

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// Write replaces path only after the source has been copied and the temporary
// file closed. Failures before replacement preserve the destination and include
// cleanup errors.
func Write(path string, source io.Reader) (err error) {
	path = filepath.Clean(path)
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("opening output directory: %w", err)
	}
	defer func() { err = errors.Join(err, root.Close()) }()

	name := filepath.Base(path)
	tempName := name + ".tmp-" + rand.Text()
	f, err := root.OpenFile(tempName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("creating temporary file: %w", err)
	}
	defer func() {
		if cleanupErr := root.Remove(tempName); cleanupErr != nil && !errors.Is(cleanupErr, fs.ErrNotExist) {
			err = errors.Join(err, fmt.Errorf("removing temporary file: %w", cleanupErr))
		}
	}()

	if err := copyAndClose(f, source); err != nil {
		return fmt.Errorf("writing temporary file: %w", err)
	}
	if err := root.Rename(tempName, name); err != nil {
		return fmt.Errorf("replacing output file: %w", err)
	}
	return nil
}

// Create writes a new file exclusively. An existing path, including a
// symlink, is refused. An incomplete file is removed on failure.
func Create(path string, source io.Reader) (err error) {
	path = filepath.Clean(path)
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("opening output directory: %w", err)
	}
	defer func() { err = errors.Join(err, root.Close()) }()

	name := filepath.Base(path)
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("creating file: %w", err)
	}
	if err := copyAndClose(f, source); err != nil {
		return fmt.Errorf("writing file: %w", errors.Join(err, root.Remove(name)))
	}
	return nil
}

// copyAndClose always closes the file, preserving both the original failure
// and any permission or close error.
func copyAndClose(f *os.File, source io.Reader) error {
	_, copyErr := io.Copy(f, source)
	return errors.Join(copyErr, f.Chmod(0600), f.Close())
}
