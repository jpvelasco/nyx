package credentials

import (
	"errors"
	"os"
)

// fileLock keeps the root and the sibling lock file open until release.
// It serializes store transactions across handles and processes.
type fileLock struct {
	f    *os.File
	root *os.Root
}

// The acquire operation supplies the platform lock syscall; file ownership
// and failure cleanup remain shared across platforms.
func acquireFileLock(path string, acquire func(*os.File) error) (*fileLock, error) {
	root, name, err := openStoreRoot(path)
	if err != nil {
		return nil, err
	}
	f, err := root.OpenFile(name, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, errors.Join(err, root.Close())
	}
	if err := acquire(f); err != nil {
		return nil, errors.Join(err, f.Close(), root.Close())
	}
	return &fileLock{f: f, root: root}, nil
}

func (l *fileLock) release() error {
	return errors.Join(unlockFile(l.f), l.f.Close(), l.root.Close())
}
