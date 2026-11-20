package credentials

import (
	"errors"
	"io/fs"
	"os"
	"time"
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
	f, err := retryNotExist(func() (*os.File, error) {
		return root.OpenFile(name, os.O_CREATE|os.O_RDWR, 0600)
	})
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

// lockOpenAttempts bounds retries when creating the lock file reports
// ENOENT. macOS can fail openat(O_CREAT) with ENOENT while another caller
// is creating the same name (#352); the directory exists, so a retry
// succeeds.
const lockOpenAttempts = 5

// retryNotExist calls open until it returns anything but fs.ErrNotExist,
// at most lockOpenAttempts times, backing off linearly between attempts.
func retryNotExist[T any](open func() (T, error)) (T, error) {
	for attempt := 1; ; attempt++ {
		v, err := open()
		if !errors.Is(err, fs.ErrNotExist) || attempt == lockOpenAttempts {
			return v, err
		}
		time.Sleep(time.Duration(attempt) * time.Millisecond)
	}
}
