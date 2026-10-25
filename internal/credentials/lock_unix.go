//go:build unix

package credentials

import (
	"os"

	"golang.org/x/sys/unix"
)

// fileLock is an exclusive advisory lock on the store's sibling lock file.
// It serializes store transactions across handles and processes.
type fileLock struct{ f *os.File }

// acquireFileLock opens the lock file (creating it if needed) and takes an
// exclusive advisory lock, blocking until it is available.
func acquireFileLock(path string) (*fileLock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return &fileLock{f: f}, nil
}

// release drops the lock and closes the lock file.
func (l *fileLock) release() {
	defer l.f.Close()
	_ = unix.Flock(int(l.f.Fd()), unix.LOCK_UN)
}
