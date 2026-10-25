//go:build windows

package credentials

import (
	"os"

	"golang.org/x/sys/windows"
)

// fileLock is an exclusive lock on the store's sibling lock file. It
// serializes store transactions across handles and processes.
type fileLock struct{ f *os.File }

// acquireFileLock opens the lock file (creating it if needed) and takes an
// exclusive byte-range lock, blocking until it is available.
func acquireFileLock(path string) (*fileLock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	// Lock the first byte of the file. Go opens files with share modes
	// that allow other handles to open the same lock file, so concurrent
	// processes block here until the lock is released.
	ol := new(windows.Overlapped)
	if err := windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, ol); err != nil {
		f.Close()
		return nil, err
	}
	return &fileLock{f: f}, nil
}

// release drops the lock and closes the lock file.
func (l *fileLock) release() {
	defer l.f.Close()
	ol := new(windows.Overlapped)
	_ = windows.UnlockFileEx(windows.Handle(l.f.Fd()), 0, 1, 0, ol)
}
