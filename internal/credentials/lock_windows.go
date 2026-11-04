//go:build windows

package credentials

import (
	"os"

	"golang.org/x/sys/windows"
)

func lockFile(f *os.File) error {
	// Lock the first byte of the file. Go opens files with share modes
	// that allow other handles to open the same lock file, so concurrent
	// processes block here until the lock is released.
	ol := new(windows.Overlapped)
	return windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, ol)
}

func unlockFile(f *os.File) error {
	ol := new(windows.Overlapped)
	return windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, ol)
}
