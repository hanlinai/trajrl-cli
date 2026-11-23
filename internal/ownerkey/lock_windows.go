//go:build windows

package ownerkey

import (
	"os"

	"golang.org/x/sys/windows"
)

// lockFile takes an exclusive lock on f, waiting for it: LockFileEx on the
// file's first byte, the Windows counterpart of flock(LOCK_EX).
func lockFile(f *os.File) error {
	return windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, new(windows.Overlapped))
}

// unlockFile releases the lock lockFile took.
func unlockFile(f *os.File) error {
	return windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, new(windows.Overlapped))
}
