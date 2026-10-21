//go:build windows

package fileaccess

import (
	"os"

	"golang.org/x/sys/windows"
)

// TryLock takes a nonblocking exclusive lock on file, or fails at once with
// ERROR_LOCK_VIOLATION when another handle (in any process) holds it. The
// lock covers every byte and is released when this handle is closed or its
// process exits. Windows byte-range locks are mandatory, so lock files must
// not also carry data read through other handles.
func TryLock(file *os.File) error {
	err := withHandle(file, func(h windows.Handle) error {
		return windows.LockFileEx(h, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, ^uint32(0), ^uint32(0), new(windows.Overlapped))
	})
	if err != nil {
		name := ""
		if file != nil {
			name = file.Name()
		}
		return &os.PathError{Op: "lock", Path: name, Err: err}
	}
	return nil
}
