//go:build !windows

package fileaccess

import (
	"os"

	"golang.org/x/sys/unix"
)

// TryLock takes KMX's existing nonblocking exclusive flock on file, failing
// at once with EWOULDBLOCK when another open file description holds it. The
// lock is released when the descriptor is closed or its process exits.
func TryLock(file *os.File) error {
	if file == nil {
		return os.ErrInvalid
	}
	conn, err := file.SyscallConn()
	if err != nil {
		return &os.PathError{Op: "lock", Path: file.Name(), Err: err}
	}
	var lockErr error
	if err := conn.Control(func(fd uintptr) { lockErr = unix.Flock(int(fd), unix.LOCK_EX|unix.LOCK_NB) }); err != nil {
		return &os.PathError{Op: "lock", Path: file.Name(), Err: err}
	}
	if lockErr != nil {
		return &os.PathError{Op: "lock", Path: file.Name(), Err: lockErr}
	}
	return nil
}
