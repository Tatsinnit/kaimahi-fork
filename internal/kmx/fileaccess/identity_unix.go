//go:build !windows

package fileaccess

import (
	"context"
	"fmt"

	"golang.org/x/sys/unix"
)

// PhysicalIdentity returns the device and inode of the object behind file.
func PhysicalIdentity(ctx context.Context, object Object) (string, error) {
	if err := checkContext(ctx); err != nil {
		return "", wrapAccess("identify object", err)
	}
	file := rawObject(object)
	if file == nil {
		return "", wrapAccess("identify object", unsafeCause("file handle is absent"))
	}
	conn, err := file.SyscallConn()
	if err != nil {
		return "", wrapAccess("identify object", unreadableCause("file handle is unavailable"))
	}
	var st unix.Stat_t
	var statErr error
	if err := conn.Control(func(fd uintptr) { statErr = unix.Fstat(int(fd), &st) }); err != nil {
		return "", wrapAccess("identify object", err)
	}
	if statErr != nil {
		return "", wrapAccess("identify object", statErr)
	}
	if err := checkContext(ctx); err != nil {
		return "", wrapAccess("identify object", err)
	}
	return fmt.Sprintf("%x-%x", uint64(st.Dev), uint64(st.Ino)), nil
}
