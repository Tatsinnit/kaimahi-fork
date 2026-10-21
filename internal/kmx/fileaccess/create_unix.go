//go:build !windows

package fileaccess

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// OpenPrivateAt opens or creates the single-component regular file name
// below parent with KMX's existing openat flags and mode 0600. flags holds an
// access mode plus optional os.O_CREATE, os.O_EXCL and os.O_TRUNC. The opened
// file must pass CheckPrivate before the handle is returned, and before any
// truncation.
func OpenPrivateAt(parent *os.File, name string, flags int) (*os.File, error) {
	if flags&^(unix.O_ACCMODE|os.O_CREATE|os.O_EXCL|os.O_TRUNC) != 0 ||
		flags&os.O_EXCL != 0 && flags&os.O_CREATE == 0 ||
		flags&os.O_TRUNC != 0 && flags&unix.O_ACCMODE == os.O_RDONLY {
		return nil, &os.PathError{Op: "openat", Path: name, Err: unix.EINVAL}
	}
	file, err := openAt(parent, name, flags&^os.O_TRUNC|fileFlags, 0o600)
	if err != nil {
		return nil, err
	}
	if err := requireRegular(file); err != nil {
		file.Close()
		return nil, err
	}
	if err := CheckPrivate(file, false); err != nil {
		file.Close()
		return nil, &os.PathError{Op: "openat", Path: name, Err: err}
	}
	if flags&os.O_TRUNC != 0 {
		if err := file.Truncate(0); err != nil {
			file.Close()
			return nil, err
		}
	}
	return file, nil
}

// EnsurePrivateDirectoryAt creates the single-component directory name below
// parent with mode 0700, or opens an existing one, and refuses it unless it
// passes CheckPrivate. Nothing existing is repaired.
func EnsurePrivateDirectoryAt(parent *os.File, name string) (*os.File, error) {
	if parent == nil {
		return nil, &os.PathError{Op: "mkdirat", Path: name, Err: os.ErrInvalid}
	}
	if !singleComponent(name) {
		return nil, &os.PathError{Op: "mkdirat", Path: name, Err: unix.EINVAL}
	}
	conn, err := parent.SyscallConn()
	if err != nil {
		return nil, &os.PathError{Op: "mkdirat", Path: name, Err: err}
	}
	var mkdirErr error
	if err := conn.Control(func(fd uintptr) { mkdirErr = unix.Mkdirat(int(fd), name, 0o700) }); err != nil {
		return nil, &os.PathError{Op: "mkdirat", Path: name, Err: err}
	}
	if mkdirErr != nil && !errors.Is(mkdirErr, unix.EEXIST) {
		return nil, &os.PathError{Op: "mkdirat", Path: name, Err: mkdirErr}
	}
	dir, err := OpenDirectoryAt(parent, name)
	if err != nil {
		return nil, err
	}
	if err := CheckPrivate(dir, false); err != nil {
		dir.Close()
		return nil, &os.PathError{Op: "mkdirat", Path: name, Err: err}
	}
	return dir, nil
}

// EnsurePrivatePath is KMX's existing os.MkdirAll(path, 0700).
func EnsurePrivatePath(path string) error {
	return os.MkdirAll(path, 0o700)
}

// PrivateTempDir is KMX's existing os.MkdirTemp(parent, prefix).
func PrivateTempDir(parent, prefix string) (string, error) {
	return os.MkdirTemp(parent, prefix)
}

// WritePrivateFile is KMX's existing os.WriteFile(path, data, perm).
func WritePrivateFile(path string, data []byte, perm os.FileMode) error {
	return os.WriteFile(path, data, perm)
}
