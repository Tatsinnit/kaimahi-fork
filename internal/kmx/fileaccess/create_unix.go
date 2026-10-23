//go:build !windows

package fileaccess

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const privateFileFlags = unix.O_RDWR | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC

// CreatePrivateFileAt exclusively creates a protected owner-only regular file
// immediately below parent.
func CreatePrivateFileAt(ctx context.Context, parent *Directory, name string) (*PrivateFile, error) {
	return createPrivateFileAt(ctx, parent, name)
}

// EnsurePrivateFileAt opens a protected owner-only regular file immediately
// below parent, creating it if absent. Existing objects are checked, never
// repaired or truncated.
func EnsurePrivateFileAt(ctx context.Context, parent *Directory, name string) (*PrivateFile, error) {
	file, err := openExistingPrivateFileAt(ctx, parent, name)
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		return file, wrapAccess("open private file", err)
	}
	file, err = createPrivateFileAt(ctx, parent, name)
	if errors.Is(err, errEntryExists) {
		file, err = openExistingPrivateFileAt(ctx, parent, name)
	}
	return file, err
}

func createPrivateFileAt(ctx context.Context, parent *Directory, name string) (*PrivateFile, error) {
	if err := CheckSafeDirectory(ctx, parent, true); err != nil {
		return nil, wrapAccess("open private file", err)
	}
	flags := privateFileFlags | unix.O_CREAT | unix.O_EXCL
	file, err := openAtMode(ctx, rawObject(parent), name, flags, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			err = &classifiedCause{class: ClassUnsafe, cause: errEntryExists, reason: "private file already exists"}
		}
		return nil, wrapAccess("open private file", err)
	}
	private := &PrivateFile{file: file}
	if err := CheckPrivate(ctx, private, false); err != nil {
		removeErr := discardCreatedFile(parent, name)
		closeErr := file.Close()
		return nil, wrapAccess("open private file", errors.Join(err, removeErr, closeErr))
	}
	return private, nil
}

// CreatePrivateDirectoryAt exclusively creates a protected owner-only
// directory immediately below parent.
func CreatePrivateDirectoryAt(ctx context.Context, parent *Directory, name string) (*Directory, error) {
	return createPrivateDirectoryAt(ctx, parent, name)
}

// EnsurePrivateDirectoryAt opens a protected owner-only directory immediately
// below parent, creating it if absent. Existing directories are never repaired.
func EnsurePrivateDirectoryAt(ctx context.Context, parent *Directory, name string) (*Directory, error) {
	directory, err := OpenDirectoryAt(ctx, parent, name)
	if err == nil {
		err = CheckPrivate(ctx, directory, true)
		if err != nil {
			directory.Close()
			directory = nil
		}
	}
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		return directory, wrapAccess("open private directory", err)
	}
	directory, err = createPrivateDirectoryAt(ctx, parent, name)
	if errors.Is(err, errEntryExists) {
		directory, err = OpenDirectoryAt(ctx, parent, name)
		if err == nil {
			err = CheckPrivate(ctx, directory, true)
			if err != nil {
				directory.Close()
				directory = nil
			}
		}
	}
	return directory, wrapAccess("open private directory", err)
}

func createPrivateDirectoryAt(ctx context.Context, parent *Directory, name string) (*Directory, error) {
	if err := CheckSafeDirectory(ctx, parent, true); err != nil {
		return nil, wrapAccess("open private directory", err)
	}
	if !singleUnixComponent(name) {
		return nil, wrapAccess("open private directory", unsafeCause("entry name is not one component"))
	}
	parentFile := rawObject(parent)
	if parentFile == nil {
		return nil, wrapAccess("open private directory", unsafeCause("parent handle is absent"))
	}
	conn, err := parentFile.SyscallConn()
	if err != nil {
		return nil, wrapAccess("open private directory", unreadableCause("parent handle is unavailable"))
	}
	var mkdirErr error
	if err := conn.Control(func(fd uintptr) { mkdirErr = unix.Mkdirat(int(fd), name, 0o700) }); err != nil {
		return nil, wrapAccess("open private directory", err)
	}
	if mkdirErr != nil {
		if errors.Is(mkdirErr, unix.EEXIST) {
			return nil, wrapAccess("open private directory", &classifiedCause{class: ClassUnsafe, cause: errEntryExists, reason: "private directory already exists"})
		}
		return nil, wrapAccess("open private directory", mkdirErr)
	}
	directory, err := OpenDirectoryAt(ctx, parent, name)
	if err != nil {
		return nil, wrapAccess("open private directory", err)
	}
	if err := CheckPrivate(ctx, directory, true); err != nil {
		removeErr := discardCreatedDirectory(parent, name)
		closeErr := directory.Close()
		return nil, wrapAccess("open private directory", errors.Join(err, removeErr, closeErr))
	}
	return directory, nil
}

// OpenPrivateDirectory opens an existing protected owner-only directory after
// checking every retained ancestor. It creates and repairs nothing.
func OpenPrivateDirectory(ctx context.Context, path string) (*Directory, error) {
	return privateDirectoryPath(ctx, path, false)
}

// EnsurePrivateDirectory opens or creates a protected owner-only directory,
// checking every existing ancestor and repairing nothing.
func EnsurePrivateDirectory(ctx context.Context, path string) (*Directory, error) {
	return privateDirectoryPath(ctx, path, true)
}

func privateDirectoryPath(ctx context.Context, path string, create bool) (*Directory, error) {
	if err := validateUnixPath(path); err != nil {
		return nil, wrapAccess("open private directory", err)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, wrapAccess("open private directory", err)
	}
	parts := strings.Split(strings.TrimPrefix(absolute, "/"), "/")
	if len(parts) == 0 || len(parts) == 1 && parts[0] == "" {
		return nil, wrapAccess("open private directory", unsafeCause("filesystem root cannot be private state"))
	}
	fd, err := unix.Open("/", directoryFlags, 0)
	if err != nil {
		return nil, wrapAccess("open private directory", err)
	}
	current := &Directory{file: os.NewFile(uintptr(fd), "/")}
	if err := CheckSafeDirectory(ctx, current, false); err != nil {
		current.Close()
		return nil, wrapAccess("open private directory", err)
	}
	for i, part := range parts {
		last := i == len(parts)-1
		if last {
			if err := CheckSafeDirectory(ctx, current, true); err != nil {
				current.Close()
				return nil, wrapAccess("open private directory", err)
			}
			var next *Directory
			if create {
				next, err = EnsurePrivateDirectoryAt(ctx, current, part)
			} else {
				next, err = OpenDirectoryAt(ctx, current, part)
				if err == nil {
					err = CheckPrivate(ctx, next, true)
				}
			}
			current.Close()
			if err != nil {
				if next != nil {
					next.Close()
				}
				return nil, wrapAccess("open private directory", err)
			}
			return next, nil
		}
		next, openErr := OpenDirectoryAt(ctx, current, part)
		if openErr != nil && create && errors.Is(openErr, os.ErrNotExist) {
			next, openErr = EnsurePrivateDirectoryAt(ctx, current, part)
		}
		if openErr == nil {
			openErr = CheckSafeDirectory(ctx, next, i == len(parts)-2)
		}
		current.Close()
		if openErr != nil {
			if next != nil {
				next.Close()
			}
			return nil, wrapAccess("open private directory", openErr)
		}
		current = next
	}
	current.Close()
	return nil, wrapAccess("open private directory", unsafeCause("private directory path is empty"))
}

func discardCreatedFile(parent *Directory, name string) error {
	return discardUnixEntry(parent, name, 0)
}

func discardCreatedDirectory(parent *Directory, name string) error {
	return discardUnixEntry(parent, name, unix.AT_REMOVEDIR)
}

func discardUnixEntry(parent *Directory, name string, flags int) error {
	raw := rawObject(parent)
	if raw == nil {
		return unsafeCause("parent handle is absent")
	}
	conn, err := raw.SyscallConn()
	if err != nil {
		return err
	}
	var removeErr error
	if err := conn.Control(func(fd uintptr) { removeErr = unix.Unlinkat(int(fd), name, flags) }); err != nil {
		return err
	}
	return removeErr
}
