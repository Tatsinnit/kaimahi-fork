//go:build windows

package fileaccess

import (
	"context"
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

const privateMutableAccess = windows.FILE_GENERIC_READ | windows.FILE_GENERIC_WRITE |
	windows.FILE_WRITE_ATTRIBUTES | windows.DELETE | windows.READ_CONTROL

const fileCreated = 2

func privateDescriptor(ctx context.Context, directory bool) (*windows.SECURITY_DESCRIPTOR, error) {
	user, err := currentUser(ctx)
	if err != nil {
		return nil, err
	}
	inherit := ""
	if directory {
		inherit = "OICI"
	}
	sid := user.String()
	descriptor, err := windows.SecurityDescriptorFromString(fmt.Sprintf("O:%sD:P(A;%s;FA;;;%s)", sid, inherit, sid))
	if err != nil {
		return nil, unreadableError(err)
	}
	return descriptor, nil
}

// CreatePrivateFileAt exclusively creates a protected owner-only regular file
// immediately below parent.
func CreatePrivateFileAt(ctx context.Context, parent *Directory, name string) (*PrivateFile, error) {
	file, _, err := createPrivateFileAt(ctx, parent, name, windows.FILE_CREATE)
	return file, err
}

// EnsurePrivateFileAt opens a protected owner-only regular file immediately
// below parent, creating it if absent. Existing objects are checked, never
// repaired or truncated.
func EnsurePrivateFileAt(ctx context.Context, parent *Directory, name string) (*PrivateFile, error) {
	file, _, err := createPrivateFileAt(ctx, parent, name, windows.FILE_OPEN_IF)
	return file, err
}

func createPrivateFileAt(ctx context.Context, parent *Directory, name string, disposition uint32) (*PrivateFile, bool, error) {
	if err := CheckSafeDirectory(ctx, parent, true); err != nil {
		return nil, false, wrapAccess("open private file", err)
	}
	if err := checkWindowsComponent(name); err != nil {
		return nil, false, wrapAccess("open private file", err)
	}
	descriptor, err := privateDescriptor(ctx, false)
	if err != nil {
		return nil, false, wrapAccess("open private file", err)
	}
	var handle windows.Handle
	var created bool
	parentFile := rawObject(parent)
	err = withHandle(parentFile, func(parentHandle windows.Handle) error {
		if err := qualifyHandle(ctx, parentHandle, true); err != nil {
			return err
		}
		opened, status, openErr := ntCreate(parentHandle, name, privateMutableAccess, windows.FILE_NON_DIRECTORY_FILE, disposition, descriptor)
		if openErr != nil {
			if disposition == windows.FILE_CREATE && errors.Is(openErr, os.ErrExist) {
				return &classifiedCause{class: ClassUnsafe, cause: errEntryExists, reason: "private file already exists"}
			}
			return openErr
		}
		created = status == fileCreated
		if err := qualifyHandle(ctx, opened, false); err != nil {
			if created {
				_ = discardWindowsHandle(opened)
			}
			windows.CloseHandle(opened)
			return err
		}
		handle = opened
		return nil
	})
	if err != nil {
		return nil, false, wrapAccess("open private file", err)
	}
	private := &PrivateFile{file: os.NewFile(uintptr(handle), childWindowsName(parentFile, name))}
	if err := CheckPrivate(ctx, private, false); err != nil {
		var removeErr error
		if created {
			removeErr = withHandle(private.file, discardWindowsHandle)
		}
		closeErr := private.file.Close()
		return nil, false, wrapAccess("open private file", errors.Join(err, removeErr, closeErr))
	}
	return private, created, nil
}

// CreatePrivateDirectoryAt exclusively creates a protected owner-only
// directory immediately below parent.
func CreatePrivateDirectoryAt(ctx context.Context, parent *Directory, name string) (*Directory, error) {
	directory, _, err := createPrivateDirectoryAt(ctx, parent, name, windows.FILE_CREATE)
	return directory, err
}

// EnsurePrivateDirectoryAt opens a protected owner-only directory immediately
// below parent, creating it if absent. Existing directories are never repaired.
func EnsurePrivateDirectoryAt(ctx context.Context, parent *Directory, name string) (*Directory, error) {
	directory, _, err := createPrivateDirectoryAt(ctx, parent, name, windows.FILE_OPEN_IF)
	return directory, err
}

func createPrivateDirectoryAt(ctx context.Context, parent *Directory, name string, disposition uint32) (*Directory, bool, error) {
	if err := CheckSafeDirectory(ctx, parent, true); err != nil {
		return nil, false, wrapAccess("open private directory", err)
	}
	return createPrivateDirectoryAtQualified(ctx, parent, name, disposition)
}

func createPrivateDirectoryAtQualified(ctx context.Context, parent *Directory, name string, disposition uint32) (*Directory, bool, error) {
	if err := checkWindowsComponent(name); err != nil {
		return nil, false, wrapAccess("open private directory", err)
	}
	descriptor, err := privateDescriptor(ctx, true)
	if err != nil {
		return nil, false, wrapAccess("open private directory", err)
	}
	var handle windows.Handle
	var created bool
	parentFile := rawObject(parent)
	err = withHandle(parentFile, func(parentHandle windows.Handle) error {
		if err := qualifyHandle(ctx, parentHandle, true); err != nil {
			return err
		}
		opened, status, openErr := ntCreate(parentHandle, name, privateMutableAccess, windows.FILE_DIRECTORY_FILE, disposition, descriptor)
		if openErr != nil {
			if disposition == windows.FILE_CREATE && errors.Is(openErr, os.ErrExist) {
				return &classifiedCause{class: ClassUnsafe, cause: errEntryExists, reason: "private directory already exists"}
			}
			return openErr
		}
		created = status == fileCreated
		if err := qualifyHandle(ctx, opened, true); err != nil {
			if created {
				_ = discardWindowsHandle(opened)
			}
			windows.CloseHandle(opened)
			return err
		}
		handle = opened
		return nil
	})
	if err != nil {
		return nil, false, wrapAccess("open private directory", err)
	}
	directory := &Directory{file: os.NewFile(uintptr(handle), childWindowsName(parentFile, name))}
	if err := CheckPrivate(ctx, directory, true); err != nil {
		var removeErr error
		if created {
			removeErr = withHandle(directory.file, discardWindowsHandle)
		}
		closeErr := directory.file.Close()
		return nil, false, wrapAccess("open private directory", errors.Join(err, removeErr, closeErr))
	}
	return directory, created, nil
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
	parsed, err := parseLocalPath(path)
	if err != nil {
		return nil, wrapAccess("open private directory", err)
	}
	if len(parsed.parts) == 0 {
		return nil, wrapAccess("open private directory", unsafeCause("volume root cannot be private state"))
	}
	handle, err := openVolumeRoot(ctx, parsed.drive)
	if err != nil {
		return nil, wrapAccess("open private directory", err)
	}
	current := &Directory{file: os.NewFile(uintptr(handle), string(parsed.drive)+`:\`)}
	if err := CheckSafeDirectory(ctx, current, false); err != nil {
		current.Close()
		return nil, wrapAccess("open private directory", err)
	}
	for i, part := range parsed.parts {
		last := i == len(parsed.parts)-1
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
			openErr = CheckSafeDirectory(ctx, next, i == len(parsed.parts)-2)
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

func discardWindowsHandle(handle windows.Handle) error {
	info := fileDispositionInformationEx{Flags: windows.FILE_DISPOSITION_DELETE |
		windows.FILE_DISPOSITION_POSIX_SEMANTICS |
		windows.FILE_DISPOSITION_FORCE_IMAGE_SECTION_CHECK}
	var status windows.IO_STATUS_BLOCK
	return windows.NtSetInformationFile(handle, &status, (*byte)(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)), windows.FileDispositionInformationEx)
}
