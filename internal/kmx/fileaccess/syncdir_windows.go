//go:build windows

// Package fileaccess holds platform-specific handle operations for KMX's
// private on-disk state.
package fileaccess

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// OpenSyncDirectory opens the directory anchored by root so the caller can
// Sync it after publishing entries there. The caller closes the result and
// treats a Sync failure as fatal.
//
// Windows Sync is FlushFileBuffers, which requires GENERIC_WRITE, and
// root.Open(".") yields a read-only handle. Rather than re-resolving the
// root by path, this reopens the anchored handle itself with read/write
// access, then confirms the new handle is the same non-reparse directory.
// It protects only the anchored root; it does not police path components
// below it.
func OpenSyncDirectory(root *os.Root) (*os.File, error) {
	source, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	defer source.Close()

	conn, err := source.SyscallConn()
	if err != nil {
		return nil, err
	}
	reopened := windows.InvalidHandle
	var reopenErr error
	if err := conn.Control(func(fd uintptr) {
		sourceHandle := windows.Handle(fd)
		reopened, reopenErr = reopenDirectory(sourceHandle)
		if reopenErr == nil {
			if reopenErr = checkSyncDirectory(sourceHandle, reopened); reopenErr != nil {
				_ = windows.CloseHandle(reopened)
			}
		}
	}); err != nil {
		return nil, err
	}
	if reopenErr != nil {
		return nil, &os.PathError{Op: "reopen for sync", Path: source.Name(), Err: reopenErr}
	}
	return os.NewFile(uintptr(reopened), source.Name()), nil
}

func reopenDirectory(original windows.Handle) (windows.Handle, error) {
	// An empty relative name opens the directory object itself. A dot name is
	// not equivalent for NtCreateFile, and resolving a pathname would discard
	// the caller's anchored identity.
	name, err := windows.NewNTUnicodeString("")
	if err != nil {
		return windows.InvalidHandle, err
	}
	attributes := windows.OBJECT_ATTRIBUTES{RootDirectory: original, ObjectName: name, Attributes: windows.OBJ_DONT_REPARSE}
	attributes.Length = uint32(unsafe.Sizeof(attributes))
	var handle windows.Handle
	err = windows.NtCreateFile(&handle, windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE|windows.SYNCHRONIZE,
		&attributes, &windows.IO_STATUS_BLOCK{}, nil, windows.FILE_ATTRIBUTE_NORMAL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, windows.FILE_OPEN,
		windows.FILE_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT, 0, 0)
	if err != nil {
		if status, ok := err.(windows.NTStatus); ok {
			return windows.InvalidHandle, status.Errno()
		}
		return windows.InvalidHandle, err
	}
	return handle, nil
}

// checkSyncDirectory refuses a reopened handle that is not an on-disk,
// non-reparse directory with the same volume and file identity as source.
func checkSyncDirectory(source, reopened windows.Handle) error {
	typ, err := windows.GetFileType(reopened)
	if err != nil {
		return err
	}
	if typ != windows.FILE_TYPE_DISK {
		return fmt.Errorf("reopened handle is not a disk file (type %d)", typ)
	}
	var got windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(reopened, &got); err != nil {
		return err
	}
	if got.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return errors.New("reopened handle is not a directory")
	}
	if got.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("reopened directory is a reparse point")
	}
	// Match the qualified filesystem and full identity contract used by
	// PhysicalIdentity, rather than the legacy 32-bit volume/64-bit file ID.
	if err := requireNTFS(source); err != nil {
		return err
	}
	if err := requireNTFS(reopened); err != nil {
		return err
	}
	var sourceID, reopenedID fileIDInfo
	for _, query := range []struct {
		handle windows.Handle
		id     *fileIDInfo
	}{{source, &sourceID}, {reopened, &reopenedID}} {
		if err := windows.GetFileInformationByHandleEx(query.handle, windows.FileIdInfo,
			(*byte)(unsafe.Pointer(query.id)), uint32(unsafe.Sizeof(*query.id))); err != nil {
			return err
		}
	}
	if sourceID != reopenedID {
		return errors.New("reopened handle names a different directory")
	}
	return nil
}
