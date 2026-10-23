//go:build windows

package fileaccess

import (
	"context"
	"errors"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

const fileLinkInformationLegacy = 11

type fileLinkInformation struct {
	ReplaceIfExists bool
	RootDirectory   windows.Handle
	FileNameLength  uint32
	FileName        [windows.MAX_PATH]uint16
}

type fileDispositionInformationEx struct {
	Flags uint32
}

func checkPrivateComponent(name string) error { return checkWindowsComponent(name) }

func openExistingPrivateFileAt(ctx context.Context, parent *Directory, name string) (*PrivateFile, error) {
	file, _, err := createPrivateFileAt(ctx, parent, name, windows.FILE_OPEN)
	return file, err
}

func linkPrivateEntry(ctx context.Context, parent *Directory, stage, name, identity string) error {
	if err := checkPrivateComponent(stage); err != nil {
		return err
	}
	if err := checkPrivateComponent(name); err != nil {
		return err
	}
	opened, err := openExistingPrivateFileAt(ctx, parent, stage)
	if err != nil {
		return err
	}
	defer opened.Close()
	got, err := PhysicalIdentity(ctx, opened)
	if err != nil || got != identity {
		return unsafeCause("private stage identity changed")
	}
	encoded, err := windows.UTF16FromString(name)
	if err != nil || len(encoded) > windows.MAX_PATH {
		return unsafeCause("publication name is too long")
	}
	info := fileLinkInformation{RootDirectory: windows.InvalidHandle}
	copy(info.FileName[:], encoded)
	info.FileNameLength = uint32((len(encoded) - 1) * 2)
	parentFile := rawObject(parent)
	err = withHandle(parentFile, func(parentHandle windows.Handle) error {
		info.RootDirectory = parentHandle
		return withHandle(rawObject(opened), func(stageHandle windows.Handle) error {
			var status windows.IO_STATUS_BLOCK
			err := windows.NtSetInformationFile(stageHandle, &status, (*byte)(unsafe.Pointer(&info)),
				uint32(unsafe.Sizeof(info)), fileLinkInformationLegacy)
			if err != nil {
				err = normalizeNTStatus(err)
				if errors.Is(err, os.ErrExist) {
					return unsafeCause("publication destination already exists")
				}
			}
			return err
		})
	})
	return err
}

func removePrivateEntry(ctx context.Context, parent *Directory, name, identity string) error {
	opened, err := openExistingPrivateFileAt(ctx, parent, name)
	if err != nil {
		return err
	}
	got, err := PhysicalIdentity(ctx, opened)
	if err != nil || got != identity {
		_ = opened.Close()
		return unsafeCause("private stage identity changed")
	}
	removeErr := withHandle(rawObject(opened), func(handle windows.Handle) error {
		info := fileDispositionInformationEx{Flags: windows.FILE_DISPOSITION_DELETE |
			windows.FILE_DISPOSITION_POSIX_SEMANTICS |
			windows.FILE_DISPOSITION_FORCE_IMAGE_SECTION_CHECK}
		var status windows.IO_STATUS_BLOCK
		if err := windows.NtSetInformationFile(handle, &status, (*byte)(unsafe.Pointer(&info)),
			uint32(unsafe.Sizeof(info)), windows.FileDispositionInformationEx); err != nil {
			return unreadableError(normalizeNTStatus(err))
		}
		return nil
	})
	closeErr := opened.Close()
	return errors.Join(removeErr, closeErr)
}
