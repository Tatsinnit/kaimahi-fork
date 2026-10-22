//go:build windows

package fileaccess

import (
	"strings"

	"golang.org/x/sys/windows"
)

var volumeInformationByHandle = windows.GetVolumeInformationByHandle

func requireQualifiedFilesystem(handle windows.Handle) error {
	name := make([]uint16, windows.MAX_PATH+1)
	var flags uint32
	if err := volumeInformationByHandle(handle, nil, 0, nil, nil, &flags, &name[0], uint32(len(name))); err != nil {
		return unreadableError(err)
	}
	return checkFilesystemInformation(windows.UTF16ToString(name), flags)
}

func checkFilesystemInformation(name string, flags uint32) error {
	if !strings.EqualFold(name, "NTFS") {
		return unsupportedCause("filesystem is not qualified local NTFS")
	}
	if flags&windows.FILE_PERSISTENT_ACLS == 0 {
		return unsupportedCause("filesystem does not enforce persistent ACLs")
	}
	return nil
}
