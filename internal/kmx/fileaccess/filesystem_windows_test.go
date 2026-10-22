//go:build windows

package fileaccess

import (
	"errors"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsFilesystemQualification(t *testing.T) {
	if err := checkFilesystemInformation("NTFS", windows.FILE_PERSISTENT_ACLS); err != nil {
		t.Fatalf("qualified NTFS = %v", err)
	}
	for _, tc := range []struct {
		name  string
		flags uint32
	}{
		{"ReFS", windows.FILE_PERSISTENT_ACLS},
		{"NTFS", 0},
		{"", windows.FILE_PERSISTENT_ACLS},
	} {
		if err := checkFilesystemInformation(tc.name, tc.flags); !errors.Is(err, ErrUnsupported) {
			t.Errorf("filesystem %q flags %#x = %v", tc.name, tc.flags, err)
		}
	}
	if err := checkDeviceInformation(fileDeviceDisk, 0); err != nil {
		t.Fatalf("local disk = %v", err)
	}
	for _, tc := range []struct{ kind, characteristics uint32 }{
		{fileDeviceDisk, fileRemoteDevice},
		{0x11, 0},
	} {
		if err := checkDeviceInformation(tc.kind, tc.characteristics); !errors.Is(err, ErrUnsupported) {
			t.Errorf("device %#x/%#x = %v", tc.kind, tc.characteristics, err)
		}
	}
}

func TestWindowsTemporaryVolumeIsQualified(t *testing.T) {
	dir := openTestDirectory(t, foundationTempDir(t))
	if err := withHandle(rawObject(dir), requireQualifiedFilesystem); err != nil {
		t.Fatalf("hosted temporary volume is outside the qualified local NTFS boundary: %v", err)
	}
}
