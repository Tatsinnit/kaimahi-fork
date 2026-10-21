//go:build windows

package oras

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/kaimahi-agents/kaimahi/internal/kmx/fileaccess"
	"golang.org/x/sys/windows"
)

// On Windows the public loose-suite reader requires a protected
// current-user-only source root, so source fixtures are new private roots
// rather than t.TempDir's inherited ACL; nothing in the checks is relaxed.

// privateFixtureDir creates path as a new protected private directory.
func privateFixtureDir(t *testing.T, path string) string {
	t.Helper()
	if err := fileaccess.EnsurePrivatePath(path); err != nil {
		t.Fatal(err)
	}
	return path
}

// emptyFixtureDir is a new empty private root.
func emptyFixtureDir(t *testing.T) string {
	t.Helper()
	return privateFixtureDir(t, filepath.Join(t.TempDir(), "empty"))
}

// fixtureSource copies the checked-in fixture into a new private root.
func fixtureSource(t *testing.T, path string) string {
	t.Helper()
	copy := privateFixtureDir(t, filepath.Join(t.TempDir(), "fixture"))
	copyDirectory(t, path, copy)
	return copy
}

// symlinkPrivilegeMissing identifies the one disclosed gap: creating a
// symbolic link needs SeCreateSymbolicLinkPrivilege (or Developer Mode),
// which an ordinary session lacks. Junction counterparts run instead.
func symlinkPrivilegeMissing(err error) bool {
	return errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD)
}

// sharedWritableRefusal is the suite's Windows refusal of any grant beyond
// the owner; Windows has no group bits, so the fixture adds a real ACE.
const sharedWritableRefusal = "invalid or non-owner grant"

func makeSharedWritable(t *testing.T, path string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString("D:(A;;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
}
