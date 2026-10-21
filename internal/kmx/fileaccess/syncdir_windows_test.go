//go:build windows

package fileaccess

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// openNoFollow opens path itself, never a reparse target, for read-only
// inspection by the handle checks.
func openNoFollow(t *testing.T, path string) windows.Handle {
	t.Helper()
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatalf("UTF16PtrFromString: %v", err)
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatalf("CreateFile %s: %v", path, err)
	}
	t.Cleanup(func() { _ = windows.CloseHandle(h) })
	return h
}

func TestOpenSyncDirectoryRefusesReadOnlyACL(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "read-only")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := user.User.Sid
	sd, err := windows.SecurityDescriptorFromString(fmt.Sprintf("O:%sD:P(A;;0x%x;;;%s)", sid, windows.FILE_GENERIC_READ|windows.FILE_GENERIC_EXECUTE, sid))
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	// This is a newly owned disposable fixture, not repair of user state.
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		sid, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	opened, err := OpenSyncDirectory(root)
	if err == nil {
		opened.Close()
		t.Fatal("write-capable directory open succeeded under a read-only DACL")
	}
	if !errors.Is(err, os.ErrPermission) {
		t.Fatalf("OpenSyncDirectory error = %v, want permission refusal", err)
	}
}

func TestCheckSyncDirectoryAcceptsSameDirectory(t *testing.T) {
	dir := t.TempDir()
	source := openNoFollow(t, dir)
	reopened := openNoFollow(t, dir)

	if err := checkSyncDirectory(source, reopened); err != nil {
		t.Fatalf("checkSyncDirectory = %v, want nil", err)
	}
}

func TestCheckSyncDirectoryRejectsRegularFile(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatalf("create file: %v", err)
	}

	err := checkSyncDirectory(openNoFollow(t, dir), openNoFollow(t, file))
	if err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("checkSyncDirectory = %v, want not-a-directory refusal", err)
	}
}

func TestCheckSyncDirectoryRejectsDifferentDirectory(t *testing.T) {
	err := checkSyncDirectory(openNoFollow(t, t.TempDir()), openNoFollow(t, t.TempDir()))
	if err == nil || !strings.Contains(err.Error(), "different directory") {
		t.Fatalf("checkSyncDirectory = %v, want identity refusal", err)
	}
}

func TestCheckSyncDirectoryRejectsReparsePoint(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "junction")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatalf("mkdir target: %v", err)
	}
	// Junctions do not need the symbolic-link privilege, so this runs as an
	// ordinary user.
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v: %s", err, out)
	}
	junction := openNoFollow(t, link)

	err := checkSyncDirectory(junction, junction)
	if err == nil || !strings.Contains(err.Error(), "reparse point") {
		t.Fatalf("checkSyncDirectory = %v, want reparse-point refusal", err)
	}
}
