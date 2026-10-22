//go:build windows

package fileaccess

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func windowsTestUser(t *testing.T) string {
	t.Helper()
	user, err := currentUser(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return user.String()
}

// setTestACL modifies only disposable test objects. Product fileaccess has no
// security mutation API and never repairs an object it refuses.
func setTestACL(t *testing.T, path, dacl string, protected bool) {
	t.Helper()
	user := windowsTestUser(t)
	installTestACL(t, path, user, dacl, protected)
	t.Cleanup(func() {
		installTestDACL(t, path, user, "P(A;OICI;FA;;;"+user+")", true)
	})
}

func installTestACL(t *testing.T, path, user, dacl string, protected bool) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString("O:" + user + "D:" + dacl)
	if err != nil {
		t.Fatalf("parse fixture security descriptor: %v", err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	flags := windows.SECURITY_INFORMATION(windows.OWNER_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION)
	if protected {
		flags |= windows.PROTECTED_DACL_SECURITY_INFORMATION
	} else {
		flags |= windows.UNPROTECTED_DACL_SECURITY_INFORMATION
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, flags, owner, nil, acl, nil); err != nil {
		t.Fatalf("install fixture security descriptor: %v", err)
	}
}

func installTestDACL(t *testing.T, path, user, dacl string, protected bool) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString("O:" + user + "D:" + dacl)
	if err != nil {
		t.Fatalf("parse cleanup security descriptor: %v", err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	flags := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION)
	if protected {
		flags |= windows.PROTECTED_DACL_SECURITY_INFORMATION
	} else {
		flags |= windows.UNPROTECTED_DACL_SECURITY_INFORMATION
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, flags, nil, nil, acl, nil); err != nil {
		t.Fatalf("restore fixture DACL: %v", err)
	}
}

func securitySnapshot(t *testing.T, path string) string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	return sd.String()
}

func makeJunction(t *testing.T, link, target string) {
	t.Helper()
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Fatalf("create junction: %v: %s", err, out)
	}
}

func openReparsePoint(t *testing.T, path string) *os.File {
	t.Helper()
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(handle), path)
	t.Cleanup(func() { _ = file.Close() })
	return file
}

func shortPath(t *testing.T, path string) string {
	t.Helper()
	long, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]uint16, 1024)
	n, err := windows.GetShortPathName(long, &buf[0], uint32(len(buf)))
	if err != nil {
		t.Fatalf("query short path: %v", err)
	}
	return windows.UTF16ToString(buf[:n])
}

func currentVolumeRoot(t *testing.T) string {
	t.Helper()
	dir := foundationTempDir(t)
	volume := filepath.VolumeName(dir)
	if len(volume) != 2 || volume[1] != ':' {
		t.Fatalf("temporary directory is not on a drive-letter volume: %s", dir)
	}
	return volume + `\`
}
