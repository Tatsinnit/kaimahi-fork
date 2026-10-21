//go:build windows

package fileaccess

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// fileAllAccess is FILE_ALL_ACCESS, the "FA" grant in SDDL.
const fileAllAccess = windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0x1ff

// faRequireExplicitPrivate checks the exact descriptor KMX creates: the
// current user as owner and one protected full-control grant to that user.
func faRequireExplicitPrivate(t *testing.T, path string, dir bool) {
	t.Helper()
	handle := openNoFollow(t, path)
	owner, control, dacl, err := securityOf(handle)
	if err != nil {
		t.Fatalf("security of %s: %v", path, err)
	}
	user, err := currentUser()
	if err != nil {
		t.Fatal(err)
	}
	if !owner.Equals(user) || control&windows.SE_DACL_PROTECTED == 0 || dacl.AceCount != 1 {
		t.Fatalf("%s descriptor is not explicit private: %s", path, faSecuritySnapshot(t, path))
	}
	ace, sid, err := aceAt(dacl, 0)
	if err != nil {
		t.Fatal(err)
	}
	wantFlags := uint8(0)
	if dir {
		wantFlags = windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE
	}
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || !sid.Equals(user) || ace.Mask != fileAllAccess || ace.Header.AceFlags != wantFlags {
		t.Fatalf("%s grant is not owner full control: %s", path, faSecuritySnapshot(t, path))
	}
	if err := checkPrivateObject(handle, dir, true); err != nil {
		t.Fatalf("CheckPrivate(%s, root) = %v", path, err)
	}
}

// Under a parent that hands every principal full control through
// inheritance, each creation helper still produces an explicit protected
// owner-only object rather than an inherited broad one.
func TestCreationUsesExplicitDescriptorDespiteBroadInheritance(t *testing.T) {
	user := faUser(t)
	parentPath := faMkdir(t, filepath.Join(t.TempDir(), "broad"))
	faSetACL(t, parentPath, "P(A;OICI;FA;;;"+user+")(A;OICI;FA;;;WD)", true)
	parent := faOpenDir(t, parentPath)

	file, err := OpenPrivateAt(parent, "file", os.O_RDWR|os.O_CREATE|os.O_EXCL)
	if err != nil {
		t.Fatal(err)
	}
	file.Close()
	faRequireExplicitPrivate(t, filepath.Join(parentPath, "file"), false)

	dir, err := EnsurePrivateDirectoryAt(parent, "dir")
	if err != nil {
		t.Fatal(err)
	}
	dir.Close()
	faRequireExplicitPrivate(t, filepath.Join(parentPath, "dir"), true)

	// The path helpers additionally refuse this unsafe immediate parent.
	if err := EnsurePrivatePath(filepath.Join(parentPath, "state")); err == nil || !strings.Contains(err.Error(), "untrusted access") {
		t.Fatalf("EnsurePrivatePath under broad parent = %v", err)
	}
	if err := WritePrivateFile(filepath.Join(parentPath, "written"), nil, 0o600); err == nil {
		t.Fatal("WritePrivateFile accepted a broad immediate parent")
	}
	if dir, err := PrivateTempDir(parentPath, "kmx-"); err == nil {
		t.Fatalf("PrivateTempDir created %s under a broad parent", dir)
	}
	for _, name := range []string{"state", "written"} {
		if _, err := os.Lstat(filepath.Join(parentPath, name)); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("refused helper created %s: %v", name, err)
		}
	}
}

func TestPathHelpersCreateExplicitPrivateObjects(t *testing.T) {
	base := t.TempDir()
	state := filepath.Join(base, "missing", "intermediate", "state")
	if err := EnsurePrivatePath(state); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(base, "missing"), filepath.Join(base, "missing", "intermediate"), state} {
		faRequireExplicitPrivate(t, path, true)
	}
	if err := WritePrivateFile(filepath.Join(state, "config"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	faRequireExplicitPrivate(t, filepath.Join(state, "config"), false)
	temp, err := PrivateTempDir(state, "")
	if err != nil {
		t.Fatal(err)
	}
	faRequireExplicitPrivate(t, temp, true)
	defaultTemp, err := PrivateTempDir("", "kmx-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(defaultTemp)
	if !strings.EqualFold(filepath.Dir(defaultTemp), filepath.Clean(os.TempDir())) {
		t.Fatalf("PrivateTempDir(\"\") = %s, want a child of %s", defaultTemp, os.TempDir())
	}
	faRequireExplicitPrivate(t, defaultTemp, true)
}

func TestEnsurePrivatePathRefusesExistingWithoutRepair(t *testing.T) {
	user := faUser(t)
	for _, tc := range []struct{ name, dacl, want string }{
		{"Inherited", "", "not protected"},
		{"ProtectedBroad", "P(A;OICI;FA;;;" + user + ")(A;;FR;;;AU)", "non-owner grant"},
		{"ProtectedSystem", "P(A;OICI;FA;;;" + user + ")(A;OICI;FA;;;SY)", "non-owner grant"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := faMkdir(t, filepath.Join(t.TempDir(), "state"))
			if tc.dacl != "" {
				faSetACL(t, dir, tc.dacl, true)
			}
			before := faSecuritySnapshot(t, dir)
			if err := EnsurePrivatePath(dir); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("EnsurePrivatePath(existing %s) = %v, want %q", tc.name, err, tc.want)
			}
			if after := faSecuritySnapshot(t, dir); after != before {
				t.Fatalf("refusal repaired security:\n%s\n%s", before, after)
			}
		})
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := EnsurePrivatePath(file); err == nil {
		t.Fatal("EnsurePrivatePath accepted a regular file")
	}
	if err := EnsurePrivatePath(`C:\`); err == nil {
		t.Fatal("EnsurePrivatePath accepted a volume root")
	}
}

func TestEnsurePrivatePathAncestorPolicy(t *testing.T) {
	user := faUser(t)
	ancestor := faMkdir(t, filepath.Join(t.TempDir(), "shared"))
	// Others may only add subdirectories: tolerated above the immediate parent.
	faSetACL(t, ancestor, "P(A;OICI;FA;;;"+user+")(A;;0x4;;;AU)(A;;0x1200a9;;;AU)", true)
	parent := faMkdir(t, filepath.Join(ancestor, "parent"))
	if err := EnsurePrivatePath(filepath.Join(parent, "state")); err != nil {
		t.Fatalf("EnsurePrivatePath below create-only ancestor = %v", err)
	}
	if err := EnsurePrivatePath(filepath.Join(ancestor, "direct")); err == nil || !strings.Contains(err.Error(), "untrusted access") {
		t.Fatalf("EnsurePrivatePath with create-only immediate parent = %v", err)
	}
	writable := faMkdir(t, filepath.Join(t.TempDir(), "writable"))
	faSetACL(t, writable, "P(A;OICI;FA;;;"+user+")(A;OICI;0x1301bf;;;AU)", true)
	faMkdir(t, filepath.Join(writable, "below"))
	if err := EnsurePrivatePath(filepath.Join(writable, "below", "state")); err == nil || !strings.Contains(err.Error(), "untrusted access") {
		t.Fatalf("EnsurePrivatePath below writable ancestor = %v", err)
	}
	if _, err := os.Lstat(filepath.Join(writable, "below", "state")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("refused EnsurePrivatePath created state: %v", err)
	}
}

func TestOpenPrivateAtHonorsReadOnlyDACLWithoutRepair(t *testing.T) {
	dir := faPrivateDir(t)
	path := filepath.Join(dir, "readonly")
	if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	faSetACL(t, path, "P(A;;FR;;;"+faUser(t)+")", true)
	before := faSecuritySnapshot(t, path)
	parent := faOpenDir(t, dir)
	read, err := OpenPrivateAt(parent, "readonly", os.O_RDONLY)
	if err != nil {
		t.Fatalf("read-only private open = %v", err)
	}
	read.Close()
	for _, flags := range []int{os.O_RDWR, os.O_WRONLY | os.O_TRUNC, os.O_RDWR | os.O_CREATE} {
		if f, err := OpenPrivateAt(parent, "readonly", flags); !errors.Is(err, fs.ErrPermission) {
			if err == nil {
				f.Close()
			}
			t.Fatalf("OpenPrivateAt(%#x) under read-only DACL = %v, want permission error", flags, err)
		}
	}
	if err := WritePrivateFile(path, []byte("replaced"), 0o600); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("WritePrivateFile under read-only DACL = %v, want permission error", err)
	}
	if data, _ := os.ReadFile(path); string(data) != "keep" {
		t.Fatalf("contents changed to %q", data)
	}
	if after := faSecuritySnapshot(t, path); after != before {
		t.Fatalf("security changed:\n%s\n%s", before, after)
	}
}

func TestWritePrivateFileRefusals(t *testing.T) {
	dir := faPrivateDir(t)
	if err := WritePrivateFile(filepath.Join(dir, "public"), []byte("x"), 0o644); err == nil {
		t.Fatal("WritePrivateFile accepted a group/other permission")
	}
	if _, err := os.Lstat(filepath.Join(dir, "public")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("refused WritePrivateFile created a file: %v", err)
	}
	shared := filepath.Join(dir, "shared")
	if err := os.WriteFile(shared, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	faMakeUnsafe(t, shared)
	before := faSecuritySnapshot(t, shared)
	if err := WritePrivateFile(shared, []byte("replaced"), 0o600); err == nil || !strings.Contains(err.Error(), "non-owner grant") {
		t.Fatalf("WritePrivateFile over broad file = %v", err)
	}
	if data, _ := os.ReadFile(shared); string(data) != "keep" {
		t.Fatalf("contents changed to %q", data)
	}
	if after := faSecuritySnapshot(t, shared); after != before {
		t.Fatalf("security changed:\n%s\n%s", before, after)
	}
	if err := WritePrivateFile(`C:\`, nil, 0o600); err == nil {
		t.Fatal("WritePrivateFile accepted a volume root")
	}
}

func TestTryLockReportsLockViolation(t *testing.T) {
	_, file := faLockFile(t)
	parent := faOpenDir(t, filepath.Dir(file.Name()))
	second, err := OpenPrivateAt(parent, "lock", os.O_RDONLY)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if err := TryLock(file); err != nil {
		t.Fatal(err)
	}
	if err := TryLock(second); !errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		t.Fatalf("TryLock(read-only second handle) = %v, want ERROR_LOCK_VIOLATION", err)
	}
	if err := TryLock(nil); err == nil {
		t.Fatal("TryLock(nil) succeeded")
	}
}
