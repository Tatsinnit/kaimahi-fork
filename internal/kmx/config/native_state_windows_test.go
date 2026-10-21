//go:build windows

package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"github.com/kaimahi-agents/kaimahi/internal/kmx/fileaccess"
	"golang.org/x/sys/windows"
)

// privateStateHome is a NEW protected current-user-only directory. Windows
// fixtures never relax production policy to adopt t.TempDir's inherited ACL.
func privateStateHome(t *testing.T) string {
	t.Helper()
	dir, err := fileaccess.PrivateTempDir(t.TempDir(), "kmx-home-")
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

// expectedNativeStateDir isolates LocalAppData in a private fixture so the
// default-path test never touches the real profile.
func expectedNativeStateDir(t *testing.T, _ string) string {
	t.Helper()
	local := privateStateHome(t)
	t.Setenv("LOCALAPPDATA", local)
	t.Setenv("APPDATA", privateStateHome(t))
	return filepath.Join(local, "kmx")
}

func currentUserSID(t *testing.T) *windows.SID {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	return user.User.Sid
}

func securityDescriptor(t *testing.T, path string) *windows.SECURITY_DESCRIPTOR {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("security of %s: %v", path, err)
	}
	return sd
}

// assertOwnerOnly independently checks the object: owner is the current
// user and the DACL is protected with only allow entries for that user.
func assertOwnerOnly(t *testing.T, path string) {
	t.Helper()
	user := currentUserSID(t)
	sd := securityDescriptor(t, path)
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !owner.Equals(user) {
		t.Fatalf("%s owner = %v, %v; want %v", path, owner, err, user)
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("%s DACL not protected: %v %v (%s)", path, control, err, sd)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil || dacl.AceCount == 0 {
		t.Fatalf("%s missing DACL: %v (%s)", path, err, sd)
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatal(err)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || !sid.Equals(user) {
			t.Fatalf("%s grants beyond the current user: %s", path, sd)
		}
	}
}

// grantEveryone replaces the DACL with a protected one that also lets
// Everyone in, producing an unsafe existing object without mounting anything.
func grantEveryone(t *testing.T, path string) {
	t.Helper()
	inherit := ""
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		inherit = "OICI"
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;" + inherit + ";FA;;;WD)(A;" + inherit + ";FA;;;" + currentUserSID(t).String() + ")")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
}

func assertAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("%s exists: %v", path, err)
	}
}

func TestWindowsStateDefaultsToLocalAppDataNotRoamingOrHome(t *testing.T) {
	local, roaming, home := privateStateHome(t), privateStateHome(t), privateStateHome(t)
	t.Setenv("KMX_HOME", "")
	t.Setenv("LOCALAPPDATA", local)
	t.Setenv("APPDATA", roaming)
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	want := filepath.Join(local, "kmx")
	for i := 0; i < 2; i++ { // create, then check the existing root
		if got, err := StateDir(); err != nil || got != want {
			t.Fatalf("state dir = %q, %v; want %q", got, err, want)
		}
	}
	assertOwnerOnly(t, want)
	for name, tc := range map[string]struct {
		get  func() (string, error)
		want string
	}{
		"cache":     {CacheDir, filepath.Join(want, "bin")},
		"lift":      {LiftRecordDir, filepath.Join(want, "lift")},
		"toolchain": {ToolchainDir, filepath.Join(want, "path")},
	} {
		if got, err := tc.get(); err != nil || got != tc.want {
			t.Fatalf("%s = %q, %v; want %q", name, got, err, tc.want)
		}
	}
	for _, path := range []string{filepath.Join(roaming, "kmx"), filepath.Join(home, ".kmx"), filepath.Join(home, "kmx")} {
		assertAbsent(t, path)
	}
}

// Only the LocalAppData known folder replaces an empty LOCALAPPDATA; this
// calls the resolver directly so the real profile is never created.
func TestWindowsNativeStateFallsBackOnlyToKnownLocalAppData(t *testing.T) {
	roaming := privateStateHome(t)
	t.Setenv("APPDATA", roaming)
	t.Setenv("LOCALAPPDATA", "")
	known, err := windows.KnownFolderPath(windows.FOLDERID_LocalAppData, windows.KF_FLAG_DONT_VERIFY)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := nativeStateDirectory(); err != nil || got != filepath.Join(known, "kmx") || strings.HasPrefix(got, roaming) {
		t.Fatalf("fallback = %q, %v; want %q", got, err, filepath.Join(known, "kmx"))
	}
	for _, bad := range []string{`relative\dir`, `C:relative`} {
		t.Setenv("LOCALAPPDATA", bad)
		if got, err := nativeStateDirectory(); err == nil || !strings.Contains(err.Error(), "LOCALAPPDATA") {
			t.Fatalf("relative LOCALAPPDATA %q = %q, %v", bad, got, err)
		}
	}
}

// An existing state root with a broad ACL is refused by every resolver and
// writer; nothing is repaired, adopted or written.
func TestWindowsStateRootRefusesBroadACLWithoutRepair(t *testing.T) {
	for name, fixture := range map[string]func(t *testing.T) string{
		"inherited temp ACL": func(t *testing.T) string { return t.TempDir() },
		"explicit Everyone": func(t *testing.T) string {
			dir := privateStateHome(t)
			grantEveryone(t, dir)
			return dir
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := fixture(t)
			before := securityDescriptor(t, dir).String()
			t.Setenv("KMX_HOME", dir)
			t.Setenv("KUBE_CTX", "")
			for name, get := range map[string]func() (string, error){
				"state": StateDir, "cache": CacheDir, "lift": LiftRecordDir, "toolchain": ToolchainDir,
			} {
				if got, err := get(); err == nil {
					t.Fatalf("%s accepted unsafe root: %q", name, got)
				}
			}
			if _, err := WriteSelectedContext("kind-demo"); err == nil {
				t.Fatal("context written under unsafe root")
			}
			if _, err := Load(""); err == nil {
				t.Fatal("config loaded from unsafe root")
			}
			if after := securityDescriptor(t, dir).String(); after != before {
				t.Fatalf("unsafe root was modified:\nbefore %s\nafter  %s", before, after)
			}
			assertAbsent(t, filepath.Join(dir, "context"))
		})
	}
}

func TestWindowsKMXHomeCreatedPrivateAndContextChecked(t *testing.T) {
	home := filepath.Join(privateStateHome(t), "kmx")
	t.Setenv("KMX_HOME", home)
	t.Setenv("KUBE_CTX", "")
	if got, err := StateDir(); err != nil || got != home {
		t.Fatalf("state dir = %q, %v", got, err)
	}
	assertOwnerOnly(t, home)
	path, err := WriteSelectedContext("kind-demo")
	if err != nil || path != filepath.Join(home, "context") {
		t.Fatalf("write = %q, %v", path, err)
	}
	assertOwnerOnly(t, path)
	if c, err := Load(""); err != nil || c.KubeContext != "kind-demo" || c.ContextSource != SourceSelected {
		t.Fatalf("load = %+v, %v", c, err)
	}

	grantEveryone(t, path)
	before := securityDescriptor(t, path).String()
	if _, err := WriteSelectedContext("kind-other"); err == nil {
		t.Fatal("unsafe existing context file overwritten")
	}
	if raw, err := os.ReadFile(path); err != nil || string(raw) != "kind-demo\n" {
		t.Fatalf("refused write changed bytes: %q, %v", raw, err)
	}
	if after := securityDescriptor(t, path).String(); after != before {
		t.Fatalf("unsafe context ACL repaired:\nbefore %s\nafter  %s", before, after)
	}
}
