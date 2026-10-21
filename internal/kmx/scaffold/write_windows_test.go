//go:build windows

package scaffold

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/kaimahi-agents/kaimahi/internal/kmx/fileaccess"
	"golang.org/x/sys/windows"
)

// scaffoldPrivateDir is a new protected current-user-only fixture root,
// never t.TempDir's inherited descriptor.
func scaffoldPrivateDir(t *testing.T) string {
	t.Helper()
	dir, err := fileaccess.PrivateTempDir(t.TempDir(), "scaffold-")
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func scaffoldJunction(t *testing.T, link, target string) {
	t.Helper()
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J %s %s: %v: %s", link, target, err, out)
	}
}

func scaffoldCheckPrivate(t *testing.T, path string, dir bool) {
	t.Helper()
	var file *os.File
	var err error
	if dir {
		file, err = fileaccess.OpenDirectory(path)
	} else {
		var parent *os.File
		if parent, err = fileaccess.OpenDirectory(filepath.Dir(path)); err == nil {
			file, err = fileaccess.OpenRegularAt(parent, filepath.Base(path), os.O_RDONLY)
			parent.Close()
		}
	}
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer file.Close()
	if err := fileaccess.CheckPrivate(file, dir); err != nil {
		t.Fatalf("%s is not private: %v", path, err)
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if control, _, err := sd.Control(); err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("%s has no explicit protected DACL: %v", path, err)
	}
}

func scaffoldEntries(t *testing.T, dir string, want int) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != want {
		t.Fatalf("%s entries = %v, %v; want %d", dir, entries, err, want)
	}
}

func TestWindowsWriteNewCreatesExplicitPrivateObjects(t *testing.T) {
	base := scaffoldPrivateDir(t)
	path := filepath.Join(base, "agents", "nested", "billing.yaml")
	if err := WriteNew(path, "first\n"); err != nil {
		t.Fatal(err)
	}
	scaffoldCheckPrivate(t, filepath.Join(base, "agents"), true)
	scaffoldCheckPrivate(t, filepath.Join(base, "agents", "nested"), true)
	scaffoldCheckPrivate(t, path, false)
	if err := WriteNew(path, "second\n"); !errors.Is(err, os.ErrExist) {
		t.Fatalf("collision = %v", err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "first\n" {
		t.Fatalf("existing file modified: %q %v", got, err)
	}
}

func TestWindowsWriteNewNeverFollowsOrRepairs(t *testing.T) {
	t.Run("junction leaf", func(t *testing.T) {
		base, target := scaffoldPrivateDir(t), scaffoldPrivateDir(t)
		path := filepath.Join(base, "agent.yaml")
		scaffoldJunction(t, path, target)
		if err := WriteNew(path, "x\n"); !errors.Is(err, os.ErrExist) {
			t.Fatalf("junction leaf = %v, want collision", err)
		}
		scaffoldEntries(t, target, 0)
		if info, err := os.Lstat(path); err != nil || info.Mode().Type() == 0 {
			t.Fatalf("junction replaced: %v %v", info, err)
		}
	})
	t.Run("junction parent", func(t *testing.T) {
		base, target := scaffoldPrivateDir(t), scaffoldPrivateDir(t)
		scaffoldJunction(t, filepath.Join(base, "linked"), target)
		if err := WriteNew(filepath.Join(base, "linked", "agent.yaml"), "x\n"); err == nil {
			t.Fatal("junction parent followed")
		}
		scaffoldEntries(t, target, 0)
	})
	t.Run("existing broad file", func(t *testing.T) {
		base := scaffoldPrivateDir(t)
		path := filepath.Join(base, "agent.yaml")
		if err := os.WriteFile(path, []byte("mine\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		before, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		if err := WriteNew(path, "x\n"); !errors.Is(err, os.ErrExist) {
			t.Fatalf("existing = %v", err)
		}
		after, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil || before.String() != after.String() {
			t.Fatalf("existing descriptor changed: %v", err)
		}
		if got, _ := os.ReadFile(path); string(got) != "mine\n" {
			t.Fatalf("existing modified: %q", got)
		}
	})
}
