//go:build !windows

package fileaccess

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func faMakeUnsafe(t *testing.T, path string) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, info.Mode().Perm()|0o044); err != nil {
		t.Fatal(err)
	}
}

func faSecuritySnapshot(t *testing.T, path string) string {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprint(info.Mode())
}

func TestOpenRefusesSymlinksAndSpecialFiles(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "file"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "dirlink")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(target, "file"), filepath.Join(dir, "filelink")); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(dir, "fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(dir, "dirlink"), filepath.Join(dir, "dirlink", "x")} {
		if f, err := OpenDirectory(path); err == nil {
			f.Close()
			t.Errorf("OpenDirectory(%s) followed a symlink", path)
		}
	}
	parent := faOpenDir(t, dir)
	if f, err := OpenDirectoryAt(parent, "dirlink"); err == nil {
		f.Close()
		t.Error("OpenDirectoryAt followed a symlink")
	}
	for _, name := range []string{"filelink", "fifo"} {
		// O_NONBLOCK keeps a FIFO open from blocking; the type check refuses it.
		if f, err := OpenRegularAt(parent, name, os.O_RDONLY); err == nil {
			f.Close()
			t.Errorf("OpenRegularAt(%s) succeeded", name)
		}
		if f, err := OpenPrivateAt(parent, name, os.O_RDWR|os.O_CREATE); err == nil {
			f.Close()
			t.Errorf("OpenPrivateAt(%s) succeeded", name)
		}
	}
	if _, err := os.Lstat(filepath.Join(target, "file")); err != nil {
		t.Fatal(err)
	}
	if f, err := EnsurePrivateDirectoryAt(parent, "dirlink"); err == nil {
		f.Close()
		t.Error("EnsurePrivateDirectoryAt followed a symlink")
	}
}

func TestUnixCheckPrivateModes(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		mode os.FileMode
		dir  bool
		ok   bool
	}{
		{0o600, false, true}, {0o400, false, true}, {0o640, false, false}, {0o604, false, false},
		{0o700, true, true}, {0o750, true, false}, {0o701, true, false},
	} {
		path := filepath.Join(dir, fmt.Sprintf("%v-%o", tc.dir, tc.mode))
		if tc.dir {
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		} else if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, tc.mode); err != nil {
			t.Fatal(err)
		}
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, root := range []bool{false, true} {
			if err := CheckPrivate(f, root); (err == nil) != tc.ok {
				t.Errorf("CheckPrivate(%o dir=%v root=%v) = %v, want ok=%v", tc.mode, tc.dir, root, err, tc.ok)
			}
		}
		f.Close()
	}
}

func TestUnixCheckSafeDirectoryModes(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		mode               os.FileMode
		ancestor, immedate bool
	}{
		{0o755, true, true}, {0o700, true, true}, {0o775, false, false}, {0o757, false, false},
		{0o777 | os.ModeSticky, true, false}, {0o755 | os.ModeSticky, true, true},
	} {
		path := filepath.Join(dir, fmt.Sprintf("%o", uint32(tc.mode)))
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, tc.mode); err != nil {
			t.Fatal(err)
		}
		f := faOpenDir(t, path)
		if err := CheckSafeDirectory(f, false); (err == nil) != tc.ancestor {
			t.Errorf("CheckSafeDirectory(%v, ancestor) = %v", tc.mode, err)
		}
		if err := CheckSafeDirectory(f, true); (err == nil) != tc.immedate {
			t.Errorf("CheckSafeDirectory(%v, immediate) = %v", tc.mode, err)
		}
	}
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := CheckSafeDirectory(f, false); err == nil {
		t.Error("CheckSafeDirectory accepted a regular file")
	}
}

// The Unix path helpers are the original standard-library calls, so existing
// directory and file modes are neither checked nor changed.
func TestUnixPathHelpersPreserveStandardLibraryBehavior(t *testing.T) {
	dir := t.TempDir()
	public := filepath.Join(dir, "public")
	if err := os.Mkdir(public, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(public, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := EnsurePrivatePath(public); err != nil {
		t.Fatalf("EnsurePrivatePath(existing 0755) = %v, want MkdirAll behavior", err)
	}
	if info, _ := os.Stat(public); info.Mode().Perm() != 0o755 {
		t.Fatalf("EnsurePrivatePath changed mode to %v", info.Mode())
	}
	created := filepath.Join(dir, "new", "state")
	if err := EnsurePrivatePath(created); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(created); info.Mode().Perm() != 0o700 {
		t.Fatalf("EnsurePrivatePath mode %v, want 0700", info.Mode())
	}
	temp, err := PrivateTempDir(dir, "kmx-")
	if err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(temp); info.Mode().Perm() != 0o700 {
		t.Fatalf("PrivateTempDir mode %v, want 0700", info.Mode())
	}
	file := filepath.Join(dir, "file")
	if err := WritePrivateFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Independent of the host umask: an existing mode is retained.
	if err := os.Chmod(file, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WritePrivateFile(file, []byte("y"), 0o600); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(file); info.Mode().Perm() != 0o644 {
		t.Fatalf("WritePrivateFile mode %v, want os.WriteFile's retained 0644", info.Mode())
	}
	parent := faOpenDir(t, dir)
	lock, err := OpenPrivateAt(parent, "lock", os.O_RDWR|os.O_CREATE)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if info, _ := lock.Stat(); info.Mode().Perm() != 0o600 {
		t.Fatalf("OpenPrivateAt mode %v, want 0600", info.Mode())
	}
}

func TestUnixTryLockReportsWouldBlock(t *testing.T) {
	_, file := faLockFile(t)
	second, err := os.OpenFile(file.Name(), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if err := TryLock(file); err != nil {
		t.Fatal(err)
	}
	if err := TryLock(second); !errors.Is(err, unix.EWOULDBLOCK) {
		t.Fatalf("TryLock(second) = %v, want EWOULDBLOCK", err)
	}
}
