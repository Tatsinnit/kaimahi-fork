//go:build !windows

package fileaccess

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestUnixOpenRefusesLinksAndSpecialFiles(t *testing.T) {
	dir := foundationTempDir(t)
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
	if _, err := OpenDirectory(t.Context(), filepath.Join(dir, "dirlink")); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("directory symlink = %v", err)
	}
	parent := openTestDirectory(t, dir)
	for _, name := range []string{"filelink", "fifo"} {
		if file, err := OpenRegularAt(t.Context(), parent, name); err == nil {
			file.Close()
			t.Errorf("OpenRegularAt(%s) succeeded", name)
		}
	}
}

func TestUnixSecurityModes(t *testing.T) {
	dir := foundationTempDir(t)
	for _, tc := range []struct {
		mode os.FileMode
		dir  bool
		ok   bool
	}{
		{0o600, false, true}, {0o400, false, true}, {0o640, false, false}, {0o604, false, false},
		{0o700, true, true}, {0o750, true, false}, {0o701, true, false},
	} {
		path := filepath.Join(dir, fmt.Sprintf("private-%v-%o", tc.dir, tc.mode))
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
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		var object Object = &File{file: file}
		if tc.dir {
			object = &Directory{file: file}
		}
		err = CheckPrivate(t.Context(), object, tc.dir)
		file.Close()
		if (err == nil) != tc.ok {
			t.Errorf("CheckPrivate(%o, dir=%v) = %v, want ok=%v", tc.mode, tc.dir, err, tc.ok)
		}
	}
	for _, tc := range []struct {
		mode                os.FileMode
		ancestor, immediate bool
	}{
		{0o755, true, true}, {0o700, true, true}, {0o775, false, false},
		{0o777 | os.ModeSticky, true, false}, {0o755 | os.ModeSticky, true, true},
	} {
		path := filepath.Join(dir, fmt.Sprintf("ancestor-%o", uint32(tc.mode)))
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, tc.mode); err != nil {
			t.Fatal(err)
		}
		file := openTestDirectory(t, path)
		if err := CheckSafeDirectory(t.Context(), file, false); (err == nil) != tc.ancestor {
			t.Errorf("ancestor mode %v = %v", tc.mode, err)
		}
		if err := CheckSafeDirectory(t.Context(), file, true); (err == nil) != tc.immediate {
			t.Errorf("immediate mode %v = %v", tc.mode, err)
		}
	}
}

type unixOwnershipInfo struct {
	os.FileInfo
	stat *syscall.Stat_t
}

func (i unixOwnershipInfo) Sys() any { return i.stat }

func TestUnixSecurityOwnership(t *testing.T) {
	dir := foundationTempDir(t)
	privatePath := filepath.Join(dir, "private")
	if err := os.WriteFile(privatePath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	privateInfo, err := os.Stat(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	privateStat := *privateInfo.Sys().(*syscall.Stat_t)
	privateStat.Uid = foreignUID(privateStat.Uid)
	if err := checkUnixPrivateInfo(unixOwnershipInfo{FileInfo: privateInfo, stat: &privateStat}); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("foreign private owner = %v, want unsafe", err)
	}

	ancestorPath := filepath.Join(dir, "ancestor")
	if err := os.Mkdir(ancestorPath, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(ancestorPath, 0o755); err != nil {
		t.Fatal(err)
	}
	ancestorInfo, err := os.Stat(ancestorPath)
	if err != nil {
		t.Fatal(err)
	}
	ancestorStat := *ancestorInfo.Sys().(*syscall.Stat_t)
	ancestorStat.Uid = foreignUID(ancestorStat.Uid)
	if err := checkUnixSafeDirectoryInfo(unixOwnershipInfo{FileInfo: ancestorInfo, stat: &ancestorStat}, false); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("foreign 0755 ancestor owner = %v, want unsafe", err)
	}
	ancestorStat.Uid = 0
	if err := checkUnixSafeDirectoryInfo(unixOwnershipInfo{FileInfo: ancestorInfo, stat: &ancestorStat}, true); err != nil {
		t.Fatalf("root-owned 0755 ancestor = %v, want pass", err)
	}

	missingOwner := unixOwnershipInfo{FileInfo: privateInfo}
	if err := checkUnixPrivateInfo(missingOwner); !errors.Is(err, ErrUnreadable) {
		t.Fatalf("missing private ownership = %v, want unreadable", err)
	}
	if err := checkUnixSafeDirectoryInfo(unixOwnershipInfo{FileInfo: ancestorInfo}, false); !errors.Is(err, ErrUnreadable) {
		t.Fatalf("missing ancestor ownership = %v, want unreadable", err)
	}
}

func foreignUID(uid uint32) uint32 {
	if uid == ^uint32(0) {
		return uid - 1
	}
	return uid + 1
}

func TestUnixDescriptorsAreNonblockingAndCloseOnExec(t *testing.T) {
	dir := foundationTempDir(t)
	if err := os.WriteFile(filepath.Join(dir, "file"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	parent := openTestDirectory(t, dir)
	file, err := OpenRegularAt(context.Background(), parent, "file")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	for _, opened := range []*os.File{rawObject(parent), rawObject(file)} {
		flags, err := unix.FcntlInt(opened.Fd(), unix.F_GETFL, 0)
		if err != nil || flags&unix.O_NONBLOCK == 0 {
			t.Errorf("F_GETFL(%s) = %#x, %v; O_NONBLOCK missing", opened.Name(), flags, err)
		}
		fdFlags, err := unix.FcntlInt(opened.Fd(), unix.F_GETFD, 0)
		if err != nil || fdFlags&unix.FD_CLOEXEC == 0 {
			t.Errorf("F_GETFD(%s) = %#x, %v; FD_CLOEXEC missing", opened.Name(), fdFlags, err)
		}
	}
}
