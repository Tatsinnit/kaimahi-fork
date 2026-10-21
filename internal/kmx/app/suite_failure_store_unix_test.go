//go:build !windows

package app

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// Unix-only failure-store fixtures: mode bits, uid, umask, FIFOs and
// unprivileged symbolic links. Shared behavior stays in
// suite_failure_store_test.go.

var suiteFailurePlatformUnsafeModes = []string{"symlink", "fifo", "mode", "pending-mode", "pending-link", "pending-fifo", "lock", "directory"}

func applySuiteFailurePlatformUnsafe(t *testing.T, mode, path, target string) error {
	t.Helper()
	var err error
	switch mode {
	case "symlink":
		_ = os.Remove(target)
		err = os.Symlink(filepath.Join(t.TempDir(), "outside"), target)
	case "fifo":
		_ = os.Remove(target)
		err = unix.Mkfifo(target, 0600)
	case "mode":
		err = os.Chmod(target, 0644)
	case "pending-mode":
		pending := filepath.Join(path, suiteFailurePendingName)
		if err = os.WriteFile(pending, nil, 0600); err == nil {
			err = os.Chmod(pending, 0644)
		}
	case "pending-link":
		err = os.Symlink(target, filepath.Join(path, suiteFailurePendingName))
	case "pending-fifo":
		err = unix.Mkfifo(filepath.Join(path, suiteFailurePendingName), 0600)
	case "lock":
		err = os.Chmod(filepath.Join(path, "lock"), 0644)
	case "directory":
		err = os.Chmod(path, 0755)
	default:
		t.Fatalf("unknown unsafe mode %q", mode)
	}
	return err
}

func requireSuiteFailurePrivateFile(t *testing.T, path string) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("unsafe retained file", info, err)
	}
}

func requireSuiteFailurePrivateDirectory(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatal("unsafe partition", err)
	}
}

func TestSuiteFailureStorePublicationUncertainty(t *testing.T) {
	root, d := failureStoreFixture(t)
	s, err := openSuiteFailureStore(root, true)
	if err != nil {
		t.Fatal(err)
	}
	s.publish = func(from, to string) error {
		if err := s.root.Rename(from, to); err != nil {
			return err
		}
		return s.root.Close()
	}
	id, err := s.save(t.Context(), d)
	_ = s.Close() // The injected failure already closed the root handle.
	if !suiteFailureID.MatchString(id) || !errors.Is(err, errSuiteFailureStore) {
		t.Fatal("visible publication lost its ID", id, err)
	}
	fresh, err := openSuiteFailureStore(root, false)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	entries, err := fresh.scan()
	if err != nil || len(entries) != 1 || entries[0].record.Detail.ID != id {
		t.Fatal("published record lost", err)
	}
}

type suiteFailureForeignInfo struct {
	os.FileInfo
	stat syscall.Stat_t
}

func (i suiteFailureForeignInfo) Sys() any { return &i.stat }
func TestSuiteFailureStoreOwnership(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owned")
	if err := os.WriteFile(path, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat := *info.Sys().(*syscall.Stat_t)
	stat.Uid++
	if safeSuiteFailureFile(suiteFailureForeignInfo{info, stat}) {
		t.Fatal("foreign-owner file accepted")
	}
}

func TestSuiteFailureStorePermissions(t *testing.T) {
	if mode := os.Getenv("KMX_FAILURE_UMASK"); mode != "" {
		mask := 0077
		if mode == "022" {
			mask = 0022
		}
		unix.Umask(mask)
		TestSuiteFailureStoreRetention(t)
		return
	}
	for _, mode := range []string{"077", "022"} {
		cmd := exec.Command(os.Args[0], "-test.run=^TestSuiteFailureStorePermissions$", "-test.count=1")
		cmd.Env = append(os.Environ(), "KMX_FAILURE_UMASK="+mode)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("umask%s: %s %v", mode, out, err)
		}
	}
}
