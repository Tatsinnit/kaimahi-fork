//go:build !windows

package fileaccess

import (
	"errors"
	"os"
	"syscall"
	"testing"
)

func makeExistingPrivateUnsafe(t *testing.T, path string) error {
	t.Helper()
	return os.Chmod(path, 0o644)
}

func mutationTestBase(t *testing.T) string {
	t.Helper()
	return foundationTempDir(t)
}

func TestUnixPrivateCreationModesAndDescriptorFlags(t *testing.T) {
	path, directory := privateTestDirectory(t)
	directoryInfo, err := os.Stat(path)
	if err != nil || directoryInfo.Mode().Perm() != 0o700 {
		t.Fatalf("private directory mode = %v, %v", directoryInfo, err)
	}
	file, err := CreatePrivateFileAt(t.Context(), directory, "file")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("private file mode = %v, %v", info.Mode(), err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		t.Fatalf("private file owner = %+v", stat)
	}
}

func TestUnixSyncDirectoryInvokesAnchoredSync(t *testing.T) {
	_, directory := privateTestDirectory(t)
	oldSync := syncDirectoryHandle
	injected := errors.New("injected directory sync failure")
	calls := 0
	syncDirectoryHandle = func(*os.File) error {
		calls++
		return injected
	}
	t.Cleanup(func() { syncDirectoryHandle = oldSync })
	if err := SyncDirectory(t.Context(), directory); !errors.Is(err, ErrUnreadable) || errors.Is(err, injected) {
		t.Fatalf("directory sync = %v, want redacted unreadable", err)
	}
	if calls != 1 {
		t.Fatalf("directory sync calls = %d, want 1", calls)
	}
}
