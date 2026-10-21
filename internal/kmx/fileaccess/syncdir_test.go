package fileaccess

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func openTestRoot(t *testing.T) *os.Root {
	t.Helper()
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	t.Cleanup(func() { _ = root.Close() })
	return root
}

func TestOpenSyncDirectorySyncsAnchoredRoot(t *testing.T) {
	root := openTestRoot(t)

	dir, err := OpenSyncDirectory(root)
	if err != nil {
		t.Fatalf("OpenSyncDirectory: %v", err)
	}
	defer dir.Close()

	if err := dir.Sync(); err != nil {
		t.Fatalf("Sync() = %v, want nil", err)
	}
	got, err := dir.Stat()
	if err != nil {
		t.Fatalf("Stat opened directory: %v", err)
	}
	want, err := root.Stat(".")
	if err != nil {
		t.Fatalf("Stat root: %v", err)
	}
	if !got.IsDir() {
		t.Fatalf("opened handle mode = %v, want directory", got.Mode())
	}
	if !os.SameFile(got, want) {
		t.Fatal("opened handle is not the root's anchored directory")
	}
}

func TestOpenSyncDirectoryStaysAnchoredOnPathReplacement(t *testing.T) {
	base := t.TempDir()
	original, moved := filepath.Join(base, "original"), filepath.Join(base, "moved")
	if err := os.Mkdir(original, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(original)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	dir, err := OpenSyncDirectory(root)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	// Release os.Root's Windows delete-sharing restriction. The returned
	// sync handle must independently retain the original directory object.
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(original, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(original, 0700); err != nil {
		t.Fatal(err)
	}
	got, err := dir.Stat()
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.Stat(moved)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(got, want) {
		t.Fatal("opened the replacement pathname instead of the anchored directory")
	}
	if err := dir.Sync(); err != nil {
		t.Fatalf("Sync renamed anchored directory: %v", err)
	}
}

func TestOpenSyncDirectoryRefusesClosedRoot(t *testing.T) {
	root := openTestRoot(t)
	if err := root.Close(); err != nil {
		t.Fatalf("Close root: %v", err)
	}

	dir, err := OpenSyncDirectory(root)
	if err == nil {
		dir.Close()
		t.Fatal("OpenSyncDirectory on closed root succeeded, want error")
	}
	if !errors.Is(err, os.ErrClosed) {
		t.Fatalf("OpenSyncDirectory error = %v, want os.ErrClosed", err)
	}
}

func TestOpenSyncDirectoryClosedHandleSyncFails(t *testing.T) {
	root := openTestRoot(t)
	dir, err := OpenSyncDirectory(root)
	if err != nil {
		t.Fatalf("OpenSyncDirectory: %v", err)
	}
	if err := dir.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if err := dir.Sync(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Sync after Close = %v, want os.ErrClosed", err)
	}
}
