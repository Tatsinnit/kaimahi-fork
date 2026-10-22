package fileaccess

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func foundationTempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func openTestDirectory(t *testing.T, path string) *Directory {
	t.Helper()
	dir, err := OpenDirectory(t.Context(), path)
	if err != nil {
		t.Fatalf("OpenDirectory: %v", err)
	}
	t.Cleanup(func() { _ = dir.Close() })
	return dir
}

func requireSameFile(t *testing.T, file *Directory, path string) {
	t.Helper()
	got, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(got, want) {
		t.Fatal("opened handle does not identify the expected object")
	}
}

func TestOpenDirectoryAndRegularFile(t *testing.T) {
	dir := foundationTempDir(t)
	filePath := filepath.Join(dir, "entry")
	if err := os.WriteFile(filePath, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	parent := openTestDirectory(t, dir)
	requireSameFile(t, parent, dir)
	if _, ok := any(parent).(fs.ReadDirFile); ok {
		t.Fatal("checked directory exposes path-reopening directory entries")
	}
	file, err := OpenRegularAt(t.Context(), parent, "entry")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	data, err := io.ReadAll(file)
	if err != nil || string(data) != "payload" {
		t.Fatalf("read = %q, %v", data, err)
	}
	if _, ok := any(file).(interface{ Fd() uintptr }); ok {
		t.Fatal("checked file exposes a raw descriptor")
	}
	if _, ok := any(file).(io.Writer); ok {
		t.Fatal("checked file exposes write authority")
	}
	if _, ok := any(parent).(interface{ Fd() uintptr }); ok {
		t.Fatal("checked directory exposes a raw descriptor")
	}
}

func TestOpenDirectoryRelativeAndAnchored(t *testing.T) {
	dir := foundationTempDir(t)
	parentPath := filepath.Dir(dir)
	t.Chdir(parentPath)
	rel, err := filepath.Rel(parentPath, dir)
	if err != nil {
		t.Fatal(err)
	}
	requireSameFile(t, openTestDirectory(t, rel), dir)

	original := filepath.Join(dir, "original")
	moved := filepath.Join(dir, "moved")
	if err := os.Mkdir(original, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(original, "value"), []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	handle := openTestDirectory(t, original)
	if err := os.Rename(original, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(original, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(original, "value"), []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := OpenRegularAt(t.Context(), handle, "value")
	if err != nil {
		t.Fatal(err)
	}
	data, readErr := io.ReadAll(file)
	file.Close()
	if readErr != nil || string(data) != "original" {
		t.Fatalf("anchored read = %q, %v", data, readErr)
	}
}

func TestOpenRefusalsAreDistinctAndRedacted(t *testing.T) {
	dir := foundationTempDir(t)
	missing := filepath.Join(dir, "missing-canary")
	if _, err := OpenDirectory(t.Context(), missing); !errors.Is(err, ErrMissing) || !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing = %v", err)
	} else if strings.Contains(err.Error(), "missing-canary") {
		t.Fatalf("missing error leaked a path: %v", err)
	}
	file := filepath.Join(dir, "private-path-canary")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenDirectory(t.Context(), file); !errors.Is(err, ErrUnsafe) || errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("wrong type = %v", err)
	} else if strings.Contains(err.Error(), "private-path-canary") {
		t.Fatalf("unsafe error leaked a path: %v", err)
	}
	traversal := dir + string(filepath.Separator) + ".." + string(filepath.Separator) + filepath.Base(dir)
	if _, err := OpenDirectory(t.Context(), traversal); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("traversal = %v", err)
	}
}

func TestOpenAtRefusesNonComponents(t *testing.T) {
	parent := openTestDirectory(t, foundationTempDir(t))
	names := []string{"", ".", "..", "child/", "../child", "child/../child", "nul\x00name"}
	if filepath.Separator == '\\' {
		names = append(names, `child\`, `..\child`)
	}
	for _, name := range names {
		if file, err := OpenDirectoryAt(t.Context(), parent, name); err == nil {
			file.Close()
			t.Errorf("OpenDirectoryAt(%q) succeeded", name)
		}
		if file, err := OpenRegularAt(t.Context(), parent, name); err == nil {
			file.Close()
			t.Errorf("OpenRegularAt(%q) succeeded", name)
		}
	}
}

func TestReadFoundationHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := OpenDirectory(ctx, foundationTempDir(t)); !errors.Is(err, context.Canceled) {
		t.Fatalf("OpenDirectory cancelled = %v", err)
	}
	parent := openTestDirectory(t, foundationTempDir(t))
	if _, err := OpenRegularAt(ctx, parent, "missing"); !errors.Is(err, context.Canceled) {
		t.Fatalf("OpenRegularAt cancelled = %v", err)
	}
	if err := CheckPrivate(ctx, parent, true); !errors.Is(err, context.Canceled) {
		t.Fatalf("CheckPrivate cancelled = %v", err)
	}
	if _, err := PhysicalIdentity(ctx, parent); !errors.Is(err, context.Canceled) {
		t.Fatalf("PhysicalIdentity cancelled = %v", err)
	}
	if _, err := OpenDirectoryAt(ctx, parent, "missing"); !errors.Is(err, context.Canceled) {
		t.Fatalf("OpenDirectoryAt cancelled = %v", err)
	}
	if err := CheckSafeDirectory(ctx, parent, true); !errors.Is(err, context.Canceled) {
		t.Fatalf("CheckSafeDirectory cancelled = %v", err)
	}
}

func TestPhysicalIdentityTracksObjectsNotPaths(t *testing.T) {
	dir := foundationTempDir(t)
	a := filepath.Join(dir, "a")
	b := filepath.Join(dir, "b")
	if err := os.WriteFile(a, []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte("b"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "hardlink")
	if err := os.Link(a, link); err != nil {
		t.Fatal(err)
	}
	parent := openTestDirectory(t, dir)
	identity := func(name string) string {
		t.Helper()
		file, err := OpenRegularAt(t.Context(), parent, name)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		id, err := PhysicalIdentity(t.Context(), file)
		if err != nil || id == "" {
			t.Fatalf("identity = %q, %v", id, err)
		}
		return id
	}
	idA := identity("a")
	if got := identity("hardlink"); got != idA {
		t.Fatalf("hard-link identity %q, want %q", got, idA)
	}
	if got := identity("b"); got == idA {
		t.Fatalf("distinct files share identity %q", got)
	}
	if err := os.Rename(a, filepath.Join(dir, "renamed")); err != nil {
		t.Fatal(err)
	}
	if got := identity("renamed"); got != idA {
		t.Fatalf("rename identity %q, want %q", got, idA)
	}
	if err := os.WriteFile(a, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := identity("a"); got == idA {
		t.Fatalf("replacement retained old identity %q", got)
	}
}

func TestChecksRefuseClosedAndNonDiskHandles(t *testing.T) {
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	defer write.Close()
	if err := CheckPrivate(t.Context(), &File{file: read}, false); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("CheckPrivate(pipe) = %v", err)
	}
	if err := CheckSafeDirectory(t.Context(), &Directory{file: read}, false); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("CheckSafeDirectory(pipe) = %v", err)
	}
	closed := openTestDirectory(t, foundationTempDir(t))
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := PhysicalIdentity(t.Context(), closed); err == nil {
		t.Fatal("PhysicalIdentity accepted a closed handle")
	}
}

func TestOpaqueHandleErrorsAreClassifiedAndRedacted(t *testing.T) {
	dir := foundationTempDir(t)
	path := filepath.Join(dir, "wrapper-path-canary")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	parent := openTestDirectory(t, dir)
	file, err := OpenRegularAt(t.Context(), parent, filepath.Base(path))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.ReadAt(make([]byte, 1), -1); !errors.Is(err, ErrUnreadable) || strings.Contains(err.Error(), "wrapper-path-canary") {
		t.Fatalf("ReadAt error = %v, want redacted unreadable", err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Stat(); !errors.Is(err, ErrUnreadable) || strings.Contains(err.Error(), "wrapper-path-canary") {
		t.Fatalf("Stat closed error = %v, want redacted unreadable", err)
	}
}
