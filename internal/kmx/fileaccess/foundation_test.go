package fileaccess

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// faPrivateDir returns a fresh private directory created by EnsurePrivatePath,
// so Windows fixtures never adopt t.TempDir's inherited ACL.
func faPrivateDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "private")
	if err := EnsurePrivatePath(dir); err != nil {
		t.Fatalf("EnsurePrivatePath: %v", err)
	}
	return dir
}

func faOpenDir(t *testing.T, path string) *os.File {
	t.Helper()
	dir, err := OpenDirectory(path)
	if err != nil {
		t.Fatalf("OpenDirectory(%s): %v", path, err)
	}
	t.Cleanup(func() { _ = dir.Close() })
	return dir
}

func faSameFile(t *testing.T, file *os.File, path string) {
	t.Helper()
	got, err := file.Stat()
	if err != nil {
		t.Fatalf("Stat opened %s: %v", path, err)
	}
	want, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat %s: %v", path, err)
	}
	if !os.SameFile(got, want) {
		t.Fatalf("opened handle is not %s", path)
	}
}

func TestOpenDirectoryOpensExistingDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "entry"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	opened := faOpenDir(t, dir)
	faSameFile(t, opened, dir)
	entries, err := opened.ReadDir(-1)
	if err != nil || len(entries) != 1 || entries[0].Name() != "entry" {
		t.Fatalf("ReadDir = %v, %v; want [entry]", entries, err)
	}
}

func TestOpenDirectoryRelativePath(t *testing.T) {
	dir := t.TempDir()
	// The checkout and temporary directory may be on different Windows
	// volumes. Relative-path coverage needs a same-volume working directory.
	t.Chdir(filepath.Dir(dir))
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	rel, err := filepath.Rel(wd, dir)
	if err != nil {
		t.Fatalf("Rel(%s, %s): %v", wd, dir, err)
	}
	faSameFile(t, faOpenDir(t, rel), dir)
	faSameFile(t, faOpenDir(t, filepath.Join(rel, "..", filepath.Base(dir))), dir)
}

func TestOpenDirectoryMissingIsNotExist(t *testing.T) {
	dir := t.TempDir()
	for _, path := range []string{filepath.Join(dir, "missing"), filepath.Join(dir, "missing", "child")} {
		if _, err := OpenDirectory(path); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("OpenDirectory(%s) = %v, want not-exist", path, err)
		}
	}
}

func TestOpenDirectoryRefusesRegularFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{file, filepath.Join(file, "child")} {
		opened, err := OpenDirectory(path)
		if err == nil {
			opened.Close()
			t.Fatalf("OpenDirectory(%s) succeeded on a regular file", path)
		}
		if errors.Is(err, fs.ErrNotExist) && path == file {
			t.Fatalf("OpenDirectory(%s) = %v, a file must not look absent", path, err)
		}
	}
}

func TestOpenDirectoryAtOpensSingleComponent(t *testing.T) {
	dir := t.TempDir()
	child := filepath.Join(dir, "child")
	if err := os.Mkdir(child, 0o700); err != nil {
		t.Fatal(err)
	}
	opened, err := OpenDirectoryAt(faOpenDir(t, dir), "child")
	if err != nil {
		t.Fatalf("OpenDirectoryAt: %v", err)
	}
	defer opened.Close()
	faSameFile(t, opened, child)
}

func TestOpenAtRefusesMultiComponentNames(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "a", "b"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a", "f"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	parent := faOpenDir(t, filepath.Join(dir, "a"))
	names := []string{"", ".", "..", "b/", "../a", "b/../b", "x\x00"}
	if filepath.Separator == '\\' {
		names = append(names, `b\`, `..\a`)
	}
	for _, name := range names {
		if f, err := OpenDirectoryAt(parent, name); err == nil {
			f.Close()
			t.Errorf("OpenDirectoryAt(%q) succeeded", name)
		}
		if f, err := OpenRegularAt(parent, name, os.O_RDONLY); err == nil {
			f.Close()
			t.Errorf("OpenRegularAt(%q) succeeded", name)
		}
		if f, err := OpenPrivateAt(parent, name, os.O_RDWR|os.O_CREATE); err == nil {
			f.Close()
			t.Errorf("OpenPrivateAt(%q) succeeded", name)
		}
		if f, err := EnsurePrivateDirectoryAt(parent, name); err == nil {
			f.Close()
			t.Errorf("EnsurePrivateDirectoryAt(%q) succeeded", name)
		}
	}
}

func TestOpenRegularAt(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "file"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "dir"), 0o700); err != nil {
		t.Fatal(err)
	}
	parent := faOpenDir(t, dir)

	read, err := OpenRegularAt(parent, "file", os.O_RDONLY)
	if err != nil {
		t.Fatalf("OpenRegularAt read: %v", err)
	}
	data, err := io.ReadAll(read)
	read.Close()
	if err != nil || string(data) != "old" {
		t.Fatalf("read = %q, %v", data, err)
	}
	write, err := OpenRegularAt(parent, "file", os.O_RDWR)
	if err != nil {
		t.Fatalf("OpenRegularAt write: %v", err)
	}
	if _, err := write.WriteAt([]byte("new"), 0); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	write.Close()
	if data, _ := os.ReadFile(filepath.Join(dir, "file")); string(data) != "new" {
		t.Fatalf("written = %q", data)
	}
	if f, err := OpenRegularAt(parent, "dir", os.O_RDONLY); err == nil {
		f.Close()
		t.Fatal("OpenRegularAt opened a directory")
	}
	if _, err := OpenRegularAt(parent, "missing", os.O_RDONLY); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("OpenRegularAt missing = %v, want not-exist", err)
	}
	for _, flags := range []int{os.O_RDWR | os.O_CREATE, os.O_RDWR | os.O_TRUNC, os.O_WRONLY | os.O_APPEND} {
		if f, err := OpenRegularAt(parent, "file", flags); err == nil {
			f.Close()
			t.Errorf("OpenRegularAt flags %#x succeeded", flags)
		}
	}
	if data, _ := os.ReadFile(filepath.Join(dir, "file")); string(data) != "new" {
		t.Fatalf("refused flags changed file to %q", data)
	}
}

func TestOpenPrivateAtCreatesAndOpensPrivateFiles(t *testing.T) {
	parent := faOpenDir(t, faPrivateDir(t))

	created, err := OpenPrivateAt(parent, "lock", os.O_RDWR|os.O_CREATE|os.O_EXCL)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := created.Write([]byte("payload")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := CheckPrivate(created, false); err != nil {
		t.Fatalf("CheckPrivate(created) = %v", err)
	}
	created.Close()

	if _, err := OpenPrivateAt(parent, "lock", os.O_RDWR|os.O_CREATE|os.O_EXCL); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("exclusive re-create = %v, want exist", err)
	}
	if _, err := OpenPrivateAt(parent, "missing", os.O_RDWR); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("open missing = %v, want not-exist", err)
	}
	existing, err := OpenPrivateAt(parent, "lock", os.O_RDWR|os.O_CREATE)
	if err != nil {
		t.Fatalf("open-or-create existing: %v", err)
	}
	if data, err := io.ReadAll(existing); err != nil || string(data) != "payload" {
		t.Fatalf("existing data = %q, %v", data, err)
	}
	existing.Close()
	truncated, err := OpenPrivateAt(parent, "lock", os.O_WRONLY|os.O_TRUNC)
	if err != nil {
		t.Fatalf("truncate: %v", err)
	}
	info, err := truncated.Stat()
	truncated.Close()
	if err != nil || info.Size() != 0 {
		t.Fatalf("truncated size = %v, %v", info, err)
	}
	for _, flags := range []int{os.O_RDWR | os.O_APPEND, os.O_RDWR | os.O_EXCL, os.O_RDONLY | os.O_TRUNC} {
		if f, err := OpenPrivateAt(parent, "lock", flags); err == nil {
			f.Close()
			t.Errorf("OpenPrivateAt flags %#x succeeded", flags)
		}
	}
	if err := os.Mkdir(filepath.Join(parent.Name(), "dir"), 0o700); err != nil {
		t.Fatal(err)
	}
	if f, err := OpenPrivateAt(parent, "dir", os.O_RDONLY); err == nil {
		f.Close()
		t.Fatal("OpenPrivateAt opened a directory")
	}
}

func TestOpenPrivateAtRefusesUnsafeExistingBeforeTruncation(t *testing.T) {
	dir := faPrivateDir(t)
	path := filepath.Join(dir, "shared")
	if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	faMakeUnsafe(t, path)
	before := faSecuritySnapshot(t, path)
	parent := faOpenDir(t, dir)
	for _, flags := range []int{os.O_RDONLY, os.O_RDWR | os.O_CREATE, os.O_WRONLY | os.O_TRUNC} {
		if f, err := OpenPrivateAt(parent, "shared", flags); err == nil {
			f.Close()
			t.Fatalf("OpenPrivateAt flags %#x accepted an unsafe file", flags)
		}
	}
	if data, _ := os.ReadFile(path); string(data) != "keep" {
		t.Fatalf("refused open changed data to %q", data)
	}
	if after := faSecuritySnapshot(t, path); after != before {
		t.Fatalf("refused open repaired security: %s -> %s", before, after)
	}
}

func TestEnsurePrivateDirectoryAt(t *testing.T) {
	dir := faPrivateDir(t)
	parent := faOpenDir(t, dir)

	created, err := EnsurePrivateDirectoryAt(parent, "child")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	faSameFile(t, created, filepath.Join(dir, "child"))
	if err := CheckPrivate(created, false); err != nil {
		t.Fatalf("CheckPrivate(created) = %v", err)
	}
	created.Close()
	again, err := EnsurePrivateDirectoryAt(parent, "child")
	if err != nil {
		t.Fatalf("existing: %v", err)
	}
	again.Close()

	if err := os.WriteFile(filepath.Join(dir, "file"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if f, err := EnsurePrivateDirectoryAt(parent, "file"); err == nil {
		f.Close()
		t.Fatal("EnsurePrivateDirectoryAt accepted a regular file")
	}

	unsafe := filepath.Join(dir, "unsafe")
	if err := os.Mkdir(unsafe, 0o700); err != nil {
		t.Fatal(err)
	}
	faMakeUnsafe(t, unsafe)
	before := faSecuritySnapshot(t, unsafe)
	if f, err := EnsurePrivateDirectoryAt(parent, "unsafe"); err == nil {
		f.Close()
		t.Fatal("EnsurePrivateDirectoryAt accepted an unsafe directory")
	}
	if after := faSecuritySnapshot(t, unsafe); after != before {
		t.Fatalf("refusal repaired security: %s -> %s", before, after)
	}
}

func TestEnsurePrivatePathCreatesNestedAndAcceptsExisting(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a", "b", "state")
	for range 2 {
		if err := EnsurePrivatePath(dir); err != nil {
			t.Fatalf("EnsurePrivatePath: %v", err)
		}
	}
	opened := faOpenDir(t, dir)
	if err := CheckPrivate(opened, true); err != nil {
		t.Fatalf("CheckPrivate(root) = %v", err)
	}
}

func TestPrivateTempDir(t *testing.T) {
	parent := faPrivateDir(t)
	first, err := PrivateTempDir(parent, "kmx-*.tmp")
	if err != nil {
		t.Fatalf("PrivateTempDir: %v", err)
	}
	second, err := PrivateTempDir(parent, "kmx-*.tmp")
	if err != nil {
		t.Fatalf("PrivateTempDir: %v", err)
	}
	if first == second {
		t.Fatalf("PrivateTempDir returned %s twice", first)
	}
	for _, dir := range []string{first, second} {
		name := filepath.Base(dir)
		if filepath.Dir(dir) != parent || len(name) <= len("kmx-.tmp") || name[:4] != "kmx-" || filepath.Ext(name) != ".tmp" {
			t.Fatalf("PrivateTempDir = %s, want kmx-*.tmp in %s", dir, parent)
		}
		if err := CheckPrivate(faOpenDir(t, dir), true); err != nil {
			t.Fatalf("CheckPrivate(%s) = %v", dir, err)
		}
	}
	if _, err := PrivateTempDir(parent, "a"+string(filepath.Separator)+"b"); err == nil {
		t.Fatal("PrivateTempDir accepted a pattern with a separator")
	}
}

func TestWritePrivateFileCreatesAndReplacesPrivateFile(t *testing.T) {
	path := filepath.Join(faPrivateDir(t), "config")
	for _, data := range []string{"first contents", "second"} {
		if err := WritePrivateFile(path, []byte(data), 0o600); err != nil {
			t.Fatalf("WritePrivateFile: %v", err)
		}
		if got, err := os.ReadFile(path); err != nil || string(got) != data {
			t.Fatalf("contents = %q, %v; want %q", got, err, data)
		}
	}
	parent := faOpenDir(t, filepath.Dir(path))
	file, err := OpenRegularAt(parent, "config", os.O_RDONLY)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := CheckPrivate(file, false); err != nil {
		t.Fatalf("CheckPrivate(written) = %v", err)
	}
}

func TestTryLockExcludesOtherHandlesUntilClose(t *testing.T) {
	parent := faOpenDir(t, faPrivateDir(t))
	first, err := OpenPrivateAt(parent, "lock", os.O_RDWR|os.O_CREATE|os.O_EXCL)
	if err != nil {
		t.Fatal(err)
	}
	second, err := OpenPrivateAt(parent, "lock", os.O_RDWR)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if err := TryLock(first); err != nil {
		t.Fatalf("TryLock(first) = %v", err)
	}
	if err := TryLock(second); err == nil {
		t.Fatal("TryLock(second) succeeded while first holds the lock")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := TryLock(second); err != nil {
		t.Fatalf("TryLock after release = %v", err)
	}
	if err := TryLock(first); err == nil {
		t.Fatal("TryLock on a closed file succeeded")
	}
}

func TestPhysicalIdentity(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	for _, path := range []string{a, b} {
		if err := os.WriteFile(path, []byte(path), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(dir, "hardlink")
	if err := os.Link(a, link); err != nil {
		t.Fatalf("Link: %v", err)
	}
	parent := faOpenDir(t, dir)
	id := func(name string) string {
		t.Helper()
		f, err := OpenRegularAt(parent, name, os.O_RDONLY)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		got, err := PhysicalIdentity(f)
		if err != nil || got == "" {
			t.Fatalf("PhysicalIdentity(%s) = %q, %v", name, got, err)
		}
		return got
	}
	idA := id("a")
	if again := id("a"); again != idA {
		t.Fatalf("identity changed between handles: %s vs %s", idA, again)
	}
	if idB := id("b"); idB == idA {
		t.Fatalf("distinct files share identity %s", idA)
	}
	if idLink := id("hardlink"); idLink != idA {
		t.Fatalf("hard link identity %s, want %s", idLink, idA)
	}
	if err := os.Rename(a, filepath.Join(dir, "renamed")); err != nil {
		t.Fatal(err)
	}
	if renamed := id("renamed"); renamed != idA {
		t.Fatalf("rename changed identity: %s vs %s", renamed, idA)
	}
	dirID, err := PhysicalIdentity(parent)
	if err != nil || dirID == idA {
		t.Fatalf("directory identity = %q, %v", dirID, err)
	}
	closed, err := OpenDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	closed.Close()
	if _, err := PhysicalIdentity(closed); err == nil {
		t.Fatal("PhysicalIdentity on a closed file succeeded")
	}
}

func TestCheckFunctionsRefuseClosedAndNonDiskFiles(t *testing.T) {
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer write.Close()
	defer read.Close()
	if err := CheckPrivate(read, false); err == nil {
		t.Error("CheckPrivate accepted a pipe")
	}
	if err := CheckSafeDirectory(read, false); err == nil {
		t.Error("CheckSafeDirectory accepted a pipe")
	}
	closed, err := OpenDirectory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	closed.Close()
	if err := CheckPrivate(closed, true); err == nil {
		t.Error("CheckPrivate accepted a closed file")
	}
	if err := CheckSafeDirectory(closed, true); err == nil {
		t.Error("CheckSafeDirectory accepted a closed file")
	}
}
