//go:build windows

package oras

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kaimahi-agents/kaimahi/internal/kmx/fileaccess"
	"golang.org/x/sys/windows"
)

// Native Windows storage tests. Fixtures live under new protected
// current-user-only roots (fileaccess.PrivateTempDir) and are written with
// fileaccess's explicit private descriptor, never by weakening the suite or
// KMX checks; the bytes (and so declared payload modes) are the checked-in
// fixture's.

func winPrivateRoot(t *testing.T) string {
	t.Helper()
	dir, err := fileaccess.PrivateTempDir(t.TempDir(), "kmx-oras-*")
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

// winPrivateSuite copies the minimal fixture into a new protected root.
func winPrivateSuite(t *testing.T) string {
	t.Helper()
	root := winPrivateRoot(t)
	source := filepath.Join("..", "..", "..", "..", "testdata", "agentsuite", "minimal")
	if err := filepath.WalkDir(source, func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(source, name)
		if err != nil || rel == "." {
			return err
		}
		target := filepath.Join(root, rel)
		if entry.IsDir() {
			return fileaccess.EnsurePrivatePath(target)
		}
		data, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		return fileaccess.WritePrivateFile(target, data, 0o600)
	}); err != nil {
		t.Fatal(err)
	}
	return root
}

func winShortPath(t *testing.T, path string) string {
	t.Helper()
	long, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]uint16, 1024)
	n, err := windows.GetShortPathName(long, &buf[0], uint32(len(buf)))
	if err != nil {
		t.Fatalf("GetShortPathName(%s): %v", path, err)
	}
	return windows.UTF16ToString(buf[:n])
}

// winAliases returns case, extended-length and (when the volume keeps 8.3
// names) short spellings of the existing directory dir.
func winAliases(t *testing.T, dir string) map[string]string {
	t.Helper()
	aliases := map[string]string{"upper": strings.ToUpper(dir), "extended": `\\?\` + dir}
	if short := winShortPath(t, dir); !strings.EqualFold(short, dir) {
		aliases["short"] = short
	} else {
		t.Logf("8.3 names are not generated for %s; short-name alias not exercised", dir)
	}
	return aliases
}

func winRequirePrivateRoot(t *testing.T, path string) {
	t.Helper()
	if err := verifyPrivateTree(path); err != nil {
		t.Fatalf("%s is not a private tree: %v", path, err)
	}
}

func TestWindowsLayoutLockPhysicalParentAliases(t *testing.T) {
	ctx := context.Background()
	parent := filepath.Join(winPrivateRoot(t), "layout-parent-directory")
	if err := fileaccess.EnsurePrivatePath(parent); err != nil {
		t.Fatal(err)
	}
	release, err := lockLayoutPublication(ctx, filepath.Join(parent, "out"))
	if err != nil {
		t.Fatal(err)
	}
	aliases := winAliases(t, parent)
	aliases["other destination"] = parent
	for name, alias := range aliases {
		base := "out"
		if name == "other destination" {
			base = "another-layout"
		}
		if _, err := lockLayoutPublication(ctx, filepath.Join(alias, base)); err == nil || !strings.Contains(err.Error(), "another local layout publisher") {
			t.Fatalf("%s alias did not serialize on the physical parent: %v", name, err)
		}
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatalf("release left %v (%v)", entries, err)
	}
	release, err = lockLayoutPublication(ctx, filepath.Join(aliases["extended"], "out"))
	if err != nil {
		t.Fatalf("re-acquire through an alias: %v", err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsLayoutLockRefusesJunctionParent(t *testing.T) {
	root := winPrivateRoot(t)
	target := filepath.Join(root, "target")
	if err := fileaccess.EnsurePrivatePath(target); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v: %s", err, out)
	}
	if release, err := lockLayoutPublication(context.Background(), filepath.Join(link, "out")); err == nil {
		release()
		t.Fatal("a junction parent was accepted as a lock anchor")
	}
	if entries, _ := os.ReadDir(target); len(entries) != 0 {
		t.Fatalf("refusal wrote below the junction target: %v", entries)
	}
}

// A publisher that dies holding the sentinel leaves it behind; as on Unix,
// later publishers refuse until an operator removes it.
func TestWindowsLayoutLockStaleSentinelAcrossProcess(t *testing.T) {
	if os.Getenv("KMX_WINDOWS_LOCK_HELPER") != "" {
		_, err := lockLayoutPublication(context.Background(), os.Getenv("KMX_WINDOWS_LOCK_HELPER"))
		if err != nil {
			os.Exit(3)
		}
		os.Exit(0) // exits without releasing, like a crash
	}
	parent := winPrivateRoot(t)
	cmd := exec.Command(os.Args[0], "-test.run=^TestWindowsLayoutLockStaleSentinelAcrossProcess$")
	cmd.Env = append(os.Environ(), "KMX_WINDOWS_LOCK_HELPER="+filepath.Join(parent, "out"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("helper: %v: %s", err, out)
	}
	if _, err := lockLayoutPublication(context.Background(), filepath.Join(strings.ToUpper(parent), "other")); err == nil || !strings.Contains(err.Error(), "another local layout publisher") {
		t.Fatalf("stale sentinel from a dead process was not refused: %v", err)
	}
}

func TestWindowsPushPullPrivateOutputsAndAliasFences(t *testing.T) {
	ctx := context.Background()
	source := winPrivateSuite(t)
	out := winPrivateRoot(t)
	layout := filepath.Join(out, "layout")
	pushed, err := Push(ctx, source, layout, "minimal:v1")
	if err != nil {
		t.Fatal(err)
	}
	winRequirePrivateRoot(t, layout)
	if _, err := Push(ctx, source, layout, "minimal:v2"); err != nil {
		t.Fatalf("update existing private layout: %v", err)
	}
	pulled := filepath.Join(out, "pulled")
	result, err := Pull(ctx, layout, "minimal:v1", pulled)
	if err != nil {
		t.Fatal(err)
	}
	if result.Descriptor.Digest != pushed.Descriptor.Digest {
		t.Fatal("pull substituted the descriptor")
	}
	winRequirePrivateRoot(t, pulled)
	if _, err := Pull(ctx, layout, "minimal:v1", pulled); err == nil {
		t.Fatal("pull replaced an existing output")
	}
	// The pulled output qualifies as a loose source and repacks to the
	// same artifact: declared payload modes survived as metadata.
	repushed, err := Push(ctx, pulled, filepath.Join(out, "repushed"), "minimal:v1")
	if err != nil {
		t.Fatal(err)
	}
	if repushed.Descriptor.Digest != pushed.Descriptor.Digest {
		t.Fatalf("repacked %s, want %s", repushed.Descriptor.Digest, pushed.Descriptor.Digest)
	}
	prepared := filepath.Join(out, "prepared-copy")
	single := filepath.Join(out, "single")
	if _, err := Push(ctx, source, single, "prepared"); err != nil {
		t.Fatal(err)
	}
	if _, err := PushLayout(ctx, single, prepared, "v1", pushed.Descriptor); err != nil {
		t.Fatal(err)
	}
	winRequirePrivateRoot(t, prepared)

	for name, alias := range winAliases(t, source) {
		target := filepath.Join(alias, "nested-layout")
		if _, err := Push(ctx, source, target, "x:v1"); err == nil || !strings.Contains(err.Error(), "outside the source") {
			t.Errorf("%s alias: push into the source was not refused: %v", name, err)
		}
	}
	for name, alias := range winAliases(t, layout) {
		if _, err := Pull(ctx, layout, "minimal:v1", filepath.Join(alias, "nested-output")); err == nil || !strings.Contains(err.Error(), "outside the source") {
			t.Errorf("%s alias: pull into the source layout was not refused: %v", name, err)
		}
	}
	for name, alias := range winAliases(t, single) {
		if _, err := PushLayout(ctx, single, filepath.Join(alias, "nested"), "v1", pushed.Descriptor); err == nil || !strings.Contains(err.Error(), "outside the prepared source") {
			t.Errorf("%s alias: prepared push into the source was not refused: %v", name, err)
		}
	}
	for _, dir := range []string{source, layout, single} {
		for _, nested := range []string{"nested-layout", "nested-output", "nested"} {
			if _, err := os.Lstat(filepath.Join(dir, nested)); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("refused publication wrote %s: %v", filepath.Join(dir, nested), err)
			}
		}
	}
	entries, err := os.ReadDir(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".") {
			t.Errorf("staging or lock leftover %s", entry.Name())
		}
	}
}

func TestWindowsExtractionRefusesLinkEntries(t *testing.T) {
	for _, typ := range []byte{tar.TypeSymlink, tar.TypeLink} {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gz)
		if err := tw.WriteHeader(&tar.Header{Name: "a", Typeflag: tar.TypeReg, Mode: 0o644, Size: 1}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
		if err := tw.WriteHeader(&tar.Header{Name: "link", Typeflag: typ, Linkname: "a"}); err != nil {
			t.Fatal(err)
		}
		if err := errors.Join(tw.Close(), gz.Close()); err != nil {
			t.Fatal(err)
		}
		dest := winPrivateRoot(t)
		err := extractContentLayer(context.Background(), &buf, dest)
		if err == nil || !strings.Contains(err.Error(), "not supported on Windows") {
			t.Fatalf("type %c: %v", typ, err)
		}
		if _, err := os.Lstat(filepath.Join(dest, "link")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("type %c link was created: %v", typ, err)
		}
	}
}

func TestWindowsVerifyPrivateTreeRefusesBroadAndJunctionEntries(t *testing.T) {
	root := winPrivateRoot(t)
	if err := fileaccess.WritePrivateFile(filepath.Join(root, "ok"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	winRequirePrivateRoot(t, root)
	target := winPrivateRoot(t)
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", filepath.Join(root, "j"), target).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v: %s", err, out)
	}
	if err := verifyPrivateTree(root); err == nil {
		t.Fatal("a junction inside a private tree was accepted")
	}
	if err := os.Remove(filepath.Join(root, "j")); err != nil {
		t.Fatal(err)
	}
	broad := filepath.Join(root, "broad")
	if err := os.WriteFile(broad, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(broad, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	if err := verifyPrivateTree(root); err == nil {
		t.Fatal("an Everyone grant inside a private tree was accepted")
	}
}

// Junction counterpart of TestPushRejectsNestedTargetThroughSymlinks, which
// needs the symbolic-link privilege an ordinary session lacks.
func TestWindowsPushRejectsNestedTargetThroughJunctions(t *testing.T) {
	ctx := context.Background()
	realSource := winPrivateSuite(t)
	link := filepath.Join(winPrivateRoot(t), "link")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, realSource).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v: %s", err, out)
	}
	for name, pair := range map[string][2]string{
		"source":        {link, filepath.Join(realSource, "layout")},
		"target parent": {realSource, filepath.Join(link, "layout")},
	} {
		if _, err := Push(ctx, pair[0], pair[1], "agentsuites/minimal:v1"); err == nil {
			t.Errorf("%s through a junction: nested target accepted", name)
		}
		if _, err := os.Lstat(filepath.Join(realSource, "layout")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s through a junction wrote into the source: %v", name, err)
		}
	}
}
