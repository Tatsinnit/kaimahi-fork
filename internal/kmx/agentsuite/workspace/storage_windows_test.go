//go:build windows

package workspace_test

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	suiteoras "github.com/kaimahi-agents/kaimahi/internal/kmx/agentsuite/oras"
	"github.com/kaimahi-agents/kaimahi/internal/kmx/agentsuite/workspace"
	"github.com/kaimahi-agents/kaimahi/internal/kmx/fileaccess"
	"golang.org/x/sys/windows"
)

// Native Windows end-to-end storage tests: authoring, preparation, loading,
// local layout publication and extraction, all under new protected
// current-user-only roots, without relaxing any production check.

func winPrivateRoot(t *testing.T) string {
	t.Helper()
	dir, err := fileaccess.PrivateTempDir(t.TempDir(), "kmx-ws-*")
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func winRequirePrivate(t *testing.T, path string, root bool) {
	t.Helper()
	dir, err := fileaccess.OpenDirectory(path)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	if err := fileaccess.CheckPrivate(dir, root); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

func TestWindowsCreatePrepareLoadPushLayoutPullEndToEnd(t *testing.T) {
	ctx := context.Background()
	// Authored inputs are ordinary readable files outside private state.
	input := filepath.Join(t.TempDir(), "input.md")
	if err := os.WriteFile(input, []byte("Answer briefly.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	base := winPrivateRoot(t)
	root := filepath.Join(base, "workspace")
	opt := workspace.CreateOptions{Name: "greeter", Description: "Public questions", Model: "qwen-3.5-2b", InstructionsFile: input}
	if err := workspace.Create(ctx, root, opt); err != nil {
		t.Fatal(err)
	}
	winRequirePrivate(t, root, true)
	if err := workspace.Create(ctx, root, opt); err == nil {
		t.Fatal("create replaced an existing workspace")
	}
	cache := filepath.Join(base, "cache")
	p, err := workspace.Prepare(ctx, root, cache)
	if err != nil {
		t.Fatal(err)
	}
	winRequirePrivate(t, cache, true)
	again, err := workspace.Prepare(ctx, root, cache)
	if err != nil {
		t.Fatalf("reuse prepared cache: %v", err)
	}
	if again.Descriptor.Digest != p.Descriptor.Digest || again.Path != p.Path {
		t.Fatalf("cache reuse changed identity: %+v vs %+v", again, p)
	}
	if _, err := workspace.Load(ctx, p); err != nil {
		t.Fatalf("load prepared suite: %v", err)
	}
	if err := workspace.CheckCurrent(ctx, root, p); err != nil {
		t.Fatal(err)
	}
	published := filepath.Join(base, "published")
	pushed, err := suiteoras.PushLayout(ctx, p.Path, published, "greeter:v1", p.Descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if pushed.Descriptor.Digest != p.Descriptor.Digest {
		t.Fatal("local publication changed the artifact identity")
	}
	winRequirePrivate(t, published, true)
	for i := range 3 {
		pulled := filepath.Join(base, fmt.Sprintf("pulled-%d", i))
		result, err := suiteoras.Pull(ctx, published, "greeter:v1", pulled)
		if err != nil {
			t.Fatal(err)
		}
		if result.Descriptor.Digest != p.Descriptor.Digest {
			t.Fatal("pull substituted the descriptor")
		}
		winRequirePrivate(t, pulled, true)
	}
	if _, err := suiteoras.Pull(ctx, published, "greeter:v1", filepath.Join(base, "pulled-0")); err == nil {
		t.Fatal("pull replaced an existing output")
	}
	// The extracted suite repacks to the exact prepared artifact.
	repushed, err := suiteoras.Push(ctx, filepath.Join(base, "pulled-0"), filepath.Join(base, "repushed"), "greeter:v1")
	if err != nil {
		t.Fatal(err)
	}
	if repushed.Descriptor.Digest != p.Descriptor.Digest {
		t.Fatalf("repacked %s, want prepared %s", repushed.Descriptor.Digest, p.Descriptor.Digest)
	}
	entries, err := os.ReadDir(base)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".") {
			t.Errorf("staging or lock leftover %s", entry.Name())
		}
	}
	if entries, err := os.ReadDir(root); err != nil {
		t.Fatal(err)
	} else {
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".kmx-create-") {
				t.Errorf("authoring stage leftover %s", entry.Name())
			}
		}
	}
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
		t.Fatal(err)
	}
	return windows.UTF16ToString(buf[:n])
}

// Any spelling of the workspace must keep the cache out of it (and the
// workspace out of the cache), refused before the cache is created.
func TestWindowsPrepareRefusesPhysicalAliasOverlap(t *testing.T) {
	ctx := context.Background()
	input := filepath.Join(t.TempDir(), "input.md")
	if err := os.WriteFile(input, []byte("Answer briefly.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	base := winPrivateRoot(t)
	root := filepath.Join(base, "workspace-with-long-name")
	if err := workspace.Create(ctx, root, workspace.CreateOptions{Name: "greeter", Model: "m", InstructionsFile: input}); err != nil {
		t.Fatal(err)
	}
	aliases := map[string]string{"upper": strings.ToUpper(root), "extended": `\\?\` + root}
	if short := winShortPath(t, root); !strings.EqualFold(short, root) {
		aliases["short"] = short
	} else {
		t.Logf("8.3 names are not generated for %s; short-name alias not exercised", root)
	}
	for name, alias := range aliases {
		cache := filepath.Join(alias, "cache")
		_, err := workspace.Prepare(ctx, root, cache)
		if err == nil || !strings.Contains(err.Error(), "prepared cache must be outside") {
			t.Errorf("%s alias: cache inside the workspace was not refused: %v", name, err)
		}
		if _, err := os.Lstat(filepath.Join(root, "cache")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s alias: refusal created the cache: %v", name, err)
		}
		// The reverse: a workspace spelled through an alias, cache its parent.
		if _, err := workspace.Prepare(ctx, alias, base); err == nil || !strings.Contains(err.Error(), "prepared cache must be outside") {
			t.Errorf("%s alias: workspace inside the cache was not refused: %v", name, err)
		}
	}
}

// fixtureSource copies a checked-in suite into a new protected private root,
// which the Windows loose-suite reader requires; nothing is relaxed.
func fixtureSource(t *testing.T, path string) string {
	t.Helper()
	root := filepath.Join(winPrivateRoot(t), "fixture")
	if err := fileaccess.EnsurePrivatePath(root); err != nil {
		t.Fatal(err)
	}
	if err := filepath.WalkDir(path, func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(path, name)
		if err != nil || rel == "." {
			return err
		}
		if entry.IsDir() {
			return fileaccess.EnsurePrivatePath(filepath.Join(root, rel))
		}
		data, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		return fileaccess.WritePrivateFile(filepath.Join(root, rel), data, 0o600)
	}); err != nil {
		t.Fatal(err)
	}
	return root
}

func emptySourceDir(t *testing.T) string {
	t.Helper()
	root := filepath.Join(winPrivateRoot(t), "source")
	if err := fileaccess.EnsurePrivatePath(root); err != nil {
		t.Fatal(err)
	}
	return root
}

// symlinkUnavailable skips only the disclosed gap: creating a symbolic link
// needs SeCreateSymbolicLinkPrivilege, which an ordinary session lacks.
// Junction counterparts run in TestWindowsPrepareRefusesJunctions.
func symlinkUnavailable(t *testing.T, err error) {
	t.Helper()
	if errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD) {
		t.Skipf("symbolic links need SeCreateSymbolicLinkPrivilege (junction counterpart runs instead): %v", err)
	}
}

// makeEntryShared grants Everyone read access, the Windows counterpart of
// the Unix chmod 0755; Windows has no group or other mode bits.
func makeEntryShared(t *testing.T, path string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString("D:(A;OICI;FR;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
}

func winJunction(t *testing.T, link, target string) {
	t.Helper()
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J %s %s: %v: %s", link, target, err, out)
	}
}

// Junction counterparts of the symbolic-link refusals: a junction inside the
// workspace or as the cache path is refused, and nothing is cached.
func TestWindowsPrepareRefusesJunctions(t *testing.T) {
	ctx := context.Background()
	input := filepath.Join(t.TempDir(), "input.md")
	if err := os.WriteFile(input, []byte("Answer briefly.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	newWorkspace := func() (string, string) {
		base := winPrivateRoot(t)
		root := filepath.Join(base, "workspace")
		if err := workspace.Create(ctx, root, workspace.CreateOptions{Name: "greeter", Model: "m", InstructionsFile: input}); err != nil {
			t.Fatal(err)
		}
		return base, root
	}
	base, root := newWorkspace()
	moved := filepath.Join(base, "real-eval")
	if err := os.Rename(filepath.Join(root, "eval"), moved); err != nil {
		t.Fatal(err)
	}
	winJunction(t, filepath.Join(root, "eval"), moved)
	if _, err := workspace.Prepare(ctx, root, filepath.Join(base, "cache")); err == nil {
		t.Fatal("a junction inside the workspace was accepted")
	}
	if _, err := os.Lstat(filepath.Join(base, "cache")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("refusal created the cache: %v", err)
	}

	base, root = newWorkspace()
	realCache := filepath.Join(base, "real-cache")
	if err := fileaccess.EnsurePrivatePath(realCache); err != nil {
		t.Fatal(err)
	}
	winJunction(t, filepath.Join(base, "cache"), realCache)
	if _, err := workspace.Prepare(ctx, root, filepath.Join(base, "cache")); err == nil {
		t.Fatal("a junction cache path was accepted")
	}
	if entries, _ := os.ReadDir(realCache); len(entries) != 0 {
		t.Fatalf("refusal wrote through the junction: %v", entries)
	}
}
