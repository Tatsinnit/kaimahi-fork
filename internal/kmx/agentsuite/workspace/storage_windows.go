//go:build windows

package workspace

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	suiteoras "github.com/kaimahi-agents/kaimahi/internal/kmx/agentsuite/oras"
	"github.com/kaimahi-agents/kaimahi/internal/kmx/fileaccess"
)

// Windows private storage: KMX creates every private directory and file with
// fileaccess's explicit current-user-only descriptor, and checks existing or
// third-party (ORAS) objects through their own handles. FileInfo permission
// bits are synthetic on Windows and are never consulted; nothing existing is
// repaired.

// privateTree refuses root unless it is a protected private directory whose
// every descendant is a private, non-reparse directory or regular file.
// setMode has no Windows meaning: new objects are already private, and a
// third-party object that is not is refused rather than relabeled.
func privateTree(root string, _ bool) error {
	dir, err := fileaccess.OpenDirectory(root)
	if err != nil {
		return err
	}
	defer dir.Close()
	if err := fileaccess.CheckPrivate(dir, true); err != nil {
		return fmt.Errorf("cache directories must be private (current-user-only ACL): %w", err)
	}
	return privateChildren(dir)
}

func privateChildren(dir *os.File) error {
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		var child *os.File
		if entry.IsDir() {
			child, err = fileaccess.OpenDirectoryAt(dir, entry.Name())
		} else {
			// Refuses reparse points (including symbolic links and
			// junctions), devices and anything not a regular file.
			child, err = fileaccess.OpenRegularAt(dir, entry.Name(), os.O_RDONLY)
		}
		if err != nil {
			return fmt.Errorf("cache contains an unsupported entry: %w", err)
		}
		err = fileaccess.CheckPrivate(child, false)
		if err != nil {
			err = fmt.Errorf("cache entries must be private (current-user-only ACL): %s: %w", child.Name(), err)
		} else if entry.IsDir() {
			err = privateChildren(child)
		}
		if closeErr := child.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// ensurePrivateCache creates the cache directory as a protected private root,
// or checks an existing one; ancestors must satisfy the public-ancestor policy.
func ensurePrivateCache(cacheDir string) error {
	if err := fileaccess.EnsurePrivatePath(cacheDir); err != nil {
		return fmt.Errorf("prepared cache must be private (current-user-only ACL): %w", err)
	}
	return nil
}

// openPrivateRoot opens path as an os.Root only after the native handle walk
// has opened and checked the same physical private directory; the native
// handle is authoritative and a mismatched Go root is refused before I/O.
func openPrivateRoot(path string) (*os.Root, error) {
	dir, err := fileaccess.OpenDirectory(path)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	if err := fileaccess.CheckPrivate(dir, false); err != nil {
		return nil, fmt.Errorf("%s must be private (current-user-only ACL): %w", path, err)
	}
	want, err := fileaccess.PhysicalIdentity(dir)
	if err != nil {
		return nil, err
	}
	r, err := os.OpenRoot(dir.Name())
	if err != nil {
		return nil, err
	}
	self, err := r.Open(".")
	if err != nil {
		r.Close()
		return nil, err
	}
	got, err := fileaccess.PhysicalIdentity(self)
	self.Close()
	if err == nil && got != want {
		err = fmt.Errorf("%s changed while opening", path)
	}
	if err != nil {
		r.Close()
		return nil, err
	}
	return r, nil
}

// publishCacheEntry renames the staged entry into place without replacing
// any existing object; a concurrent winner is then verified as before.
func publishCacheEntry(stage, key string) error { return suiteoras.RenameNoReplace(stage, key) }

// ensureWorkspaceRoot creates a missing workspace root as a protected private
// directory. An existing root is used as is (never repaired); the staged
// creation below it applies the public immediate-parent policy.
func ensureWorkspaceRoot(root string) error {
	dir, err := fileaccess.OpenDirectory(root)
	if err == nil {
		return dir.Close()
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return fileaccess.EnsurePrivatePath(root)
}

func flowCreateStage() (string, error) {
	return fileaccess.PrivateTempDir("", "kmx-flow-create-*")
}

// writeFiles creates root (below a private parent) if needed and writes each
// file exclusively through fileaccess, creating private parent directories
// one component at a time.
func writeFiles(root string, files map[string][]byte) error {
	dir, err := openPrivateDirectory(root)
	if err != nil {
		return err
	}
	defer dir.Close()
	for _, name := range slices.Sorted(maps.Keys(files)) {
		parts := strings.Split(name, "/")
		err := inPrivateDirectory(dir, parts[:len(parts)-1], func(parent *os.File) error {
			file, err := fileaccess.OpenPrivateAt(parent, parts[len(parts)-1], os.O_WRONLY|os.O_CREATE|os.O_EXCL)
			if err != nil {
				return err
			}
			_, err = file.Write(files[name])
			return errors.Join(err, file.Close())
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func openPrivateDirectory(path string) (*os.File, error) {
	dir, err := fileaccess.OpenDirectory(path)
	if errors.Is(err, os.ErrNotExist) {
		parent, perr := fileaccess.OpenDirectory(filepath.Dir(path))
		if perr != nil {
			return nil, perr
		}
		defer parent.Close()
		if perr := fileaccess.CheckPrivate(parent, false); perr != nil {
			return nil, fmt.Errorf("%s must be private (current-user-only ACL): %w", parent.Name(), perr)
		}
		return fileaccess.EnsurePrivateDirectoryAt(parent, filepath.Base(path))
	}
	if err != nil {
		return nil, err
	}
	if err := fileaccess.CheckPrivate(dir, false); err != nil {
		dir.Close()
		return nil, fmt.Errorf("%s must be private (current-user-only ACL): %w", path, err)
	}
	return dir, nil
}

// inPrivateDirectory creates or opens each private directory in parts below
// root and runs fn with the innermost one (root itself when parts is empty).
func inPrivateDirectory(root *os.File, parts []string, fn func(*os.File) error) error {
	if len(parts) == 0 {
		return fn(root)
	}
	dir, err := fileaccess.EnsurePrivateDirectoryAt(root, parts[0])
	if err != nil {
		return err
	}
	return errors.Join(inPrivateDirectory(dir, parts[1:], fn), dir.Close())
}

// publishSourceFiles completes every directory inside the private stage, then
// moves each top-level entry into root without replacing anything, and moves
// workspace.yaml last. Windows has no exclusive private mkdir in root that
// fileaccess exposes, so whole private subtrees move instead of the Unix
// mkdir-then-link sequence; the result and publication order are the same.
// Rollback removes only entries this call moved into place.
func publishSourceFiles(ctx context.Context, r *os.Root, root, stage string, dirs map[string]bool, files map[string][]byte) error {
	stageDir, err := openPrivateDirectory(stage)
	if err != nil {
		return err
	}
	for _, name := range slices.Sorted(maps.Keys(dirs)) {
		if err = inPrivateDirectory(stageDir, strings.Split(name, "/"), func(*os.File) error { return nil }); err != nil {
			break
		}
	}
	// Every handle inside the stage is closed before anything is renamed.
	if err := errors.Join(err, stageDir.Close()); err != nil {
		return err
	}
	var top []string
	for name := range dirs {
		if !strings.Contains(name, "/") {
			top = append(top, name)
		}
	}
	for name := range files {
		if name != "workspace.yaml" && !strings.Contains(name, "/") {
			top = append(top, name)
		}
	}
	slices.Sort(top)
	var owned []string
	published := false
	defer func() {
		if !published {
			for _, name := range owned {
				_ = r.RemoveAll(name)
			}
		}
	}()
	for _, name := range append(top, "workspace.yaml") {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := suiteoras.RenameNoReplace(filepath.Join(stage, name), filepath.Join(root, name)); err != nil {
			return err
		}
		owned = append(owned, name)
	}
	published = true
	return nil
}

// cacheOverlaps keeps the lexical fence and adds the physical one: case, 8.3
// and extended-length aliases of the workspace or cache cannot bypass it,
// and an unresolvable location refuses rather than falling back.
func cacheOverlaps(root, cacheDir string) (bool, error) {
	if within(root, cacheDir) || within(cacheDir, root) {
		return true, nil
	}
	for _, pair := range [][2]string{{root, cacheDir}, {cacheDir, root}} {
		if inside, err := suiteoras.PhysicalPathWithin(pair[0], pair[1]); err != nil || inside {
			return true, err
		}
	}
	return false, nil
}
