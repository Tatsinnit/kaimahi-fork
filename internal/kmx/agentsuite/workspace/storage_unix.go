//go:build !windows

package workspace

import (
	"context"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
)

// Unix keeps KMX's existing mode-based private storage. These are the
// original calls, moved behind the platform seam unchanged.

func privateTree(root string, setMode bool) error {
	return filepath.WalkDir(root, func(name string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			return errors.New("cache symlinks are not supported")
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !d.IsDir() && !info.Mode().IsRegular() {
			return errors.New("cache contains nonregular file")
		}
		if d.IsDir() {
			if setMode {
				return os.Chmod(name, 0o700)
			}
			if info.Mode().Perm() != 0o700 {
				return errors.New("cache directories must be private (0700)")
			}
		}
		return nil
	})
}
func ensurePrivateCache(cacheDir string) error {
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return err
	}
	info, err := os.Stat(cacheDir)
	if err != nil {
		return err
	}
	if info.Mode().Perm() != 0o700 {
		return errors.New("prepared cache must be private (0700)")
	}
	return nil
}

func cacheOverlaps(root, cacheDir string) (bool, error) {
	return within(root, cacheDir) || within(cacheDir, root), nil
}

func openPrivateRoot(path string) (*os.Root, error) { return os.OpenRoot(path) }

func publishCacheEntry(stage, key string) error { return os.Rename(stage, key) }

func ensureWorkspaceRoot(root string) error { return os.MkdirAll(root, 0o700) }

func flowCreateStage() (string, error) {
	tmp, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil {
		return "", err
	}
	return os.MkdirTemp(tmp, "kmx-flow-create-*")
}

func writeFiles(root string, files map[string][]byte) error {
	for name, b := range files {
		if err := os.MkdirAll(filepath.Join(root, filepath.Dir(name)), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(root, name), b, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func publishSourceFiles(ctx context.Context, r *os.Root, _ string, stage string, dirs map[string]bool, files map[string][]byte) error {
	var owned []string
	published := false
	defer func() {
		if !published {
			for _, name := range owned {
				_ = r.RemoveAll(name)
			}
		}
	}()
	for _, name := range slices.Sorted(maps.Keys(dirs)) {
		if err := r.Mkdir(name, 0o700); err != nil {
			return err
		}
		owned = append(owned, name)
	}
	for name := range files {
		if name == "workspace.yaml" {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := r.Link(filepath.Base(stage)+"/"+name, name); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := r.Link(filepath.Base(stage)+"/workspace.yaml", "workspace.yaml"); err != nil {
		return err
	}
	published = true
	return nil
}
