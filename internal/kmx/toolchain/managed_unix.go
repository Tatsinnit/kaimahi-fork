//go:build !windows

package toolchain

import (
	"os"
	"path/filepath"
)

// On Unix the managed directories keep their historical behavior: created
// on demand with ordinary modes, the binary installed 0755 beside a 0644
// digest record, and the plain command name a SYMLINK to the versioned
// cache entry. (Windows publishes a verified copy instead; see
// managed_windows.go.)

// prepareManagedDir has nothing to check up front on Unix: install and
// relink create the directories they write into.
func prepareManagedDir(string) error { return nil }

// readManagedFile reads a cache entry. Any read error is a miss — the entry
// is then fetched again rather than trusted.
func readManagedFile(path string) ([]byte, bool, error) {
	data, err := os.ReadFile(path)
	return data, err == nil, nil
}

// discardCacheEntry removes an entry that failed re-verification. A
// leftover is harmless: it is re-verified, and refused, on the next run.
func discardCacheEntry(path string) error {
	_ = os.Remove(path)
	_ = os.Remove(path + ".sha256")
	return nil
}

// install writes the binary atomically: a killed download must not leave a
// truncated file behind under the real name.
func install(path string, binary []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".partial-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(binary); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o755); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// writeDigest records the installed binary's digest beside it.
func writeDigest(path string, line []byte) error {
	return os.WriteFile(path, line, 0o644)
}

// publishAlias links linkDir/<name> to the versioned cache entry.
func publishAlias(linkDir, name, target string, _ []byte) (string, error) {
	link := filepath.Join(linkDir, name)
	return link, relink(link, target)
}

// relink points linkDir/<name> at the versioned cache entry, replacing
// whatever was there. Replacing rather than keeping is the point: after a pin
// bump the old link would otherwise still be the thing on PATH.
func relink(link, target string) error {
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		return err
	}
	if err := os.Remove(link); err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.Symlink(target, link)
}
