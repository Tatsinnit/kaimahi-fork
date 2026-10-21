//go:build !windows

package toolchain

import (
	"os"
	"path/filepath"
	"testing"
)

// Unix keeps its historical layout: the plain command is a symlink to the
// versioned cache entry, the binary is 0755 and its digest record 0644.
func TestUnixManagedLayoutIsUnchanged(t *testing.T) {
	cache := filepath.Join(t.TempDir(), "cache")
	path := filepath.Join(cache, cacheFileName("kind", KindVersion, "linux", "amd64"))
	if err := install(path, []byte("#!/bin/sh\n")); err != nil {
		t.Fatal(err)
	}
	if err := writeDigest(path+".sha256", []byte(digestOf([]byte("#!/bin/sh\n"))+"  kind\n")); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o755 {
		t.Errorf("binary is not installed 0755: %v, %v", info, err)
	}
	// The digest record goes through the umask, as before: never more than 0644.
	if info, err := os.Stat(path + ".sha256"); err != nil || info.Mode().Perm()&^0o644 != 0 {
		t.Errorf("digest record is broader than 0644: %v, %v", info, err)
	}
	link, err := publishAlias(filepath.Join(t.TempDir(), "bin"), "kind", path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(link) != "kind" {
		t.Errorf("alias %q, want the plain name", link)
	}
	target, err := os.Readlink(link)
	if err != nil || target != path {
		t.Fatalf("alias is not a symlink to the cache entry: %q, %v", target, err)
	}
}
