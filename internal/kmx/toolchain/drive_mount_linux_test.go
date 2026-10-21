//go:build linux

package toolchain

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kaimahi-agents/kaimahi/internal/kmx/fileaccess"
)

// windowsDriveMount returns a path on a mounted Windows drive, skipping the
// test on hosts (non-WSL Linux, CI) that have none. The path itself is never
// created: the refusal must come first.
func windowsDriveMount(t *testing.T) string {
	t.Helper()
	for _, drive := range []string{"/mnt/c", "/mnt/d"} {
		if errors.Is(fileaccess.RefuseWindowsDriveMount(drive), fileaccess.ErrWindowsDriveMount) {
			return filepath.Join(drive, fmt.Sprintf("kmx-toolchain-guard-%d", time.Now().UnixNano()))
		}
	}
	t.Skip("no Windows drive (WSL drvfs) mount on this host")
	return ""
}

// On WSL, kmx's cache and managed command directory must not live on a
// Windows drive: shared native/WSL writes are unsupported. The refusal
// names the path and happens before any download or write.
func TestDriveMountedManagedDirectoriesAreRefusedFirst(t *testing.T) {
	drive := windowsDriveMount(t)
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		http.NotFound(w, r)
	}))
	defer srv.Close()
	spec, _ := Pinned("kind", "linux", "amd64")

	cache := filepath.Join(drive, "cache")
	_, _, err := EnsureReporting(spec, Options{CacheDir: cache, BaseOverride: srv.URL})
	if !errors.Is(err, fileaccess.ErrWindowsDriveMount) || !strings.Contains(err.Error(), cache) {
		t.Fatalf("a drive-mounted cache was not refused by name: %v", err)
	}

	t.Setenv("PATH", t.TempDir())
	link := filepath.Join(drive, "bin")
	linuxCache := t.TempDir()
	_, err = Provision([]string{"kind"}, link, Options{CacheDir: linuxCache, BaseOverride: srv.URL})
	if !errors.Is(err, fileaccess.ErrWindowsDriveMount) || !strings.Contains(err.Error(), link) {
		t.Fatalf("a drive-mounted command directory was not refused by name: %v", err)
	}
	if hits != 0 {
		t.Errorf("downloaded %d times before refusing", hits)
	}
	if entries, _ := os.ReadDir(linuxCache); len(entries) != 0 {
		t.Errorf("the cache was written before the refusal: %v", entries)
	}
	if _, err := os.Lstat(drive); !os.IsNotExist(err) {
		t.Errorf("the refused Windows-drive path was created: %v", err)
	}
}
