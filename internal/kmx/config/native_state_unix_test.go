//go:build !windows

package config

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Unix state fixtures are plain temporary directories, exactly as before.
func privateStateHome(t *testing.T) string { return t.TempDir() }

func expectedNativeStateDir(t *testing.T, xdg string) string {
	t.Helper()
	switch runtime.GOOS {
	case "linux":
		return filepath.Join(xdg, "kmx")
	case "darwin":
		userHome, err := os.UserHomeDir()
		if err != nil {
			t.Fatal(err)
		}
		return filepath.Join(userHome, "Library", "Application Support", "kmx")
	default:
		native, err := os.UserConfigDir()
		if err != nil {
			t.Fatal(err)
		}
		return filepath.Join(native, "kmx")
	}
}

// Resolving state on Unix inspects metadata only: no directory appears until
// a writer creates it, and the selected-context writer keeps its exact modes.
func TestUnixStateResolutionNeverCreatesAndContextKeepsModes(t *testing.T) {
	home := filepath.Join(t.TempDir(), "missing", "kmx")
	t.Setenv("KMX_HOME", home)
	for name, tc := range map[string]struct {
		get  func() (string, error)
		want string
	}{
		"state":     {StateDir, home},
		"cache":     {CacheDir, filepath.Join(home, "bin")},
		"lift":      {LiftRecordDir, filepath.Join(home, "lift")},
		"toolchain": {ToolchainDir, filepath.Join(home, "path")},
	} {
		if got, err := tc.get(); err != nil || got != tc.want {
			t.Fatalf("%s = %q, %v; want %q", name, got, err, tc.want)
		}
	}
	xdg := filepath.Join(t.TempDir(), "xdg")
	t.Setenv("KMX_HOME", "")
	t.Setenv("XDG_CONFIG_HOME", xdg)
	if _, err := StateDir(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Dir(home), xdg} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("resolution created %s: %v", path, err)
		}
	}

	t.Setenv("KMX_HOME", home)
	path, err := WriteSelectedContext("kind-demo")
	if err != nil || path != filepath.Join(home, "context") {
		t.Fatalf("write = %q, %v", path, err)
	}
	if info, err := os.Stat(home); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("state root mode: %v %v", info, err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("context mode: %v %v", info, err)
	}
	if got, err := ReadSelectedContext(); err != nil || got != "kind-demo" {
		t.Fatalf("read = %q, %v", got, err)
	}
}
