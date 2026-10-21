//go:build !windows

package workspace_test

import (
	"os"
	"testing"
)

// Unix fixtures are used exactly as before; see storage_windows_test.go.

func fixtureSource(_ *testing.T, path string) string { return path }

func emptySourceDir(t *testing.T) string { return t.TempDir() }

func symlinkUnavailable(*testing.T, error) {}

func makeEntryShared(t *testing.T, path string) {
	t.Helper()
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatal(err)
	}
}
