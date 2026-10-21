//go:build !windows

package oras

import (
	"os"
	"testing"
)

// Unix fixtures are used exactly as before; see fixture_windows_test.go.

func privateFixtureDir(_ *testing.T, path string) string { return path }

func emptyFixtureDir(t *testing.T) string { return t.TempDir() }

func fixtureSource(_ *testing.T, path string) string { return path }

func symlinkPrivilegeMissing(error) bool { return false }

const sharedWritableRefusal = "unsafe file mode"

func makeSharedWritable(t *testing.T, path string) {
	t.Helper()
	if err := os.Chmod(path, 0o664); err != nil {
		t.Fatal(err)
	}
}
