//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// suiteInputDir returns a fresh AgentSuite input root: t.TempDir itself.
func suiteInputDir(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}

// unsafeSuiteDiffInput adds a world-writable supplemental file whose name
// carries terminal controls and returns the suite directory to diff.
func unsafeSuiteDiffInput(t *testing.T, fixture string) string {
	t.Helper()
	unsafePath := filepath.Join(fixture, "bad\x1b[31m\nname")
	if err := os.WriteFile(unsafePath, []byte("unsafe"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafePath, 0o666); err != nil {
		t.Fatal(err)
	}
	return fixture
}
