//go:build !windows

package main

import "testing"

// privateTestStateDir returns a fresh KMX_HOME fixture. Unix t.TempDir is
// already a new owner-only directory.
func privateTestStateDir(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}
