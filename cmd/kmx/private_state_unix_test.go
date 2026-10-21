//go:build !windows

package main

import (
	"crypto/sha256"
	"fmt"
	"testing"
)

// privateTestStateDir returns a fresh KMX_HOME fixture. Unix t.TempDir is
// already a new owner-only directory.
func privateTestStateDir(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}

// failureExplainWorkspaceKey keeps the existing Unix fixture's path hash.
func failureExplainWorkspaceKey(t *testing.T, workspace string) string {
	t.Helper()
	return fmt.Sprintf("%x", sha256.Sum256([]byte(workspace)))
}
