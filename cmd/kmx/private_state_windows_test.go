//go:build windows

package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/kaimahi-agents/kaimahi/internal/kmx/fileaccess"
)

// privateTestStateDir returns a fresh protected current-user-only KMX_HOME
// fixture rather than t.TempDir's inherited broad descriptor.
func privateTestStateDir(t *testing.T) string {
	t.Helper()
	dir, err := fileaccess.PrivateTempDir(t.TempDir(), "state-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// The handwritten diagnostic fixture belongs in the native physical workspace
// partition, not the Unix path-hash partition. This grants no product authority.
func failureExplainWorkspaceKey(t *testing.T, workspace string) string {
	t.Helper()
	dir, err := fileaccess.OpenDirectory(workspace)
	if err != nil {
		t.Fatal(err)
	}
	id, idErr := fileaccess.PhysicalIdentity(dir)
	if err := errors.Join(idErr, dir.Close()); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x", sha256.Sum256([]byte("kmx/windows-workspace-identity/v1\x00"+id)))
}
