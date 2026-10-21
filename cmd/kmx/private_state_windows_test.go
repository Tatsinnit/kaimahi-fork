//go:build windows

package main

import (
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
