//go:build windows

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kaimahi-agents/kaimahi/internal/kmx/fileaccess"
)

// suiteInputDir returns a fresh AgentSuite input root. AgentSuite v0.6
// refuses a Windows directory input whose root DACL is inherited, so the root
// is a new protected current-user-only directory; children created beneath it
// inherit only owner grants. Safety checks are unchanged.
func suiteInputDir(t *testing.T) string {
	t.Helper()
	dir, err := fileaccess.PrivateTempDir(t.TempDir(), "suite-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// unsafeSuiteDiffInput returns a diff input whose failure text carries
// terminal controls. NTFS cannot name a file with ESC or newline, so the
// controls reach the artifact error through the refused input path itself.
func unsafeSuiteDiffInput(t *testing.T, fixture string) string {
	t.Helper()
	return filepath.Join(fixture, "bad\x1b[31m\nname")
}
