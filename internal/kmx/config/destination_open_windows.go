//go:build windows

package config

import (
	"os"

	"github.com/kaimahi-agents/kaimahi/internal/kmx/fileaccess"
)

// openDestinationsRoot opens abs through the strict volume-rooted,
// per-component no-follow walk: no reparse point or device/UNC namespace is
// followed, and there is no os.Root or path-following fallback. kmx.yaml is
// public operator input, so no private-ACL requirement applies here.
func openDestinationsRoot(abs string) (*os.File, error) {
	return fileaccess.OpenDirectory(abs)
}

// openDestinationsFile opens kmx.yaml read-only as a regular, non-reparse
// file relative to dir. Absence must surface as a not-exist error.
func openDestinationsFile(dir *os.File) (*os.File, error) {
	return fileaccess.OpenRegularAt(dir, "kmx.yaml", os.O_RDONLY)
}
