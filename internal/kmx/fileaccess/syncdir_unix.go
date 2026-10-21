//go:build !windows

// Package fileaccess holds platform-specific handle operations for KMX's
// private on-disk state.
package fileaccess

import "os"

// OpenSyncDirectory opens the directory anchored by root so the caller can
// Sync it after publishing entries there. The caller closes the result and
// treats a Sync failure as fatal.
func OpenSyncDirectory(root *os.Root) (*os.File, error) {
	return root.Open(".")
}
