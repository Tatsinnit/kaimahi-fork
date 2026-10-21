//go:build !linux

package fileaccess

// RefuseWindowsDriveMount is a Linux (WSL) concern only. Native Windows and
// macOS paths are governed by their own platform checks.
func RefuseWindowsDriveMount(string) error { return nil }
