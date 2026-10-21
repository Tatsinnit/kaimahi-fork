//go:build !windows

package app

import (
	"os"
	"testing"
)

// requirePrivateFileForTest is the existing Unix 0600 assertion.
func requirePrivateFileForTest(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("%s permissions=%v err=%v", path, info, err)
	}
}

// requireCarriedScriptForTest is the existing owner-executable assertion.
func requireCarriedScriptForTest(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm()&0o100 == 0 {
		t.Errorf("carried script %s is missing or not executable: %v", path, err)
	}
}
