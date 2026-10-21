//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// installFakeTool writes the POSIX shell fake; native is its Windows replay.
func installFakeTool(t *testing.T, dir, name, script string, _ fakeTool) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
}
