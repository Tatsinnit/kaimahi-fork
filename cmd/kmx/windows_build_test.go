//go:build !windows

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Native filesystem/publication contracts run on Windows CI; this separate
// test prevents either supported Windows architecture regressing at build time.
func TestWindowsBuildsNativeCLI(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		t.Run(arch, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			cmd := exec.CommandContext(ctx, "go", "build", "-o", filepath.Join(t.TempDir(), "kmx.exe"), ".")
			cmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH="+arch, "CGO_ENABLED=0")
			output, err := cmd.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("Windows build timed out: %s", output)
			}
			if err != nil {
				t.Fatalf("Windows native CLI build: %v\n%s", err, output)
			}
		})
	}
}
