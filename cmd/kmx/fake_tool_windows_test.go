//go:build windows

package main

import (
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
)

// fakeToolSpecSuffix names the replay table beside a fake tool executable.
const fakeToolSpecSuffix = ".kmx-fake-tool.json"

var (
	fakeToolOnce   sync.Once
	fakeToolDir    string
	fakeToolHelper string
	fakeToolErr    error
)

// TestMain only removes the once-built helper after the run.
func TestMain(m *testing.M) {
	code := m.Run()
	if fakeToolDir != "" {
		os.RemoveAll(fakeToolDir)
	}
	os.Exit(code)
}

// installFakeTool copies the small stdlib-only helper (built once from
// testdata/faketool) to dir as name.exe with its replay table. The POSIX
// script is the Unix counterpart and is not used here.
func installFakeTool(t *testing.T, dir, name, _ string, native fakeTool) {
	t.Helper()
	fakeToolOnce.Do(func() {
		fakeToolDir, fakeToolErr = os.MkdirTemp("", "kmx-faketool-")
		if fakeToolErr == nil {
			fakeToolHelper, fakeToolErr = buildFakeToolHelper(fakeToolDir)
		}
	})
	if fakeToolErr != nil {
		t.Fatal(fakeToolErr)
	}
	target := filepath.Join(dir, name+".exe")
	// Always copy: a hard link would share identity with the helper.
	if err := copyExecutable(fakeToolHelper, target); err != nil {
		t.Fatal(err)
	}
	// Establish fixture readiness before the product starts its bounded
	// context check. This is one setup handshake, never a command retry.
	if output, err := exec.CommandContext(t.Context(), target, "--kmx-fixture-ready").CombinedOutput(); err != nil || len(output) != 0 {
		t.Fatalf("fake tool readiness: output=%q error=%v", output, err)
	}
	raw, err := json.Marshal(native)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target+fakeToolSpecSuffix, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func copyExecutable(source, target string) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
