//go:build linux

package app

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kaimahi-agents/kaimahi/internal/kmx/fileaccess"
)

// windowsDriveForTest returns a real WSL drive mount or skips; refused paths
// beneath it are unique and must never be created.
func windowsDriveForTest(t *testing.T) string {
	t.Helper()
	for _, drive := range []string{"/mnt/c", "/mnt/d"} {
		if errors.Is(fileaccess.RefuseWindowsDriveMount(drive), fileaccess.ErrWindowsDriveMount) {
			return drive
		}
	}
	t.Skip("no Windows drive (WSL drvfs) mount on this host")
	return ""
}

func requireNamedDriveRefusal(t *testing.T, name string, err, class error, path, created string) {
	t.Helper()
	if !errors.Is(err, class) || !errors.Is(err, fileaccess.ErrWindowsDriveMount) ||
		!strings.Contains(err.Error(), strconv.Quote(path)) || !strings.Contains(err.Error(), "use a Linux path or run native Windows kmx") {
		t.Errorf("%s: drive-mount refusal lost its class or named remedy: %v", name, err)
	}
	if _, statErr := os.Lstat(created); !os.IsNotExist(statErr) {
		t.Errorf("%s: refused boundary created %s: %v", name, created, statErr)
	}
}

// Managed state on a Windows drive is refused before any effect, and each
// redacted boundary keeps its class while naming the path and remedy.
func TestStateBoundariesNameWindowsDriveMountBeforeEffects(t *testing.T) {
	drive := windowsDriveForTest(t)
	store, suite, raw := passStoreFixture(t)
	root := store.workspace
	publicCommitFixture(t, store, suite, raw)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(privateSuiteDir(t), "evidence.json")
	dir := filepath.Join(drive, fmt.Sprintf("kmx-state-guard-%d", time.Now().UnixNano()))
	state := filepath.Join(dir, "state")
	t.Setenv("KMX_HOME", state)
	a := &App{Out: io.Discard, Err: io.Discard}
	ctx := t.Context()
	for name, c := range map[string]struct {
		run   func() error
		class error
	}{
		"public export state": {func() error {
			return a.ExportSuiteEvaluation(ctx, SuiteEvaluationExportOptions{Workspace: root, Member: suite.MemberID, Out: out})
		}, errSuitePublicProof},
		"release lift storage": {func() error {
			w, err := openReleaseLiftStorage(ctx)
			if w != nil {
				w.Close()
			}
			return err
		}, errReleaseLiftRecord},
		"release ownership": {func() error {
			_, err := readReleaseOwnership(ctx, strings.Repeat("ab", 16))
			return err
		}, errReleaseUpdateUnsupported},
		"evaluation state": {func() error {
			p, err := PrepareSuiteWorkspaceEvaluation(ctx, SuiteWorkspaceEvaluationOptions{Workspace: root, ManagedPass: true, ToContext: "kind-test", Inference: "provider:inference"})
			if p != nil {
				p.Close()
			}
			return err
		}, errSuiteNativeRefused},
	} {
		requireNamedDriveRefusal(t, name, c.run(), c.class, state, dir)
	}
	if _, err := os.Lstat(out); !os.IsNotExist(err) {
		t.Fatalf("refused export wrote output: %v", err)
	}
}

// A public evidence output on a Windows drive is refused by name before the
// output directory is anchored or created.
func TestSuitePublicExportNamesWindowsDriveMountOutput(t *testing.T) {
	drive := windowsDriveForTest(t)
	store, suite, raw := passStoreFixture(t)
	root := store.workspace
	publicCommitFixture(t, store, suite, raw)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(drive, fmt.Sprintf("kmx-public-guard-%d", time.Now().UnixNano()))
	out := filepath.Join(dir, "evidence.json")
	err := (&App{Out: io.Discard, Err: io.Discard}).ExportSuiteEvaluation(t.Context(), SuiteEvaluationExportOptions{Workspace: root, Member: suite.MemberID, Out: out})
	requireNamedDriveRefusal(t, "public export output", err, errSuitePublicOutput, out, dir)
}
