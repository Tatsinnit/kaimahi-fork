//go:build windows

package app

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/kaimahi-agents/kaimahi/internal/kmx/fileaccess"
)

// Replacing the protected temp directory with os.MkdirTemp must fail this
// contract, even when the host TEMP happens to inherit user-only access.
func TestWindowsChartTempIntegrityAndCleanup(t *testing.T) {
	payload := []byte("verified chart bytes\x00\xff")
	path, cleanup, err := writeOrkaChartTemp(payload)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanup)
	parent, err := fileaccess.OpenDirectory(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if err := fileaccess.CheckPrivate(parent, true); err != nil {
		parent.Close()
		t.Fatalf("chart parent: %v", err)
	}
	parent.Close()
	requirePrivateFileForTest(t, path)
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("chart bytes: %q, %v", got, err)
	}
	cleanup()
	if _, err := os.Lstat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Fatalf("chart temp not removed: %v", err)
	}
}

func TestWindowsChartTempRefusesOtherWritableTEMP(t *testing.T) {
	temporary := t.TempDir()
	winGrantEveryoneFull(t, temporary)
	t.Setenv("TEMP", temporary)
	t.Setenv("TMP", temporary)
	path, cleanup, err := writeOrkaChartTemp([]byte("chart"))
	defer cleanup()
	if err == nil || path != "" {
		t.Fatalf("unsafe TEMP accepted: %q, %v", path, err)
	}
	entries, err := os.ReadDir(temporary)
	if err != nil || len(entries) != 0 {
		t.Fatalf("unsafe TEMP was changed: %v, %v", entries, err)
	}
	winStillBroad(t, temporary)
}

func TestWindowsBuildStagePrivatePublication(t *testing.T) {
	parent := t.TempDir()
	winBroaden(t, parent) // Public read-only ancestors are not private roots.
	output := filepath.Join(parent, "suite.tar")
	file, stage, err := createSuiteBuildStage(parent, output)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.release()
	defer stage.remove()
	raw := []byte("complete verified archive")
	if _, err := file.Write(raw); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := stage.publish(); err != nil {
		t.Fatal(err)
	}
	requirePrivateFileForTest(t, output)
	got, err := os.ReadFile(output)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("published bytes: %q, %v", got, err)
	}
	winNoStage(t, parent, ".suite.tar-")
}

func TestWindowsBuildStageRefusesUntrustedParentAndJunction(t *testing.T) {
	t.Run("other-writable-parent", func(t *testing.T) {
		parent := t.TempDir()
		winGrantEveryoneFull(t, parent)
		file, stage, err := createSuiteBuildStage(parent, filepath.Join(parent, "out.tar"))
		if err == nil {
			file.Close()
			stage.remove()
			stage.release()
			t.Fatal("other-writable output parent accepted")
		}
		entries, err := os.ReadDir(parent)
		if err != nil || len(entries) != 0 {
			t.Fatalf("unsafe output parent changed: %v, %v", entries, err)
		}
		winStillBroad(t, parent)
	})
	t.Run("junction-leaf", func(t *testing.T) {
		parent := privateSuiteDir(t)
		target := privateSuiteDir(t)
		output := filepath.Join(parent, "out.tar")
		winJunction(t, output, target)
		file, stage, err := createSuiteBuildStage(parent, output)
		if err == nil {
			file.Close()
			stage.remove()
			stage.release()
			t.Fatal("junction output accepted")
		}
		winNoStage(t, parent, ".out.tar-")
		entries, err := os.ReadDir(target)
		if err != nil || len(entries) != 0 {
			t.Fatalf("junction target changed: %v, %v", entries, err)
		}
	})
}
