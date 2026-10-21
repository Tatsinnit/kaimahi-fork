//go:build windows

package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kaimahi-agents/kaimahi/internal/kmx/fileaccess"
	"golang.org/x/sys/windows"
)

// Windows failure-store fixtures: broad DACLs, junctions and (only when the
// account holds the privilege) symbolic links replace the Unix mode, FIFO and
// unprivileged-symlink cases. Fixtures only damage disposable test objects.

var suiteFailurePlatformUnsafeModes = []string{"broad-record", "broad-pending", "broad-lock", "broad-directory", "junction-record", "junction-pending", "symlink-record"}

func applySuiteFailurePlatformUnsafe(t *testing.T, mode, path, target string) error {
	t.Helper()
	pending := filepath.Join(path, suiteFailurePendingName)
	switch mode {
	case "broad-record":
		winBroaden(t, target)
	case "broad-pending":
		if err := fileaccess.WritePrivateFile(pending, nil, 0600); err != nil {
			return err
		}
		winBroaden(t, pending)
	case "broad-lock":
		winBroaden(t, filepath.Join(path, "lock"))
	case "broad-directory":
		winBroaden(t, path)
	case "junction-record":
		if err := os.Remove(target); err != nil {
			return err
		}
		winJunction(t, `\\?\`+target, `\\?\`+t.TempDir())
	case "junction-pending":
		winJunction(t, `\\?\`+pending, `\\?\`+t.TempDir())
	case "symlink-record":
		// Only the symbolic-link privilege is a capability; nothing is
		// changed before it is proven available.
		probe := filepath.Join(t.TempDir(), "probe")
		if err := os.Symlink(target, probe); errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD) {
			t.Skip("symbolic-link privilege not held:", err)
		} else if err != nil {
			return err
		}
		if err := os.Remove(target); err != nil {
			return err
		}
		return os.Symlink(filepath.Join(t.TempDir(), "outside"), target)
	default:
		t.Fatalf("unknown unsafe mode %q", mode)
	}
	return nil
}

func requireSuiteFailurePrivateFile(t *testing.T, path string) {
	t.Helper()
	winCheckPrivate(t, path, false)
	winRequireProtected(t, path)
}

func requireSuiteFailurePrivateDirectory(t *testing.T, path string) {
	t.Helper()
	winCheckPrivate(t, path, true)
}

func suiteFailureWindowsWorkspace(t *testing.T, root string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, "workspace.yaml"), []byte("schemaVersion: 1\nname: fictional\nmember: agents/fictional/member.yaml\nbuildProfile: build-profiles/default.json\n"), 0644); err != nil {
		t.Fatal(err)
	}
}

// Native save, explain and clear: every created object carries the explicit
// current-user-only descriptor and the record bytes are the shared wire form.
func TestWindowsSuiteFailureStoreNativeLifecycle(t *testing.T) {
	root, d := failureStoreFixture(t)
	suiteFailureWindowsWorkspace(t, root)
	first, err := saveSuiteFailure(t.Context(), root, d)
	if err != nil {
		t.Fatal(err)
	}
	second, err := saveSuiteFailure(t.Context(), root, d)
	if err != nil {
		t.Fatal(err)
	}
	s, err := openSuiteFailureStore(root, false)
	if err != nil {
		t.Fatal(err)
	}
	path := s.path
	entries, err := s.scan()
	if closeErr := s.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	if err != nil || len(entries) != 2 || entries[0].record.Detail.ID != first || entries[1].record.Detail.ID != second {
		t.Fatal("native records not retained in order", entries, err)
	}
	requireSuiteFailurePrivateDirectory(t, filepath.Dir(path))
	requireSuiteFailurePrivateDirectory(t, path)
	requireSuiteFailurePrivateFile(t, filepath.Join(path, "lock"))
	winNoEntries(t, path, 3) // lock plus two records; no stage
	for _, entry := range entries {
		file := filepath.Join(path, entry.name)
		requireSuiteFailurePrivateFile(t, file)
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		want, err := marshalSuiteFailureRecord(entry.record, nil)
		if err != nil || !bytes.Equal(raw, want) {
			t.Fatal("native record is not the shared wire form", err)
		}
		var decoded suiteFailureRecord
		if json.Unmarshal(raw, &decoded) != nil || decoded.SchemaVersion != 1 || decoded.Detail.ID != entry.record.Detail.ID {
			t.Fatal("native record wire fields changed")
		}
	}
	var out bytes.Buffer
	a := &App{Out: &out, Err: io.Discard}
	if err := a.ExplainSuiteEvaluation(t.Context(), SuiteEvaluationExplainOptions{Workspace: root, ID: second, ShowContent: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), second) || !strings.Contains(out.String(), "fictional answer") {
		t.Fatal("native explain lost detail", out.String())
	}
	out.Reset()
	if err := a.ExplainSuiteEvaluation(t.Context(), SuiteEvaluationExplainOptions{Workspace: root, ID: first, Clear: true}); err != nil || !strings.Contains(out.String(), "Cleared 1 ") {
		t.Fatal("native single clear", out.String(), err)
	}
	out.Reset()
	if err := a.ExplainSuiteEvaluation(t.Context(), SuiteEvaluationExplainOptions{Workspace: root, Clear: true}); err != nil || !strings.Contains(out.String(), "Cleared 1 ") {
		t.Fatal("native clear all", out.String(), err)
	}
	winNoEntries(t, path, 1)
}

// An existing broad partition or base is refused before any stage or record
// bytes are created, and is never repaired.
func TestWindowsSuiteFailureStoreRefusesBroadDirectoriesBeforeBytes(t *testing.T) {
	for _, level := range []string{"partition", "base"} {
		t.Run(level, func(t *testing.T) {
			root, d := failureStoreFixture(t)
			if _, err := saveSuiteFailure(t.Context(), root, d); err != nil {
				t.Fatal(err)
			}
			s, err := openSuiteFailureStore(root, false)
			if err != nil {
				t.Fatal(err)
			}
			path := s.path
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			broad := path
			if level == "base" {
				broad = filepath.Dir(path)
			}
			winBroaden(t, broad)
			if _, err := saveSuiteFailure(t.Context(), root, d); !errors.Is(err, errSuiteFailureStore) {
				t.Fatal("broad directory accepted for new bytes", err)
			}
			winStillBroad(t, broad)
			winNoEntries(t, path, 2)
		})
	}
}

// Case, extended-length and 8.3 spellings of one workspace share one
// physical partition and lock.
func TestWindowsSuiteFailureStoreWorkspaceAliasesShareLock(t *testing.T) {
	_, d := failureStoreFixture(t)
	workspace := filepath.Join(t.TempDir(), "Workspace Alias Root")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	aliases := []string{strings.ToUpper(workspace), strings.ToLower(workspace), `\\?\` + workspace}
	if short := winShortPath(t, workspace); short != workspace {
		aliases = append(aliases, short)
	} else {
		t.Log("8.3 short names unavailable on this volume; short alias not exercised")
	}
	held, err := openSuiteFailureStore(workspace, true)
	if err != nil {
		t.Fatal(err)
	}
	path := held.path
	for _, alias := range aliases {
		if s, err := openSuiteFailureStore(alias, true); !errors.Is(err, errSuiteFailureBusy) {
			if s != nil {
				s.Close()
			}
			t.Errorf("alias %s split the workspace lock: %v", alias, err)
		}
	}
	if err := held.Close(); err != nil {
		t.Fatal(err)
	}
	id, err := saveSuiteFailure(t.Context(), aliases[0], d)
	if err != nil {
		t.Fatal(err)
	}
	for _, alias := range append(aliases, workspace) {
		s, err := openSuiteFailureStore(alias, false)
		if err != nil {
			t.Fatalf("alias %s: %v", alias, err)
		}
		entries, scanErr := s.scan()
		got := s.path
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		if got != path || scanErr != nil || len(entries) != 1 || entries[0].record.Detail.ID != id {
			t.Errorf("alias %s partition %s entries %v err %v; want %s with %s", alias, got, entries, scanErr, path, id)
		}
	}
}

// If the stage cannot be retired after the exclusive link, the complete record
// is visible under its ID, the caller is told, and the second name keeps the
// store refusing until an operator removes the stage.
func TestWindowsSuiteFailureStoreLinkedStageUncertainty(t *testing.T) {
	root, d := failureStoreFixture(t)
	s, err := openSuiteFailureStore(root, true)
	if err != nil {
		t.Fatal(err)
	}
	path := s.path
	publish := s.publish
	s.publish = func(from, to string) error {
		if err := publish(from, to); err != nil {
			return err
		}
		return s.root.Close()
	}
	id, err := s.save(t.Context(), d)
	_ = s.Close() // The injected failure already closed the root handle.
	if !suiteFailureID.MatchString(id) || !errors.Is(err, errSuiteFailureStore) {
		t.Fatal("visible publication lost its ID", id, err)
	}
	matches, err := filepath.Glob(filepath.Join(path, "*-"+id+".json"))
	if err != nil || len(matches) != 1 {
		t.Fatal("linked record missing", matches, err)
	}
	raw, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	var record suiteFailureRecord
	if json.Unmarshal(raw, &record) != nil || record.Detail.ID != id || validateSuiteFailureRecord(record, nil) != nil {
		t.Fatal("linked record incomplete")
	}
	requireSuiteFailurePrivateFile(t, matches[0])
	fresh, err := openSuiteFailureStore(root, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.scan(); !errors.Is(err, errSuiteFailureStore) {
		t.Fatal("second name accepted", err)
	}
	if err := fresh.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(path, suiteFailurePendingName)); err != nil {
		t.Fatal(err)
	}
	fresh, err = openSuiteFailureStore(root, false)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	entries, err := fresh.scan()
	if err != nil || len(entries) != 1 || entries[0].record.Detail.ID != id {
		t.Fatal("published record lost", entries, err)
	}
}
