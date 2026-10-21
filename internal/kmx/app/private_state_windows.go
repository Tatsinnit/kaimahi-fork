//go:build windows

package app

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/kaimahi-agents/kaimahi/internal/kmx/fileaccess"
	"github.com/kaimahi-agents/kaimahi/internal/kmx/lift"
)

// Windows private-state adapters for preferences, agent locations (including
// kubeconfig credential snapshots), Lift records and quickstart state.
//
// The protected state root alone does not protect its children: a principal
// holding a broad grant on a child can open it by full path through
// SeChangeNotifyPrivilege traverse bypass. So every parent and leaf is opened
// as itself (fileaccess never follows a reparse point), its owner/DACL is
// checked on the opened handle before any byte is read or staged, and new
// files get the explicit current-user-only descriptor at creation. Existing
// unsafe objects are refused, never repaired or replaced.

// maxPrivatePreferenceBytes bounds one private preference, location or Lift
// record read. These are small JSON documents; 1 MiB matches the selected
// context reader and keeps a corrupted or substituted file from exhausting
// memory.
const maxPrivatePreferenceBytes = 1 << 20

var errPrivateFileChanged = errors.New("private file changed while it was being read or replaced")

// openPrivateParent opens the directory holding path's final component and
// requires it to be a private directory.
func openPrivateParent(path string) (*os.File, string, error) {
	parentPath, leaf, ok := splitWindowsLeaf(path)
	if !ok {
		return nil, "", &os.PathError{Op: "open", Path: path, Err: os.ErrInvalid}
	}
	dir, err := fileaccess.OpenDirectory(parentPath)
	if err != nil {
		return nil, "", err
	}
	if err := fileaccess.CheckPrivate(dir, false); err != nil {
		dir.Close()
		return nil, "", &os.PathError{Op: "open", Path: dir.Name(), Err: err}
	}
	return dir, leaf, nil
}

// readPrivateAt reads the existing private regular file name below dir. The
// owner/DACL check precedes the first byte and is repeated afterwards, and
// the size and modification time must be unchanged across the bounded read.
func readPrivateAt(dir *os.File, name string) ([]byte, error) {
	file, err := fileaccess.OpenPrivateAt(dir, name, os.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if before.Size() > maxPrivatePreferenceBytes {
		return nil, fmt.Errorf("private file %s exceeds the %d byte limit", file.Name(), maxPrivatePreferenceBytes)
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxPrivatePreferenceBytes+1))
	if err != nil {
		return nil, err
	}
	after, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if len(raw) > maxPrivatePreferenceBytes || int64(len(raw)) != before.Size() || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return nil, fmt.Errorf("%s: %w", file.Name(), errPrivateFileChanged)
	}
	if err := fileaccess.CheckPrivate(file, false); err != nil {
		return nil, &os.PathError{Op: "read", Path: file.Name(), Err: err}
	}
	return raw, nil
}

// recheckPrivateParent repeats the parent check once an operation completes.
func recheckPrivateParent(dir *os.File) error {
	if err := fileaccess.CheckPrivate(dir, false); err != nil {
		return &os.PathError{Op: "check", Path: dir.Name(), Err: err}
	}
	return nil
}

func readPrivatePreference(path string) ([]byte, error) {
	dir, leaf, err := openPrivateParent(path)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	raw, err := readPrivateAt(dir, leaf)
	if err != nil {
		return nil, err
	}
	if err := recheckPrivateParent(dir); err != nil {
		return nil, err
	}
	return raw, nil
}

// removePrivatePreference removes an existing private file. A destination
// that is not a private regular file is refused and left in place.
func removePrivatePreference(path string) error {
	dir, leaf, err := openPrivateParent(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	existing, err := fileaccess.OpenPrivateAt(dir, leaf, os.O_RDONLY)
	if err != nil {
		return err
	}
	if err := existing.Close(); err != nil {
		return err
	}
	root, _, err := adoptVerifiedRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	return root.Remove(leaf)
}

func forEachPrivateAgentFile(dirPath, suffix string, fn func(name string, raw []byte) error) error {
	dir, err := fileaccess.OpenDirectory(dirPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer dir.Close()
	if err := recheckPrivateParent(dir); err != nil {
		return err
	}
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return err
	}
	slices.SortFunc(entries, func(a, b os.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
	for _, entry := range entries {
		// A directory is skipped as on Unix; any other non-regular entry with
		// the suffix (a junction or symbolic link) is refused by the strict open.
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), suffix) {
			continue
		}
		raw, err := readPrivateAt(dir, entry.Name())
		if err != nil {
			return err
		}
		if err := fn(entry.Name(), raw); err != nil {
			return err
		}
	}
	return recheckPrivateParent(dir)
}

// createPrivateStage exclusively creates a new private file below dir named
// prefix plus a random suffix, like os.CreateTemp, with access
// os.O_WRONLY or os.O_RDWR.
func createPrivateStage(dir *os.File, prefix string, access int) (*os.File, string, error) {
	for try := 0; try < 100; try++ {
		var random [8]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, "", err
		}
		name := prefix + hex.EncodeToString(random[:])
		file, err := fileaccess.OpenPrivateAt(dir, name, access|os.O_CREATE|os.O_EXCL)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return nil, "", err
		}
		return file, name, nil
	}
	return nil, "", &os.PathError{Op: "createtemp", Path: dir.Name(), Err: os.ErrExist}
}

// writePrivateAgentFile atomically replaces path with raw. The parent must be
// private and an existing destination must be a private regular file before
// anything is staged. The stage is created with the explicit private
// descriptor, written, flushed and closed, then renamed over the destination
// relative to the verified parent handle with replace semantics (never
// delete-then-create, so there is no missing-file window). The destination is
// then proven to be the staged object.
func writePrivateAgentFile(path string, raw []byte) error {
	dir, leaf, err := openPrivateParent(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	if existing, err := fileaccess.OpenPrivateAt(dir, leaf, os.O_RDONLY); err == nil {
		if err := existing.Close(); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	root, _, err := adoptVerifiedRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	stage, name, err := createPrivateStage(dir, ".agent-", os.O_WRONLY)
	if err != nil {
		return err
	}
	renamed := false
	defer func() {
		if !renamed {
			_ = root.Remove(name)
		}
	}()
	if _, err = stage.Write(raw); err != nil {
		stage.Close()
		return err
	}
	if err = stage.Sync(); err != nil {
		stage.Close()
		return err
	}
	want, err := fileaccess.PhysicalIdentity(stage)
	if err != nil {
		stage.Close()
		return err
	}
	if err = stage.Close(); err != nil {
		return err
	}
	if err = root.Rename(name, leaf); err != nil {
		return err
	}
	renamed = true
	current, err := fileaccess.OpenPrivateAt(dir, leaf, os.O_RDONLY)
	if err != nil {
		return err
	}
	got, idErr := fileaccess.PhysicalIdentity(current)
	if err := errors.Join(idErr, current.Close()); err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("%s: %w", path, errPrivateFileChanged)
	}
	return recheckPrivateParent(dir)
}

// openLiftRecordFile reads a saved Lift record (subscription and resource
// identifiers) through the private bounded reader.
func openLiftRecordFile(path string) (io.ReadCloser, error) {
	raw, err := readPrivatePreference(path)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(raw)), nil
}

func replaceLiftRecordFile(path string, record *lift.Record) error {
	var raw bytes.Buffer
	if err := record.Write(&raw); err != nil {
		return err
	}
	return writePrivateAgentFile(path, raw.Bytes())
}

// writeOrkaChartTemp writes the verified chart archive for Helm, which
// reads it by path. The bytes are public, but their integrity matters until
// Helm has read them, so even under a custom TEMP the archive lives in a new
// protected current-user-only directory (whose TEMP parent must refuse other
// writers) and is created with the explicit private descriptor.
func writeOrkaChartTemp(chart []byte) (string, func(), error) {
	dir, err := fileaccess.PrivateTempDir("", "kmx-orka-")
	if err != nil {
		return "", func() {}, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	path := filepath.Join(dir, "orka.tgz")
	if err := fileaccess.WritePrivateFile(path, chart, 0o600); err != nil {
		cleanup()
		return "", func() {}, err
	}
	return path, cleanup, nil
}

// suiteBuildStage publishes BuildSuite's image archive. The parent is opened
// without following any reparse point; an existing destination must be a
// regular non-reparse file before the builder runs. The stage is created with
// the explicit private descriptor (Windows has no public 0644 analogue that
// avoids inherited grants) and renamed over the destination relative to the
// identity-verified parent handle, then proven to be the published object.
type suiteBuildStage struct {
	dir        *os.File
	root       *os.Root
	name, leaf string
	identity   string
}

func createSuiteBuildStage(parent, outputPath string) (*os.File, *suiteBuildStage, error) {
	dir, err := fileaccess.OpenDirectory(parent)
	if err != nil {
		return nil, nil, err
	}
	// A private stage alone cannot protect its name from another writer
	// with delete-child rights on the output parent.
	if err := fileaccess.CheckSafeDirectory(dir, true); err != nil {
		dir.Close()
		return nil, nil, err
	}
	leaf := filepath.Base(outputPath)
	if existing, err := fileaccess.OpenRegularAt(dir, leaf, os.O_RDONLY); err == nil {
		existing.Close()
	} else if !os.IsNotExist(err) {
		dir.Close()
		return nil, nil, err
	}
	root, _, err := adoptVerifiedRoot(dir)
	if err != nil {
		dir.Close()
		return nil, nil, err
	}
	file, name, err := createPrivateStage(dir, "."+leaf+"-", os.O_RDWR)
	if err != nil {
		root.Close()
		dir.Close()
		return nil, nil, err
	}
	identity, err := fileaccess.PhysicalIdentity(file)
	if err != nil {
		file.Close()
		_ = root.Remove(name)
		root.Close()
		dir.Close()
		return nil, nil, err
	}
	return file, &suiteBuildStage{dir: dir, root: root, name: name, leaf: leaf, identity: identity}, nil
}

func (s *suiteBuildStage) remove() { _ = s.root.Remove(s.name) }

// setMode has no Windows counterpart: the private descriptor is the policy.
func (s *suiteBuildStage) setMode() error { return nil }

func (s *suiteBuildStage) publish() error {
	if err := s.root.Rename(s.name, s.leaf); err != nil {
		return err
	}
	current, err := fileaccess.OpenRegularAt(s.dir, s.leaf, os.O_RDONLY)
	if err != nil {
		return err
	}
	got, idErr := fileaccess.PhysicalIdentity(current)
	if err := errors.Join(idErr, current.Close()); err != nil {
		return err
	}
	if got != s.identity {
		return fmt.Errorf("%s: %w", s.leaf, errPrivateFileChanged)
	}
	return nil
}

func (s *suiteBuildStage) release() {
	s.root.Close()
	s.dir.Close()
}

// ensurePrivateWorkspaceState creates base as a protected current-user-only
// directory or checks an existing one. Every existing ancestor is walked
// without following reparse points under the public ancestor policy; an
// existing base that is linked, inherited-only, broad or foreign-owned is
// refused and never repaired.
func ensurePrivateWorkspaceState(base string) error {
	if err := fileaccess.EnsurePrivatePath(base); err != nil {
		return fmt.Errorf("quickstart state must be an unlinked private directory: %w", err)
	}
	return nil
}
