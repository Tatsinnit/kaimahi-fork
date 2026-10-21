//go:build !windows

package app

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/kaimahi-agents/kaimahi/internal/kmx/lift"
)

// Unix private-state adapters for preferences, agent locations, Lift records
// and quickstart state. Each body is the call sequence its caller used before
// Windows support, moved here unchanged; Unix modes, sync and rename behavior
// are exactly as before.

func writePrivateAgentFile(path string, raw []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".agent-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err = file.Write(raw); err != nil {
		file.Close()
		return err
	}
	if err = file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}

func readPrivatePreference(path string) ([]byte, error) { return os.ReadFile(path) }

func removePrivatePreference(path string) error { return os.Remove(path) }

// forEachPrivateAgentFile calls fn for each non-directory entry of dir whose
// name ends in suffix, in name order. A missing dir has no entries.
func forEachPrivateAgentFile(dir, suffix string, fn func(name string, raw []byte) error) error {
	files, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), suffix) {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, file.Name()))
		if err != nil {
			return err
		}
		if err := fn(file.Name(), raw); err != nil {
			return err
		}
	}
	return nil
}

func openLiftRecordFile(path string) (io.ReadCloser, error) { return os.Open(path) }

func replaceLiftRecordFile(path string, record *lift.Record) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".record-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := record.Write(tmp); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// writeOrkaChartTemp is the existing 0600 temporary chart archive Helm reads
// by path; cleanup removes it.
func writeOrkaChartTemp(chart []byte) (string, func(), error) {
	file, err := os.CreateTemp("", "kmx-orka-*.tgz")
	if err != nil {
		return "", func() {}, err
	}
	cleanup := func() { _ = os.Remove(file.Name()) }
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		cleanup()
		return "", func() {}, err
	}
	if _, err := file.Write(chart); err != nil {
		file.Close()
		cleanup()
		return "", func() {}, err
	}
	if err := file.Close(); err != nil {
		cleanup()
		return "", func() {}, err
	}
	return file.Name(), cleanup, nil
}

// suiteBuildStage is BuildSuite's existing staged output: a CreateTemp file
// beside the output, made 0644 and renamed over it.
type suiteBuildStage struct{ path, output string }

func createSuiteBuildStage(parent, outputPath string) (*os.File, *suiteBuildStage, error) {
	file, err := os.CreateTemp(parent, "."+filepath.Base(outputPath)+"-*")
	if err != nil {
		return nil, nil, err
	}
	return file, &suiteBuildStage{path: file.Name(), output: outputPath}, nil
}

func (s *suiteBuildStage) remove()        { _ = os.Remove(s.path) }
func (s *suiteBuildStage) setMode() error { return os.Chmod(s.path, 0o644) }
func (s *suiteBuildStage) publish() error { return os.Rename(s.path, s.output) }
func (s *suiteBuildStage) release()       {}

// ensurePrivateWorkspaceState refuses linked ancestors before creating local
// source or exclusive evidence, then requires base to have no group or other
// permission bits.
func ensurePrivateWorkspaceState(base string) error {
	for path := base; ; path = filepath.Dir(path) {
		info, err := os.Lstat(path)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		if err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.IsDir()) {
			return errors.New("quickstart state requires unlinked directories")
		}
		if path == filepath.Dir(path) {
			break
		}
	}
	if err := os.MkdirAll(base, 0700); err != nil {
		return err
	}
	info, err := os.Stat(base)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0077 != 0 {
		return errors.New("quickstart state must be private")
	}
	return nil
}
