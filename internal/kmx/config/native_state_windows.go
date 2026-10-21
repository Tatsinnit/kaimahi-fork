//go:build windows

package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/kaimahi-agents/kaimahi/internal/kmx/fileaccess"
	"golang.org/x/sys/windows"
)

// nativeStateDirectory is %LOCALAPPDATA%\kmx: machine-local, not the roaming
// profile, so private state and cached binaries never sync between machines.
// An empty LOCALAPPDATA falls back only to the LocalAppData known folder;
// APPDATA, HOME and USERPROFILE are never consulted. A relative value is
// refused rather than resolved against the working directory.
func nativeStateDirectory() (string, error) {
	local := os.Getenv("LOCALAPPDATA")
	if local == "" {
		known, err := windows.KnownFolderPath(windows.FOLDERID_LocalAppData, windows.KF_FLAG_DONT_VERIFY)
		if err != nil {
			return "", fmt.Errorf("cannot locate the LocalAppData folder (set KMX_HOME): %w", err)
		}
		local = known
	}
	if !filepath.IsAbs(local) {
		return "", fmt.Errorf("LOCALAPPDATA %q is not an absolute path (set KMX_HOME)", local)
	}
	return filepath.Join(local, "kmx"), nil
}

// prepareStateDirectory creates the state root with a protected
// current-user-only DACL, or checks an existing one. An existing root with
// any broader access is refused, never repaired or adopted.
func prepareStateDirectory(dir string) error {
	return fileaccess.EnsurePrivatePath(dir)
}

// ExistingStateDir resolves the same state location without creating it.
// Read-only inspection must be inert when state is absent, and must still
// refuse an existing unsafe root rather than repair or adopt it.
func ExistingStateDir() (string, error) {
	dir, err := stateDirPath()
	if err != nil {
		return "", err
	}
	if err := fileaccess.RefuseWindowsDriveMount(dir); err != nil {
		return "", err
	}
	root, err := fileaccess.OpenExistingPrivateDirectory(dir)
	if err != nil {
		return "", err
	}
	if err := errors.Join(fileaccess.CheckPrivate(root, true), root.Close()); err != nil {
		return "", err
	}
	return dir, nil
}

func readSelectedContextFile(path string) ([]byte, error) {
	parent, err := fileaccess.OpenDirectory(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	if err := fileaccess.CheckPrivate(parent, true); err != nil {
		return nil, err
	}
	file, err := fileaccess.OpenPrivateAt(parent, filepath.Base(path), os.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	const maxContextBytes = 1 << 20
	before, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if before.Size() > maxContextBytes {
		return nil, fmt.Errorf("selected context exceeds the size limit")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxContextBytes+1))
	if err != nil {
		return nil, err
	}
	after, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if len(raw) > maxContextBytes || int64(len(raw)) != before.Size() || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return nil, fmt.Errorf("selected context changed while reading")
	}
	if err := fileaccess.CheckPrivate(file, false); err != nil {
		return nil, err
	}
	return raw, nil
}

// writeSelectedContextFile writes under the already-prepared private root;
// an existing context file is ACL-checked before any bytes are written.
func writeSelectedContextFile(path string, data []byte) error {
	return fileaccess.WritePrivateFile(path, data, 0o600)
}
