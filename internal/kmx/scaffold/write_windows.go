//go:build windows

package scaffold

import (
	"os"
	"path/filepath"

	"github.com/kaimahi-agents/kaimahi/internal/kmx/fileaccess"
)

// createNew walks to the parent without following any reparse point,
// creating missing directories with the explicit protected current-user-only
// descriptor, then exclusively creates the file with that descriptor before
// any byte is written. Windows AgentSuite validation requires private roots
// even for public bytes. An existing entry of any kind (file, directory or
// junction) is a collision; nothing existing is replaced or repaired.
func createNew(path string) (*os.File, error) {
	dir, leaf := filepath.Dir(path), filepath.Base(path)
	parent, err := fileaccess.OpenDirectory(dir)
	if os.IsNotExist(err) {
		if err := fileaccess.EnsurePrivatePath(dir); err != nil {
			return nil, err
		}
		parent, err = fileaccess.OpenDirectory(dir)
	}
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	file, err := fileaccess.OpenPrivateAt(parent, leaf, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil && !os.IsExist(err) {
		// NTFS reports an existing directory or junction as access denied to
		// a non-directory create. The create already failed; this only
		// classifies any existing entry as the collision it is.
		if _, statErr := os.Lstat(path); statErr == nil {
			return nil, &os.PathError{Op: "open", Path: path, Err: os.ErrExist}
		}
	}
	return file, err
}
