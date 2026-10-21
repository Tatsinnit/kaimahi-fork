//go:build windows

package toolchain

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/kaimahi-agents/kaimahi/internal/kmx/fileaccess"
)

// On Windows kmx keeps the executables it runs only under directories it
// has verified as private to the current user (owner-only DACL, no reparse
// traversal), and every existing entry is checked on its opened handle before
// a byte of it is trusted. A check that fails is FATAL: an unsafe object is
// reported, never repaired, adopted or silently re-fetched over.
//
// The plain command name is <name>.exe holding a private COPY of the
// verified bytes, not a symlink — creating one needs a privilege an ordinary
// user does not have — and successful pin changes replace it atomically.
// Publication failure returns no runnable result and preserves the old alias.

// prepareManagedDir creates the directory as a private root, or verifies an
// existing one, before anything in it is read or written.
func prepareManagedDir(dir string) error {
	return fileaccess.EnsurePrivatePath(dir)
}

// openManagedDir opens a managed directory without following reparse points
// and re-checks its privacy on the handle that will anchor the operation.
func openManagedDir(dir string) (*os.File, error) {
	handle, err := fileaccess.OpenDirectory(dir)
	if err != nil {
		return nil, err
	}
	if err := fileaccess.CheckPrivate(handle, true); err != nil {
		handle.Close()
		return nil, err
	}
	return handle, nil
}

// readManagedFile reads a managed file whose privacy is checked on the
// opened handle before its bytes are read. Only absence is a miss; anything
// else — a broad ACL, a reparse point, an unreadable entry — is an error.
func readManagedFile(path string) ([]byte, bool, error) {
	dir, err := openManagedDir(filepath.Dir(path))
	if err != nil {
		return nil, false, err
	}
	defer dir.Close()
	f, err := fileaccess.OpenPrivateAt(dir, filepath.Base(path), os.O_RDONLY)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	// Bounded: an oversized entry reads as a digest mismatch, not as an
	// unbounded allocation.
	data, err := io.ReadAll(io.LimitReader(f, maxBinarySize+1))
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}

// discardCacheEntry removes an entry that failed re-verification. Unlike
// Unix, a removal that fails is fatal: the entry is not left to be found
// again as though it were the one just fetched.
func discardCacheEntry(path string) error {
	var errs []error
	for _, name := range []string{path, path + ".sha256"} {
		if err := os.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func install(path string, binary []byte) error {
	return writePrivateAtomically(filepath.Dir(path), filepath.Base(path), binary)
}

func writeDigest(path string, line []byte) error {
	return writePrivateAtomically(filepath.Dir(path), filepath.Base(path), line)
}

// publishAlias publishes linkDir\<name>.exe as a private copy of the
// verified bytes, then confirms the published file is private and holds
// exactly those bytes.
func publishAlias(linkDir, name, _ string, binary []byte) (string, error) {
	base := aliasFileName(name, "windows")
	link := filepath.Join(linkDir, base)
	existing, found, err := readManagedFile(link)
	if err != nil {
		return "", err
	}
	// A running Windows image cannot be replaced. Reuse only an alias whose
	// opened handle passed privacy checks and whose bytes match this pin.
	if found && bytes.Equal(existing, binary) {
		return link, nil
	}
	if err := writePrivateAtomically(linkDir, base, binary); err != nil {
		// Only the failed operation's stage belongs to us. Removing the
		// published name could delete a concurrent process's valid alias.
		return "", err
	}
	published, found, err := readManagedFile(link)
	if err != nil {
		return "", err
	}
	if !found || !bytes.Equal(published, binary) {
		return "", fmt.Errorf("the published %s does not hold the verified bytes", link)
	}
	return link, nil
}

// writePrivateAtomically stages data in a new private file created with an
// owner-only security descriptor — checked before any byte is written —
// then renames it over dir\base. A crash leaves at worst a stage file, never
// a truncated binary under the real name. Every handle on the stage is
// closed before the rename, which Windows requires to replace it.
func writePrivateAtomically(dir, base string, data []byte) (err error) {
	parent, err := openManagedDir(dir)
	if err != nil {
		return err
	}
	defer parent.Close()
	stage := base + ".partial-" + rand.Text()
	f, err := fileaccess.OpenPrivateAt(parent, stage, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		return err
	}
	stagePath := filepath.Join(dir, stage)
	defer func() {
		if err != nil {
			if rmErr := os.Remove(stagePath); rmErr != nil && !errors.Is(rmErr, fs.ErrNotExist) {
				err = errors.Join(err, rmErr)
			}
		}
	}()
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(stagePath, filepath.Join(dir, base))
}
