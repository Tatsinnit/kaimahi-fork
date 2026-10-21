//go:build windows

package oras

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kaimahi-agents/kaimahi/internal/kmx/fileaccess"
)

// lockLayoutPublication serializes local layout publishers that share a
// physical parent directory. Unlike the Unix per-destination path hash, the
// Windows key is the parent's volume serial and 128-bit file ID, so case,
// 8.3, extended-length and other spellings of one parent cannot split the
// lock; distinct destinations in one parent therefore also serialize. The
// sentinel is a private directory created atomically (FILE_CREATE) below the
// keyed parent handle and, as on
// Unix, a crashed publisher leaves it behind for manual inspection rather
// than being recovered automatically.
func lockLayoutPublication(ctx context.Context, destination string) (func() error, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	absolute, err := filepath.Abs(destination)
	if err != nil {
		return nil, err
	}
	parentPath := filepath.Dir(absolute)
	parent, err := fileaccess.OpenDirectory(parentPath)
	if err != nil {
		return nil, fmt.Errorf("acquire local layout writer exclusion: %w", err)
	}
	defer parent.Close()
	if err := fileaccess.CheckSafeDirectory(parent, true); err != nil {
		return nil, fmt.Errorf("acquire local layout writer exclusion: %s: %w", parentPath, err)
	}
	parentID, err := fileaccess.PhysicalIdentity(parent)
	if err != nil {
		return nil, fmt.Errorf("acquire local layout writer exclusion: %w", err)
	}
	name := layoutLockName(parentID)
	lock := filepath.Join(parentPath, name)
	// FILE_CREATE relative to the retained parent handle: atomically new,
	// never an existing (even private) entry, never resolved by path.
	sentinel, err := fileaccess.CreatePrivateDirectoryAt(parent, name)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("another local layout publisher may be active; inspect %s and remove it only after verifying no publisher is running", lock)
		}
		return nil, fmt.Errorf("acquire local layout writer exclusion: %w", err)
	}
	sentinelID, err := fileaccess.PhysicalIdentity(sentinel)
	// Windows cannot delete an open directory: close before any removal.
	if closeErr := sentinel.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(lock)
		return nil, fmt.Errorf("acquire local layout writer exclusion: %w", err)
	}
	return func() error { return releaseLayoutLock(parentPath, parentID, name, sentinelID) }, nil
}

func layoutLockName(parentID string) string {
	return fmt.Sprintf(".kmx-layout-%x.lock", sha256.Sum256([]byte("kmx-windows-layout-parent/v1\x00"+parentID)))
}

func checkSentinel(parent *os.File, name, want string) error {
	sentinel, err := fileaccess.OpenDirectoryAt(parent, name)
	if err != nil {
		return err
	}
	defer sentinel.Close()
	if err := fileaccess.CheckPrivate(sentinel, true); err != nil {
		return err
	}
	got, err := fileaccess.PhysicalIdentity(sentinel)
	if err != nil {
		return err
	}
	if got != want {
		return errors.New("writer exclusion sentinel is not the one this publisher created")
	}
	return nil
}

// releaseLayoutLock removes the sentinel only if it is still this
// publisher's directory under the same physical parent, closing every
// handle first because Windows cannot delete an open directory.
func releaseLayoutLock(parentPath, parentID, name, sentinelID string) error {
	parent, err := fileaccess.OpenDirectory(parentPath)
	if err != nil {
		return err
	}
	id, err := fileaccess.PhysicalIdentity(parent)
	if err == nil && id != parentID {
		err = errors.New("layout parent changed while publishing")
	}
	if err == nil {
		err = checkSentinel(parent, name, sentinelID)
	}
	if closeErr := parent.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("%s: %w", filepath.Join(parentPath, name), err)
	}
	return os.Remove(filepath.Join(parentPath, name))
}
