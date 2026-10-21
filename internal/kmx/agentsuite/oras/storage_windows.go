//go:build windows

package oras

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kaimahi-agents/kaimahi/internal/kmx/fileaccess"
	"golang.org/x/sys/windows"
	"oras.land/oras-go/v2/content/oci"
)

type layoutSourceStore = oci.ReadOnlyStore

// Windows inputs must never be initialized with an inherited token owner.
func openLayoutSource(ctx context.Context, path string) (*layoutSourceStore, error) {
	return oci.NewFromFS(ctx, os.DirFS(path))
}

// Windows stores, staged outputs and archives are private: KMX creates each
// root with an explicit current-user-only descriptor, ORAS children inherit
// it (after CheckDefaultPrivateOwner), and every object is checked through
// its own handle before KMX relies on or publishes the tree. Existing
// objects are never repaired.

// verifyPrivateTree refuses root unless it is a protected private directory
// whose every descendant is a private, non-reparse directory or regular file.
func verifyPrivateTree(root string) error {
	dir, err := fileaccess.OpenDirectory(root)
	if err != nil {
		return err
	}
	defer dir.Close()
	if err := fileaccess.CheckPrivate(dir, true); err != nil {
		return &os.PathError{Op: "check private", Path: root, Err: err}
	}
	return verifyPrivateChildren(dir)
}

func verifyPrivateChildren(dir *os.File) error {
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		var child *os.File
		if entry.IsDir() {
			child, err = fileaccess.OpenDirectoryAt(dir, entry.Name())
		} else {
			// Refuses reparse points, devices and anything not a regular file.
			child, err = fileaccess.OpenRegularAt(dir, entry.Name(), os.O_RDONLY)
		}
		if err != nil {
			return err
		}
		err = fileaccess.CheckPrivate(child, false)
		if err != nil {
			err = &os.PathError{Op: "check private", Path: child.Name(), Err: err}
		} else if entry.IsDir() {
			err = verifyPrivateChildren(child)
		}
		closeErr := child.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

// checkExistingLayout admits an existing layout for in-place update only if
// it already satisfies the private policy KMX applies to layouts it creates.
func checkExistingLayout(root string) error { return verifyPrivateTree(root) }

// finishOutputDirectory replaces the Unix chmod: Windows host access comes
// from the private descriptor, and portable modes stay archive metadata.
func finishOutputDirectory(stage string) error { return verifyPrivateTree(stage) }

// publishDirectory renames a staged directory into place without replacing
// any existing object. Callers have closed every handle inside stage.
func publishDirectory(stage, destination string) error { return RenameNoReplace(stage, destination) }

func createArchiveTemp() (*os.File, func(), error) {
	dir, err := fileaccess.PrivateTempDir("", "agentsuite-content-*")
	if err != nil {
		return nil, nil, err
	}
	remove := func() { os.RemoveAll(dir) }
	parent, err := fileaccess.OpenDirectory(dir)
	if err != nil {
		remove()
		return nil, nil, err
	}
	archive, err := fileaccess.OpenPrivateAt(parent, "content.tar.gz", os.O_RDWR|os.O_CREATE|os.O_EXCL)
	closeErr := parent.Close()
	if err == nil && closeErr != nil {
		archive.Close()
		err = closeErr
	}
	if err != nil {
		remove()
		return nil, nil, err
	}
	return archive, remove, nil
}

// RenameNoReplace renames from to to without replacing any existing object
// (Windows only). Callers must have closed every handle on or inside from:
// Go's os.Open and os.OpenRoot handles do not share delete access, so an
// open one blocks the rename.
//
// Native runs without retry saw intermittent ERROR_ACCESS_DENIED on these
// renames after KMX had closed its handles; Restart Manager named no
// holder, which does not rule out directory handles or filter drivers, so
// the cause is unproven. A bounded retry covers ERROR_ACCESS_DENIED and
// ERROR_SHARING_VIOLATION. Exclusivity is unchanged: an existing
// destination still fails at once.
func RenameNoReplace(from, to string) error {
	src, err := windows.UTF16PtrFromString(from)
	if err == nil {
		var dst *uint16
		if dst, err = windows.UTF16PtrFromString(to); err == nil {
			err = moveNoReplace(src, dst)
		}
	}
	if err != nil {
		return &os.LinkError{Op: "rename", Old: from, New: to, Err: err}
	}
	return nil
}

const renameRetryWindow = 2 * time.Second

func moveNoReplace(from, to *uint16) error {
	delay := time.Millisecond
	for start := time.Now(); ; {
		err := windows.MoveFileEx(from, to, 0)
		if err == nil || err != windows.ERROR_ACCESS_DENIED && err != windows.ERROR_SHARING_VIOLATION || time.Since(start) >= renameRetryWindow {
			return err
		}
		time.Sleep(delay)
		delay = min(2*delay, 100*time.Millisecond)
	}
}

// physicalPath returns the normalized volume-GUID path of path's nearest
// existing directory (through a strict handle walk that refuses reparse
// points), followed by any missing components. Case, 8.3 and
// extended-length spellings of one existing directory share a result.
// Anything that cannot be resolved is an error, never a lexical fallback.
func physicalPath(path string) ([]string, error) {
	cur, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	var missing []string
	for {
		dir, err := fileaccess.OpenDirectory(cur)
		if err == nil {
			final, err := finalPath(dir)
			dir.Close()
			if err != nil {
				return nil, fmt.Errorf("resolve %s: %w", cur, err)
			}
			parts := strings.FieldsFunc(final, func(r rune) bool { return r == '\\' })
			for i := len(missing) - 1; i >= 0; i-- {
				parts = append(parts, missing[i])
			}
			return parts, nil
		}
		parent := filepath.Dir(cur)
		if !errors.Is(err, os.ErrNotExist) || parent == cur {
			return nil, fmt.Errorf("resolve physical location of %s: %w", path, err)
		}
		missing = append(missing, filepath.Base(cur))
		cur = parent
	}
}

const fileNameNormalizedVolumeGUID = 0x1 // FILE_NAME_NORMALIZED | VOLUME_NAME_GUID

func finalPath(file *os.File) (string, error) {
	conn, err := file.SyscallConn()
	if err != nil {
		return "", err
	}
	buf := make([]uint16, windows.MAX_PATH)
	var final string
	var callErr error
	if err := conn.Control(func(fd uintptr) {
		for {
			n, err := windows.GetFinalPathNameByHandle(windows.Handle(fd), &buf[0], uint32(len(buf)), fileNameNormalizedVolumeGUID)
			if err != nil {
				callErr = err
				return
			}
			if n < uint32(len(buf)) {
				final = windows.UTF16ToString(buf[:n])
				return
			}
			buf = make([]uint16, n+1)
		}
	}); err != nil {
		return "", err
	}
	return final, callErr
}

// PhysicalPathWithin reports whether candidate is parent or lies below it
// (Windows only). Components compare case-insensitively, which may
// over-refuse inside case-sensitive directories but never lets an alias
// bypass a fence.
func PhysicalPathWithin(parent, candidate string) (bool, error) {
	p, err := physicalPath(parent)
	if err != nil {
		return false, err
	}
	c, err := physicalPath(candidate)
	if err != nil {
		return false, err
	}
	if len(c) < len(p) {
		return false, nil
	}
	for i := range p {
		if !strings.EqualFold(p[i], c[i]) {
			return false, nil
		}
	}
	return true, nil
}

func physicalWithin(parent, candidate string) (bool, error) {
	return PhysicalPathWithin(parent, candidate)
}
