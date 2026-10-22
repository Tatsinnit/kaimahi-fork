//go:build !windows

package fileaccess

import (
	"context"
	"os"
)

// CheckPrivate requires a regular file or directory with no group or other
// permission bits. It never changes permissions or ownership.
func CheckPrivate(ctx context.Context, object Object, _ bool) error {
	if err := checkContext(ctx); err != nil {
		return wrapAccess("check privacy", err)
	}
	file := rawObject(object)
	if file == nil {
		return wrapAccess("check privacy", unsafeCause("file handle is absent"))
	}
	info, err := file.Stat()
	if err != nil {
		return wrapAccess("check privacy", err)
	}
	if err := checkContext(ctx); err != nil {
		return wrapAccess("check privacy", err)
	}
	if !info.Mode().IsRegular() && !info.IsDir() {
		return wrapAccess("check privacy", unsafeCause("object is not a regular file or directory"))
	}
	if info.Mode().Perm()&0o077 != 0 {
		return wrapAccess("check privacy", unsafeCause("object grants group or other access"))
	}
	return nil
}

// CheckSafeDirectory requires a directory without group or other write
// permission. A sticky shared directory is tolerated as an ancestor, never as
// the immediate parent.
func CheckSafeDirectory(ctx context.Context, directory *Directory, immediate bool) error {
	if err := checkContext(ctx); err != nil {
		return wrapAccess("check ancestor", err)
	}
	file := rawObject(directory)
	if file == nil {
		return wrapAccess("check ancestor", unsafeCause("directory handle is absent"))
	}
	info, err := file.Stat()
	if err != nil {
		return wrapAccess("check ancestor", err)
	}
	if err := checkContext(ctx); err != nil {
		return wrapAccess("check ancestor", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return wrapAccess("check ancestor", unsafeCause("object is not a directory"))
	}
	if info.Mode().Perm()&0o022 != 0 && (immediate || info.Mode()&os.ModeSticky == 0) {
		return wrapAccess("check ancestor", unsafeCause("directory is writable by group or other"))
	}
	return nil
}
