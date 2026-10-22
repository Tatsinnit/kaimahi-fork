//go:build !windows

package fileaccess

import (
	"context"
	"os"
	"syscall"
)

// CheckPrivate requires a regular file or directory owned by the effective
// user with no group or other permission bits. It never changes permissions or
// ownership.
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
	if err := checkUnixPrivateInfo(info); err != nil {
		return wrapAccess("check privacy", err)
	}
	return nil
}

// CheckSafeDirectory requires a root- or effective-user-owned directory
// without group or other write permission. A sticky shared directory is
// tolerated as an ancestor, never as the immediate parent.
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
	if err := checkUnixSafeDirectoryInfo(info, immediate); err != nil {
		return wrapAccess("check ancestor", err)
	}
	return nil
}

func checkUnixPrivateInfo(info os.FileInfo) error {
	if !info.Mode().IsRegular() && !info.IsDir() {
		return unsafeCause("object is not a regular file or directory")
	}
	owner, err := unixOwner(info)
	if err != nil {
		return err
	}
	if owner != uint32(os.Geteuid()) {
		return unsafeCause("private object owner is not the current user")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return unsafeCause("object grants group or other access")
	}
	return nil
}

func checkUnixSafeDirectoryInfo(info os.FileInfo, immediate bool) error {
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return unsafeCause("object is not a directory")
	}
	owner, err := unixOwner(info)
	if err != nil {
		return err
	}
	if euid := uint32(os.Geteuid()); owner != 0 && owner != euid {
		return unsafeCause("directory owner is not trusted")
	}
	if info.Mode().Perm()&0o022 != 0 && (immediate || info.Mode()&os.ModeSticky == 0) {
		return unsafeCause("directory is writable by group or other")
	}
	return nil
}

func unixOwner(info os.FileInfo) (uint32, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return 0, unreadableCause("ownership metadata is unavailable")
	}
	return stat.Uid, nil
}
