//go:build !windows

package app

import (
	"crypto/sha256"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// Unix failure-store adapters. Each body is the expression or block the
// common store used before Windows support, moved here unchanged; the root,
// file and name arguments carry only the Windows handle seam.

func suiteFailureOwned(info os.FileInfo) bool {
	if info == nil {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}
func safeSuiteFailureDirectory(info os.FileInfo) bool {
	return suiteFailureOwned(info) && info.IsDir() && info.Mode().Perm() == 0700
}
func safeSuiteFailureFile(info os.FileInfo) bool {
	if !suiteFailureOwned(info) || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > maxSuiteFailureRecordBytes {
		return false
	}
	return info.Sys().(*syscall.Stat_t).Nlink == 1
}

func suiteFailureRootDirOK(_ *os.Root, info os.FileInfo) bool { return safeSuiteFailureDirectory(info) }

func suiteFailureFileOK(_ *os.File, info os.FileInfo) bool { return safeSuiteFailureFile(info) }

func suiteFailureEntryOK(_ *os.Root, _ string, info os.FileInfo) bool {
	return safeSuiteFailureFile(info)
}

// suiteFailureWorkspaceKey is the existing canonical-path hash.
func suiteFailureWorkspaceKey(workspaceRoot string) (string, error) {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(workspaceRoot))), nil
}

func checkSuiteFailureDirectory(p string, create bool) error {
	info, e := os.Lstat(p)
	if os.IsNotExist(e) && !create {
		return errSuiteFailureMissing
	}
	if e != nil || !safeSuiteFailureDirectory(info) {
		return errSuiteFailureStore
	}
	return nil
}

func openSuiteFailureLock(root *os.Root, create bool) (*os.File, error) {
	dir, e := root.Open(".")
	if e != nil {
		return nil, errSuiteFailureStore
	}
	flags := unix.O_RDWR | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
	if create {
		flags |= unix.O_CREAT
	}
	fd, e := unix.Openat(int(dir.Fd()), "lock", flags, 0600)
	closeErr := dir.Close()
	if e != nil || closeErr != nil {
		if e == nil {
			_ = unix.Close(fd)
		}
		return nil, errSuiteFailureStore
	}
	return os.NewFile(uintptr(fd), "lock"), nil
}

// Unix publication is the existing atomic rename of the private stage.
func suiteFailurePublish(root *os.Root) func(string, string) error { return root.Rename }

// The rename consumed the stage; nothing remains to retire.
func retireSuiteFailureStage(*suiteFailureStore, string, os.FileInfo) error { return nil }
