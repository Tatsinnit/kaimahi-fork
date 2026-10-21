//go:build windows

package app

import (
	"errors"
	"io/fs"
	"os"

	"github.com/kaimahi-agents/kaimahi/internal/kmx/fileaccess"
	"golang.org/x/sys/windows"
)

// Windows failure-store adapters. Privacy is decided on opened native handles
// (owner and DACL through fileaccess, never FileInfo's synthetic mode bits),
// every private object is created by fileaccess with the current-user-only
// descriptor before any byte is written, and publication is an exclusive
// hard link of the flushed stage rather than Go's replacing rename.

// suiteFailureSingleLink preserves the Unix Nlink == 1 refusal: a record
// reachable under a second name could be changed or retained elsewhere.
func suiteFailureSingleLink(file *os.File) bool {
	conn, err := file.SyscallConn()
	if err != nil {
		return false
	}
	var info windows.ByHandleFileInformation
	var infoErr error
	if conn.Control(func(fd uintptr) { infoErr = windows.GetFileInformationByHandle(windows.Handle(fd), &info) }) != nil || infoErr != nil {
		return false
	}
	return info.NumberOfLinks == 1
}

func suiteFailureRootDirOK(root *os.Root, info os.FileInfo) bool {
	return info != nil && info.IsDir() && privateDirOK(root, info)
}

func suiteFailureFileOK(file *os.File, info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() && info.Size() <= maxSuiteFailureRecordBytes &&
		privateFileOK(file, info) && suiteFailureSingleLink(file)
}

// suiteFailureEntryOK opens name without following any reparse point and
// decides on that handle, which must be the object info describes.
func suiteFailureEntryOK(root *os.Root, name string, info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() {
		return false
	}
	file, err := openRootEntry(root, name)
	if err != nil {
		return false
	}
	defer file.Close()
	return suiteFailureFileOK(file, info)
}

// suiteFailureWorkspaceKey reuses the managed-evidence physical identity, so
// case, 8.3 and extended-length spellings share one partition and lock.
func suiteFailureWorkspaceKey(workspaceRoot string) (string, error) {
	return suitePassWorkspaceIdentity(workspaceRoot)
}

func checkSuiteFailureDirectory(p string, create bool) error {
	dir, err := fileaccess.OpenDirectory(p)
	if errors.Is(err, fs.ErrNotExist) && !create {
		return errSuiteFailureMissing
	}
	if err != nil {
		return errSuiteFailureStore
	}
	if errors.Join(fileaccess.CheckPrivate(dir, false), dir.Close()) != nil {
		return errSuiteFailureStore
	}
	return nil
}

// openSuiteFailureLock creates the lock with the private descriptor or opens
// an existing one only after its handle passes the private check.
func openSuiteFailureLock(root *os.Root, create bool) (*os.File, error) {
	dir, err := rootDirectory(root)
	if err != nil {
		return nil, errSuiteFailureStore
	}
	flags := os.O_RDWR
	if create {
		flags |= os.O_CREATE
	}
	lock, err := fileaccess.OpenPrivateAt(dir, "lock", flags)
	closeErr := dir.Close()
	if err != nil || closeErr != nil {
		if err == nil {
			_ = lock.Close()
		}
		return nil, errSuiteFailureStore
	}
	return lock, nil
}

// Windows publication links the flushed stage under its final name, which
// fails if that name exists; a replacing rename is never used.
func suiteFailurePublish(root *os.Root) func(string, string) error { return root.Link }

// retireSuiteFailureStage removes this operation's own stage after the link.
// A failure here leaves the complete record visible with a second name, so
// the caller reports publication uncertainty and the store then refuses.
func retireSuiteFailureStage(s *suiteFailureStore, stage string, info os.FileInfo) error {
	current, err := s.root.Lstat(stage)
	if err != nil || !os.SameFile(info, current) {
		return errSuiteFailureStore
	}
	return s.root.Remove(stage)
}
