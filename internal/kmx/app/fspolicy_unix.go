//go:build !windows

package app

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// Unix filesystem adapters. Each body is the expression or call its caller
// used before Windows support, moved here unchanged so the common algorithms
// can take a Windows handle-based decision at the same seam. None of these
// strengthen or relax Unix behavior.

// suiteEvaluationReference retains the original Unix reference/URL refusal.
func suiteEvaluationReference(path string) bool {
	return strings.ContainsAny(path, ":@") || strings.HasPrefix(path, "//")
}

// openSessionReferenceDirectory walks from the volume root one component at a
// time. Each handle is anchored before descending; symlinks are never accepted,
// even if they point inside the same tree. Sticky shared ancestors such as /tmp
// are allowed, but the immediate parent must not be group/other-writable.
func openSessionReferenceDirectory(path string) (*os.Root, string, os.FileInfo, error) {
	if path == "" || strings.IndexByte(path, 0) >= 0 {
		return nil, "", nil, errSessionReferenceDirectory
	}
	absolute, err := filepath.Abs(path)
	if err != nil || filepath.Base(absolute) == "." || filepath.Base(absolute) == string(filepath.Separator) {
		return nil, "", nil, errSessionReferenceDirectory
	}
	parent := filepath.Dir(absolute)
	volume := filepath.VolumeName(parent) + string(filepath.Separator)
	root, err := os.OpenRoot(volume)
	if err != nil {
		return nil, "", nil, errSessionReferenceDirectory
	}
	parts := strings.Split(strings.TrimPrefix(parent, volume), string(filepath.Separator))
	for _, part := range parts {
		if part == "" {
			continue
		}
		info, err := root.Lstat(part)
		if err != nil || !safeSessionReferenceDirectory(info, false) {
			root.Close()
			return nil, "", nil, errSessionReferenceDirectory
		}
		next, err := root.OpenRoot(part)
		if err != nil {
			root.Close()
			return nil, "", nil, errSessionReferenceDirectory
		}
		opened, err := next.Stat(".")
		current, currentErr := root.Lstat(part)
		root.Close()
		if err != nil || currentErr != nil || !safeSessionReferenceDirectory(current, false) || !os.SameFile(info, opened) || !os.SameFile(info, current) {
			next.Close()
			return nil, "", nil, errSessionReferenceDirectory
		}
		root = next
	}
	info, err := root.Stat(".")
	if err != nil || !safeSessionReferenceDirectory(info, true) {
		root.Close()
		return nil, "", nil, errSessionReferenceDirectory
	}
	return root, filepath.Base(absolute), info, nil
}

func safeSessionReferenceDirectory(info os.FileInfo, immediate bool) bool {
	return info != nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 &&
		(info.Mode().Perm()&0022 == 0 || !immediate && info.Mode()&os.ModeSticky != 0)
}

// Creation walks anchored directories without following links or changing
// existing permissions. Only managed children must be private; existing KMX
// settings directories can retain their normal, non-writable-to-others modes.
func ensureSuitePassDirectory(path string, private bool) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return errSuitePassStore
	}
	volume := filepath.VolumeName(absolute) + string(filepath.Separator)
	root, err := os.OpenRoot(volume)
	if err != nil {
		return errSuitePassStore
	}
	for _, part := range strings.Split(strings.TrimPrefix(absolute, volume), string(filepath.Separator)) {
		if part == "" {
			continue
		}
		info, err := root.Lstat(part)
		if os.IsNotExist(err) {
			if err := root.Mkdir(part, 0700); err != nil && !os.IsExist(err) {
				root.Close()
				return errSuitePassStore
			}
			info, err = root.Lstat(part)
		}
		if err != nil || !safeSessionReferenceDirectory(info, false) {
			root.Close()
			return errSuitePassStore
		}
		next, err := root.OpenRoot(part)
		if err != nil {
			root.Close()
			return errSuitePassStore
		}
		opened, openErr := next.Stat(".")
		current, currentErr := root.Lstat(part)
		closeErr := root.Close()
		if openErr != nil || currentErr != nil || closeErr != nil || !os.SameFile(info, opened) || !os.SameFile(info, current) {
			next.Close()
			return errSuitePassStore
		}
		root = next
	}
	info, err := root.Stat(".")
	closeErr := root.Close()
	if err != nil || closeErr != nil || !safeSessionReferenceDirectory(info, true) || private && info.Mode().Perm()&0077 != 0 {
		return errSuitePassStore
	}
	return nil
}

func suiteReceiptInside(filename, tree string) bool {
	absolute, err := filepath.Abs(filename)
	if err != nil || tree == "" {
		return true
	}
	root, err := filepath.Abs(tree)
	if err != nil {
		return true
	}
	relative, err := filepath.Rel(root, absolute)
	return err != nil || relative == "." || relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

// suitePassWorkspaceIdentity is the existing canonical-path hash; managed
// partitions and record Workspace fields keep exactly this value.
func suitePassWorkspaceIdentity(workspaceRoot string) (string, error) {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(workspaceRoot))), nil
}

// Root.OpenFile follows even in-root symlinks. Use single-component openat
// calls instead, retaining each checked directory descriptor for the next step.
// O_DIRECTORY and O_NONBLOCK prevent a substituted FIFO from blocking an open.

func openKagentFile(dir *os.File, name string) (*os.File, error) {
	if name == "." || name == ".." || filepath.Base(name) != name {
		return nil, fmt.Errorf("Kagent file name must be a single path component")
	}
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open Kagent bounded regular file, not a link: %w", err)
	}
	return os.NewFile(uintptr(fd), name), nil
}

// openRunPromptFile opens path without following a final symbolic link.
func openRunPromptFile(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

// openSuiteEvaluationVerifyDirectory opens a public input's parent as a
// directory without blocking on a FIFO.
func openSuiteEvaluationVerifyDirectory(dir string) (*os.File, error) {
	return os.OpenFile(dir, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
}

// Unix privacy is the existing mode rule on the FileInfo the caller already
// captured; the root, file and name arguments carry the Windows handle seam.

func privateDirOK(_ *os.Root, info os.FileInfo) bool { return info.Mode().Perm()&0077 == 0 }

func privateFileOK(_ *os.File, info os.FileInfo) bool { return info.Mode().Perm()&0077 == 0 }

func privateEntryOK(_ *os.Root, _ string, info os.FileInfo) bool {
	return info.Mode().Perm()&0077 == 0
}

func privateEntryDirOK(_ *os.Root, _ string, info os.FileInfo) bool {
	return info.Mode().Perm()&0077 == 0
}

// privateHandleOK marks Windows-only handle rechecks where the Unix caller's
// existing FileInfo checks remain its only authority.
func privateHandleOK(*os.File) bool { return true }

func absentLeaf(root *os.Root, name string) bool {
	_, err := root.Lstat(name)
	return os.IsNotExist(err)
}

func createPrivateFile(root *os.Root, name string, flags int) (*os.File, error) {
	return root.OpenFile(name, flags, 0600)
}

func mkdirPrivate(root *os.Root, name string) error { return root.Mkdir(name, 0700) }

func openChildRoot(root *os.Root, name string) (*os.Root, error) { return root.OpenRoot(name) }

func openRootEntry(root *os.Root, name string) (*os.File, error) { return root.Open(name) }

func openSuitePassLock(root *os.Root) (*os.File, error) {
	lock, err := root.OpenFile("lock", os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if os.IsExist(err) {
		directory, e := root.Open(".")
		if e != nil {
			return nil, errSuitePassStore
		}
		fd, e := unix.Openat(int(directory.Fd()), "lock", unix.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		closeErr := directory.Close()
		if e != nil || closeErr != nil {
			if e == nil {
				unix.Close(fd)
			}
			return nil, errSuitePassStore
		}
		lock = os.NewFile(uintptr(fd), "lock")
		err = nil
	}
	if err != nil {
		return nil, errSuitePassStore
	}
	return lock, nil
}

func openReleaseLiftLock(dir *os.File) (*os.File, error) {
	fd, err := unix.Openat(int(dir.Fd()), "lock", unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "lock"), nil
}

func tryLockFile(file *os.File) error {
	return unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
}

func readPrivateSuiteSessionsHost(path string) ([]byte, os.FileInfo, os.FileInfo, error) {
	raw, parent, file, err := readSuiteKagentBindings(path)
	if err != nil || parent.Mode().Perm()&0077 != 0 || file.Mode().Perm()&0077 != 0 {
		return nil, nil, nil, errSuiteSessionsHost
	}
	return raw, parent, file, nil
}
