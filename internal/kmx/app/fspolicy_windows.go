//go:build windows

package app

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kaimahi-agents/kaimahi/internal/kmx/fileaccess"
	"golang.org/x/sys/windows"
)

// Windows filesystem adapters. Native handles from internal/kmx/fileaccess are
// the authority: every directory is opened one component at a time without
// following any reparse point, every privacy decision is an owner/DACL check
// on an opened handle (never FileInfo's synthetic permission bits), and every
// private file or directory is created through fileaccess with an explicit
// current-user-only descriptor. A Go *os.Root is adopted only after its own
// handle is proven to be the same physical object as the checked native
// handle, and is then used for anchored metadata, link, rename and removal;
// it never creates, truncates or strictly reads private objects.

var errWindowsRootIdentity = errors.New("directory changed while it was being opened")

// splitWindowsLeaf separates the caller's spelling of path into its parent
// and final component without Win32 normalization, which would silently drop
// trailing dots and spaces before fileaccess could refuse them. The parent
// keeps its separator so a drive root stays drive-absolute.
func splitWindowsLeaf(path string) (string, string, bool) {
	if path == "" || strings.IndexByte(path, 0) >= 0 {
		return "", "", false
	}
	i := strings.LastIndexAny(path, `\/`)
	if i < 0 {
		return ".", path, true
	}
	leaf := path[i+1:]
	if leaf == "" || leaf == "." || leaf == ".." {
		return "", "", false
	}
	return path[:i+1], leaf, true
}

// suiteEvaluationReference distinguishes a local absolute drive prefix from
// registry/URL syntax without normalizing the path used for subsequent IO.
func suiteEvaluationReference(path string) bool {
	candidate := strings.TrimPrefix(path, `\\?\`)
	if len(candidate) >= 3 && candidate[1] == ':' &&
		(candidate[0] >= 'A' && candidate[0] <= 'Z' || candidate[0] >= 'a' && candidate[0] <= 'z') &&
		(candidate[2] == '\\' || candidate[2] == '/') {
		path = candidate[2:]
	}
	return strings.ContainsAny(path, ":@") || strings.HasPrefix(path, "//")
}

func sameOpened(file *os.File, info os.FileInfo) bool {
	if info == nil {
		return false
	}
	opened, err := file.Stat()
	return err == nil && os.SameFile(opened, info)
}

// openSafeDirectory opens the local directory named by path and applies the
// public ancestor policy to the volume root and every component, with the
// immediate rule on the final directory. fileaccess.OpenDirectory parses the
// caller's spelling strictly; the checked walk must reach the same object.
func openSafeDirectory(path string) (*os.File, error) {
	target, err := fileaccess.OpenDirectory(path)
	if err != nil {
		return nil, err
	}
	defer target.Close()
	want, err := fileaccess.PhysicalIdentity(target)
	if err != nil {
		return nil, err
	}
	// OpenDirectory names its result drive-absolute: X:\a\b.
	name := target.Name()
	if len(name) < 3 || name[1:3] != `:\` {
		return nil, errors.New("unexpected local directory name")
	}
	var parts []string
	if rest := name[3:]; rest != "" {
		parts = strings.Split(rest, `\`)
	}
	dir, err := fileaccess.OpenDirectory(name[:3])
	if err != nil {
		return nil, err
	}
	for i := 0; ; i++ {
		if err := fileaccess.CheckSafeDirectory(dir, i == len(parts)); err != nil {
			dir.Close()
			return nil, err
		}
		if i == len(parts) {
			break
		}
		next, err := fileaccess.OpenDirectoryAt(dir, parts[i])
		dir.Close()
		if err != nil {
			return nil, err
		}
		dir = next
	}
	if got, err := fileaccess.PhysicalIdentity(dir); err != nil || got != want {
		dir.Close()
		return nil, errWindowsRootIdentity
	}
	return dir, nil
}

// adoptVerifiedRoot opens a Go Root for native's directory and refuses it
// unless the Root's own handle is the same physical object, before any I/O
// through the Root. The returned FileInfo comes from that handle.
func adoptVerifiedRoot(native *os.File) (*os.Root, os.FileInfo, error) {
	want, err := fileaccess.PhysicalIdentity(native)
	if err != nil {
		return nil, nil, err
	}
	root, err := os.OpenRoot(native.Name())
	if err != nil {
		return nil, nil, err
	}
	dir, err := root.Open(".")
	if err != nil {
		root.Close()
		return nil, nil, err
	}
	got, idErr := fileaccess.PhysicalIdentity(dir)
	info, statErr := dir.Stat()
	closeErr := dir.Close()
	if err := errors.Join(idErr, statErr, closeErr); err != nil || got != want {
		root.Close()
		return nil, nil, errWindowsRootIdentity
	}
	return root, info, nil
}

// openSessionReferenceDirectory opens the parent of path under the public
// ancestor policy (the immediate parent must not admit untrusted writes) and
// returns an identity-verified Root for it. The final component must be a
// valid local name that either names a regular file or does not exist, so an
// alternate data stream, trailing dot or reserved device name never reaches
// a Root operation.
func openSessionReferenceDirectory(path string) (*os.Root, string, os.FileInfo, error) {
	parentPath, leaf, ok := splitWindowsLeaf(path)
	if !ok {
		return nil, "", nil, errSessionReferenceDirectory
	}
	parent, err := openSafeDirectory(parentPath)
	if err != nil {
		return nil, "", nil, errSessionReferenceDirectory
	}
	defer parent.Close()
	probe, err := fileaccess.OpenRegularAt(parent, leaf, os.O_RDONLY)
	if err == nil {
		err = probe.Close()
	} else if os.IsNotExist(err) {
		err = nil
	}
	if err != nil {
		return nil, "", nil, errSessionReferenceDirectory
	}
	root, info, err := adoptVerifiedRoot(parent)
	if err != nil {
		return nil, "", nil, errSessionReferenceDirectory
	}
	return root, leaf, info, nil
}

// ensureSuitePassDirectory creates or checks path as a protected
// current-user-only directory. Missing components are created private;
// existing ancestors must satisfy the public ancestor policy. Unlike Unix,
// the state root itself must be private here: config.StateDir already
// requires that on Windows, so private=false adds no weaker case.
func ensureSuitePassDirectory(path string, _ bool) error {
	if fileaccess.EnsurePrivatePath(path) != nil {
		return errSuitePassStore
	}
	return nil
}

// suiteReceiptInside reports whether filename is tree or lies below it,
// comparing physical locations: each path's nearest existing ancestor is
// resolved through its opened handle to the normalized final path (long
// names, stored case, links and mount points resolved), then compared
// component-wise case-insensitively. Case, 8.3, extended-length and junction
// aliases therefore cannot carry an output past the fence; a case-only
// difference in a case-sensitive directory is refused rather than admitted.
// Any failure reports inside, so the caller refuses.
func suiteReceiptInside(filename, tree string) bool {
	if tree == "" {
		return true
	}
	file, err := windowsPhysicalPath(filename)
	if err != nil {
		return true
	}
	root, err := windowsPhysicalPath(tree)
	if err != nil {
		return true
	}
	if len(file) < len(root) {
		return false
	}
	for i := range root {
		if !strings.EqualFold(file[i], root[i]) {
			return false
		}
	}
	return true
}

// windowsPhysicalPath returns the components of path's physical location.
func windowsPhysicalPath(path string) ([]string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	var tail []string
	current := absolute
	for {
		final, err := finalPathName(current)
		if err == nil {
			parts := strings.Split(strings.TrimSuffix(final, `\`), `\`)
			for i := len(tail) - 1; i >= 0; i-- {
				parts = append(parts, tail[i])
			}
			return parts, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil, err
		}
		tail = append(tail, filepath.Base(current))
		current = parent
	}
}

// finalPathNormalizedDOS is FILE_NAME_NORMALIZED|VOLUME_NAME_DOS (both zero).
const finalPathNormalizedDOS = 0

func finalPathName(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetFinalPathNameByHandle(windows.Handle(file.Fd()), &buf[0], uint32(len(buf)), finalPathNormalizedDOS)
	if err != nil {
		return "", err
	}
	if n == 0 || n >= uint32(len(buf)) {
		return "", errors.New("final path name unavailable")
	}
	final := windows.UTF16ToString(buf[:n])
	if rest, ok := strings.CutPrefix(final, `\\?\UNC\`); ok {
		return `\\` + rest, nil
	}
	return strings.TrimPrefix(final, `\\?\`), nil
}

// windowsWorkspaceDomain separates native Windows workspace identities from
// the Unix canonical-path hash; there is no older Windows state to migrate.
const windowsWorkspaceDomain = "kmx/windows-workspace-identity/v1\x00"

// suitePassWorkspaceIdentity keys managed evidence by the workspace
// directory's physical identity (volume serial and 128-bit file ID), so
// case, 8.3 and extended-length spellings of one workspace share a partition
// and record Workspace value, without any lowercased path key.
func suitePassWorkspaceIdentity(workspaceRoot string) (string, error) {
	dir, err := fileaccess.OpenDirectory(workspaceRoot)
	if err != nil {
		return "", err
	}
	id, idErr := fileaccess.PhysicalIdentity(dir)
	if err := errors.Join(idErr, dir.Close()); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256([]byte(windowsWorkspaceDomain+id))), nil
}

func openKagentFile(dir *os.File, name string) (*os.File, error) {
	if name == "." || name == ".." || filepath.Base(name) != name {
		return nil, fmt.Errorf("Kagent file name must be a single path component")
	}
	file, err := fileaccess.OpenRegularAt(dir, name, os.O_RDONLY)
	if err != nil {
		return nil, fmt.Errorf("open Kagent bounded regular file, not a link: %w", err)
	}
	return file, nil
}

// openRunPromptFile opens a read-only input strictly: its directory is walked
// without following any reparse point and the final regular file is opened
// as itself. This is stricter than the Unix final-component no-follow.
func openRunPromptFile(path string) (*os.File, error) {
	parent, leaf, ok := splitWindowsLeaf(path)
	if !ok {
		return nil, &os.PathError{Op: "open", Path: path, Err: os.ErrInvalid}
	}
	dir, err := fileaccess.OpenDirectory(parent)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	return fileaccess.OpenRegularAt(dir, leaf, os.O_RDONLY)
}

func openSuiteEvaluationVerifyDirectory(dir string) (*os.File, error) {
	return fileaccess.OpenDirectory(dir)
}

// rootDirectory is the read-only handle of a verified Root, used only as an
// anchor for fileaccess's single-component opens and creations.
func rootDirectory(root *os.Root) (*os.File, error) { return root.Open(".") }

// privateDirOK checks the directory held by root (the object info describes)
// under the private owner/DACL policy.
func privateDirOK(root *os.Root, info os.FileInfo) bool {
	dir, err := rootDirectory(root)
	if err != nil {
		return false
	}
	defer dir.Close()
	return sameOpened(dir, info) && fileaccess.CheckPrivate(dir, false) == nil
}

func privateFileOK(file *os.File, info os.FileInfo) bool {
	return sameOpened(file, info) && fileaccess.CheckPrivate(file, false) == nil
}

func privateEntryOK(root *os.Root, name string, info os.FileInfo) bool {
	dir, err := rootDirectory(root)
	if err != nil {
		return false
	}
	defer dir.Close()
	file, err := fileaccess.OpenRegularAt(dir, name, os.O_RDONLY)
	if err != nil {
		return false
	}
	defer file.Close()
	return privateFileOK(file, info)
}

func privateEntryDirOK(root *os.Root, name string, info os.FileInfo) bool {
	dir, err := rootDirectory(root)
	if err != nil {
		return false
	}
	defer dir.Close()
	child, err := fileaccess.OpenDirectoryAt(dir, name)
	if err != nil {
		return false
	}
	defer child.Close()
	return privateFileOK(child, info)
}

func privateHandleOK(file *os.File) bool { return fileaccess.CheckPrivate(file, false) == nil }

// absentLeaf reports a valid local name with nothing behind it. An invalid
// name, a directory, a reparse point or any regular file is not absent.
func absentLeaf(root *os.Root, name string) bool {
	dir, err := rootDirectory(root)
	if err != nil {
		return false
	}
	defer dir.Close()
	file, err := fileaccess.OpenRegularAt(dir, name, os.O_RDONLY)
	if err == nil {
		file.Close()
		return false
	}
	return os.IsNotExist(err)
}

func createPrivateFile(root *os.Root, name string, flags int) (*os.File, error) {
	dir, err := rootDirectory(root)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	return fileaccess.OpenPrivateAt(dir, name, flags)
}

// mkdirPrivate reserves a new private directory atomically. A check followed
// by create-or-open would let two concurrent callers adopt one reservation.
func mkdirPrivate(root *os.Root, name string) error {
	dir, err := rootDirectory(root)
	if err != nil {
		return err
	}
	defer dir.Close()
	child, err := fileaccess.CreatePrivateDirectoryAt(dir, name)
	if err != nil {
		return err
	}
	return child.Close()
}

// openChildRoot opens a Root for a child directory only after a native
// no-reparse open of the same name proves both handles are one object.
func openChildRoot(root *os.Root, name string) (*os.Root, error) {
	dir, err := rootDirectory(root)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	native, err := fileaccess.OpenDirectoryAt(dir, name)
	if err != nil {
		return nil, err
	}
	defer native.Close()
	want, err := fileaccess.PhysicalIdentity(native)
	if err != nil {
		return nil, err
	}
	child, err := root.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	opened, err := child.Open(".")
	if err != nil {
		child.Close()
		return nil, err
	}
	got, idErr := fileaccess.PhysicalIdentity(opened)
	if err := errors.Join(idErr, opened.Close()); err != nil || got != want {
		child.Close()
		return nil, errWindowsRootIdentity
	}
	return child, nil
}

func openRootEntry(root *os.Root, name string) (*os.File, error) {
	dir, err := rootDirectory(root)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	return fileaccess.OpenRegularAt(dir, name, os.O_RDONLY)
}

// openSuitePassLock opens or creates the private lock file; an existing one
// must already be private. Lock data is never read through another handle.
func openSuitePassLock(root *os.Root) (*os.File, error) {
	dir, err := rootDirectory(root)
	if err != nil {
		return nil, errSuitePassStore
	}
	defer dir.Close()
	lock, err := fileaccess.OpenPrivateAt(dir, "lock", os.O_RDWR|os.O_CREATE)
	if err != nil {
		return nil, errSuitePassStore
	}
	return lock, nil
}

func openReleaseLiftLock(dir *os.File) (*os.File, error) {
	return fileaccess.OpenPrivateAt(dir, "lock", os.O_RDWR|os.O_CREATE)
}

// tryLockFile takes the exclusive LockFileEx lock, released when the handle
// is closed or the process exits.
func tryLockFile(file *os.File) error { return fileaccess.TryLock(file) }

// readPrivateSuiteSessionsHost is readSuiteKagentBindings with the private
// directory and file checks made on opened handles: the file's owner/DACL is
// checked before any byte is read and again afterwards, and the parent is
// rechecked once the read completes.
func readPrivateSuiteSessionsHost(path string) ([]byte, os.FileInfo, os.FileInfo, error) {
	root, name, parent, err := openSessionReferenceDirectory(path)
	if err != nil {
		return nil, nil, nil, errSuiteSessionsHost
	}
	defer root.Close()
	if !privateDirOK(root, parent) {
		return nil, nil, nil, errSuiteSessionsHost
	}
	before, err := root.Lstat(name)
	if err != nil || !before.Mode().IsRegular() {
		return nil, nil, nil, errSuiteSessionsHost
	}
	directory, err := rootDirectory(root)
	if err != nil {
		return nil, nil, nil, errSuiteSessionsHost
	}
	defer directory.Close()
	file, err := openKagentFile(directory, name)
	if err != nil {
		return nil, nil, nil, errSuiteSessionsHost
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !os.SameFile(before, info) {
		return nil, nil, nil, errSuiteSessionsHost
	}
	raw, err := readKagentOpenedFile(file, info, true)
	current, e := root.Lstat(name)
	if err != nil || e != nil || !os.SameFile(info, current) || !privateDirOK(root, parent) {
		return nil, nil, nil, errSuiteSessionsHost
	}
	return raw, parent, info, nil
}
