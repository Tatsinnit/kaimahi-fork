//go:build windows

package fileaccess

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/windows"
)

// Private objects are created with an explicit descriptor naming the current
// user as owner and granting only that user, in a protected DACL, so neither
// the token's default owner nor inheritable parent grants apply. Existing
// objects are checked, never repaired or adopted.

func privateDescriptor(dir bool) (*windows.SECURITY_DESCRIPTOR, error) {
	user, err := currentUser()
	if err != nil {
		return nil, err
	}
	inherit := ""
	if dir {
		inherit = "OICI"
	}
	sid := user.String()
	return windows.SecurityDescriptorFromString(fmt.Sprintf("O:%sD:P(A;%s;FA;;;%s)", sid, inherit, sid))
}

// OpenPrivateAt opens or creates the single-component regular file name
// below parent. flags holds an access mode plus optional os.O_CREATE,
// os.O_EXCL and os.O_TRUNC. A created file gets the private descriptor; an
// existing file must pass CheckPrivate before the handle is returned, and
// before any truncation.
func OpenPrivateAt(parent *os.File, name string, flags int) (*os.File, error) {
	file, err := openPrivateAt(parent, name, flags)
	if err != nil {
		return nil, pathError("openat", name, err)
	}
	return file, nil
}

func openPrivateAt(parent *os.File, name string, flags int) (*os.File, error) {
	access, err := fileAccess(flags, os.O_CREATE|os.O_EXCL|os.O_TRUNC)
	if err != nil {
		return nil, err
	}
	if err := checkCreateFlags(flags); err != nil {
		return nil, err
	}
	disposition := uint32(windows.FILE_OPEN)
	switch {
	case flags&(os.O_CREATE|os.O_EXCL) == os.O_CREATE|os.O_EXCL:
		disposition = windows.FILE_CREATE
	case flags&os.O_CREATE != 0:
		disposition = windows.FILE_OPEN_IF
	}
	sd, err := privateDescriptor(false)
	if err != nil {
		return nil, err
	}
	var handle windows.Handle
	err = withHandle(parent, func(h windows.Handle) error {
		if err := requireNTFS(h); err != nil {
			return err
		}
		opened, created, err := openChecked(h, name, access, disposition, false, sd)
		if err != nil {
			return err
		}
		if err := checkPrivateObject(opened, false, created); err != nil {
			windows.CloseHandle(opened)
			return err
		}
		handle = opened
		return nil
	})
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), childName(parent, name))
	if flags&os.O_TRUNC != 0 {
		if err := file.Truncate(0); err != nil {
			file.Close()
			return nil, err
		}
	}
	return file, nil
}

func checkCreateFlags(flags int) error {
	if flags&os.O_EXCL != 0 && flags&os.O_CREATE == 0 {
		return errors.New("O_EXCL requires O_CREATE")
	}
	if flags&os.O_TRUNC != 0 && flags&(os.O_WRONLY|os.O_RDWR) == 0 {
		return errors.New("O_TRUNC requires write access")
	}
	return nil
}

// EnsurePrivateDirectoryAt creates the single-component private directory
// name below parent, or opens an existing one. A created directory must pass
// CheckPrivate as a root; an existing one must pass the non-root private
// policy (inherited owner-only grants are accepted, nothing is repaired).
func EnsurePrivateDirectoryAt(parent *os.File, name string) (*os.File, error) {
	var handle windows.Handle
	err := withHandle(parent, func(h windows.Handle) (err error) {
		handle, err = ensurePrivateDirectory(h, name)
		return err
	})
	if err != nil {
		return nil, pathError("mkdirat", name, err)
	}
	return os.NewFile(uintptr(handle), childName(parent, name)), nil
}

// CreatePrivateDirectoryAt atomically creates a new private directory. Unlike
// EnsurePrivateDirectoryAt, it never opens an existing entry, even if private.
func CreatePrivateDirectoryAt(parent *os.File, name string) (*os.File, error) {
	var handle windows.Handle
	err := withHandle(parent, func(h windows.Handle) (err error) {
		handle, err = ensurePrivateDirectoryDisposition(h, name, windows.FILE_CREATE, true)
		return err
	})
	if err != nil {
		return nil, pathError("mkdirat", name, err)
	}
	return os.NewFile(uintptr(handle), childName(parent, name)), nil
}

func ensurePrivateDirectory(parent windows.Handle, name string) (windows.Handle, error) {
	return ensurePrivateDirectoryDisposition(parent, name, windows.FILE_OPEN_IF, false)
}

// ensurePrivateDirectoryDisposition creates or opens a private directory;
// existingRoot applies the root policy to an existing directory as well.
func ensurePrivateDirectoryDisposition(parent windows.Handle, name string, disposition uint32, existingRoot bool) (windows.Handle, error) {
	if err := requireNTFS(parent); err != nil {
		return windows.InvalidHandle, err
	}
	sd, err := privateDescriptor(true)
	if err != nil {
		return windows.InvalidHandle, err
	}
	handle, created, err := openChecked(parent, name, directoryAccess, disposition, true, sd)
	if err != nil {
		return windows.InvalidHandle, err
	}
	if err := checkPrivateHandle(handle, created || existingRoot); err != nil {
		windows.CloseHandle(handle)
		return windows.InvalidHandle, err
	}
	return handle, nil
}

// OpenExistingPrivateDirectory opens a protected private root without creating
// anything. Its ancestor checks match EnsurePrivatePath, including the stricter
// immediate-parent policy; FILE_OPEN never creates or changes the named root.
func OpenExistingPrivateDirectory(path string) (*os.File, error) {
	p, err := parseLocalPath(path)
	if err == nil && len(p.parts) == 0 {
		err = errors.New("a volume root cannot be a private directory")
	}
	if err != nil {
		return nil, pathError("open", path, err)
	}
	last := len(p.parts) - 1
	parent, err := walkDirectory(localPath{drive: p.drive, parts: p.parts[:last]}, walkOptions{checked: true})
	if err != nil {
		return nil, pathError("open", path, err)
	}
	defer windows.CloseHandle(parent)
	handle, err := ensurePrivateDirectoryDisposition(parent, p.parts[last], windows.FILE_OPEN, true)
	if err != nil {
		return nil, pathError("open", path, err)
	}
	return os.NewFile(uintptr(handle), p.String()), nil
}

// EnsurePrivatePath creates or checks the private directory root at path.
// Every existing ancestor must satisfy the public ancestor policy, with the
// immediate parent under the stricter immediate rule; missing ancestors are
// created as private directories. The final directory, new or existing, must
// pass CheckPrivate as a protected root. Nothing existing is repaired.
func EnsurePrivatePath(path string) error {
	p, err := parseLocalPath(path)
	if err == nil && len(p.parts) == 0 {
		err = errors.New("a volume root cannot be a private directory")
	}
	if err != nil {
		return pathError("mkdir", path, err)
	}
	last := len(p.parts) - 1
	parent, err := walkDirectory(localPath{drive: p.drive, parts: p.parts[:last]}, walkOptions{checked: true, createMissing: true})
	if err != nil {
		return pathError("mkdir", path, err)
	}
	defer windows.CloseHandle(parent)
	dir, err := ensurePrivateDirectoryDisposition(parent, p.parts[last], windows.FILE_OPEN_IF, true)
	if err != nil {
		return pathError("mkdir", path, err)
	}
	windows.CloseHandle(dir)
	return nil
}

// PrivateTempDir creates a new private directory in parent (os.TempDir when
// empty) and returns its absolute path. As with os.MkdirTemp, the last "*" in
// prefix is replaced by a random string, which is otherwise appended. parent
// and its ancestors must satisfy the public ancestor policy.
func PrivateTempDir(parent, prefix string) (string, error) {
	if parent == "" {
		parent = os.TempDir()
	}
	if strings.ContainsAny(prefix, `\/`) {
		return "", pathError("mkdirtemp", prefix, errors.New("pattern contains a path separator"))
	}
	p, err := parseLocalPath(parent)
	if err != nil {
		return "", pathError("mkdirtemp", parent, err)
	}
	dir, err := walkDirectory(p, walkOptions{checked: true})
	if err != nil {
		return "", pathError("mkdirtemp", parent, err)
	}
	defer windows.CloseHandle(dir)
	before, after := prefix, ""
	if i := strings.LastIndexByte(prefix, '*'); i >= 0 {
		before, after = prefix[:i], prefix[i+1:]
	}
	for try := 0; try < 10000; try++ {
		name := before + strconv.FormatUint(uint64(rand.Uint32()), 10) + after
		handle, err := ensurePrivateDirectoryDisposition(dir, name, windows.FILE_CREATE, true)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return "", pathError("mkdirtemp", parent, err)
		}
		windows.CloseHandle(handle)
		return localPath{drive: p.drive, parts: append(p.parts[:len(p.parts):len(p.parts)], name)}.String(), nil
	}
	return "", pathError("mkdirtemp", parent, errors.New("too many name collisions"))
}

// WritePrivateFile writes data to the private file at path, creating it with
// the private descriptor or truncating an existing file only after it passes
// CheckPrivate. The parent and its ancestors must satisfy the public ancestor
// policy. Windows ACLs, not perm, govern access; a perm that grants group or
// other access is refused rather than silently narrowed.
func WritePrivateFile(path string, data []byte, perm os.FileMode) error {
	if perm&^os.ModePerm != 0 || perm&0o077 != 0 {
		return pathError("write", path, fmt.Errorf("permission %v is not private", perm))
	}
	p, err := parseLocalPath(path)
	if err == nil && len(p.parts) == 0 {
		err = errors.New("path names a volume root")
	}
	if err != nil {
		return pathError("write", path, err)
	}
	last := len(p.parts) - 1
	handle, err := walkDirectory(localPath{drive: p.drive, parts: p.parts[:last]}, walkOptions{checked: true})
	if err != nil {
		return pathError("write", path, err)
	}
	parent := os.NewFile(uintptr(handle), localPath{drive: p.drive, parts: p.parts[:last]}.String())
	defer parent.Close()
	file, err := OpenPrivateAt(parent, p.parts[last], os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return err
	}
	_, err = file.Write(data)
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	return err
}
