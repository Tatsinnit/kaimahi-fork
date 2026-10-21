//go:build windows

package oras

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kaimahi-agents/kaimahi/internal/kmx/fileaccess"
	"golang.org/x/sys/windows"
)

// extractContentLayer extracts into the private staged directory destination.
// Every directory and file is created through fileaccess with the explicit
// current-user-only descriptor, one component at a time below the retained
// stage handle, so no reparse point or inherited ACL is involved. Canonical
// archive modes stay archive metadata (authored payload modes are declared in
// the suite itself); Windows has no faithful mode bits to restore. Link
// entries are refused: recreating them would need the symbolic-link
// privilege or would silently turn links into copies.
func extractContentLayer(ctx context.Context, src io.Reader, destination string) (err error) {
	gzipReader, err := gzip.NewReader(src)
	if err != nil {
		return fmt.Errorf("open AgentSuite content gzip: %w", err)
	}
	defer func() {
		err = errors.Join(err, gzipReader.Close())
	}()
	root, err := fileaccess.OpenDirectory(destination)
	if err != nil {
		return fmt.Errorf("open AgentSuite extraction root: %w", err)
	}
	defer func() {
		err = errors.Join(err, root.Close())
	}()
	if err := fileaccess.CheckPrivate(root, true); err != nil {
		return fmt.Errorf("open AgentSuite extraction root: %w", err)
	}

	tarReader := tar.NewReader(gzipReader)
	var directories []string
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read AgentSuite content tar: %w", err)
		}
		name, err := extractionPath(header)
		if err != nil {
			return err
		}
		parts := strings.Split(name, string(filepath.Separator))
		switch header.Typeflag {
		case tar.TypeDir:
			if err := inPrivateDirectory(root, parts, func(*os.File) error { return nil }); err != nil {
				return fmt.Errorf("create AgentSuite directory %s: %w", header.Name, err)
			}
			directories = append(directories, name)
		case tar.TypeReg:
			err := inPrivateDirectory(root, parts[:len(parts)-1], func(parent *os.File) error {
				return extractFile(ctx, parent, parts[len(parts)-1], header, tarReader)
			})
			if err != nil {
				return err
			}
		case tar.TypeSymlink, tar.TypeLink:
			return fmt.Errorf("AgentSuite content %s is a link; extracting links is not supported on Windows", header.Name)
		default:
			return fmt.Errorf("AgentSuite content %s has unsupported tar type %d", header.Name, header.Typeflag)
		}
	}
	// Directory times change as children are added, so they are set last.
	// The stage is private to this user and its tree was created above, so
	// the path-based attribute update cannot be redirected by others.
	for i := len(directories) - 1; i >= 0; i-- {
		if err := os.Chtimes(filepath.Join(destination, directories[i]), time.Unix(0, 0), time.Unix(0, 0)); err != nil {
			return fmt.Errorf("set AgentSuite directory time %s: %w", directories[i], err)
		}
	}
	return nil
}

// inPrivateDirectory creates or opens each private directory in parts below
// root and runs fn with the innermost one (root itself when parts is empty).
func inPrivateDirectory(root *os.File, parts []string, fn func(*os.File) error) error {
	if len(parts) == 0 {
		return fn(root)
	}
	dir, err := fileaccess.EnsurePrivateDirectoryAt(root, parts[0])
	if err != nil {
		return err
	}
	err = inPrivateDirectory(dir, parts[1:], fn)
	return errors.Join(err, dir.Close())
}

func extractFile(ctx context.Context, parent *os.File, name string, header *tar.Header, src io.Reader) error {
	file, err := fileaccess.OpenPrivateAt(parent, name, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		return fmt.Errorf("create AgentSuite file %s: %w", header.Name, err)
	}
	written, copyErr := io.CopyN(file, &contextReader{ctx: ctx, reader: src}, header.Size)
	var timeErr error
	if copyErr == nil {
		timeErr = setEpochTimes(file)
	}
	closeErr := file.Close()
	if copyErr != nil {
		return fmt.Errorf("extract AgentSuite file %s: %w", header.Name, copyErr)
	}
	if timeErr != nil {
		return fmt.Errorf("set AgentSuite file time %s: %w", header.Name, timeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close AgentSuite file %s: %w", header.Name, closeErr)
	}
	if written != header.Size {
		return fmt.Errorf("AgentSuite file %s size does not match its header", header.Name)
	}
	return nil
}

// setEpochTimes matches the Unix extraction's Chtimes(epoch) through the
// already-open private handle.
func setEpochTimes(file *os.File) error {
	conn, err := file.SyscallConn()
	if err != nil {
		return err
	}
	epoch := windows.NsecToFiletime(0)
	var setErr error
	if err := conn.Control(func(fd uintptr) {
		setErr = windows.SetFileTime(windows.Handle(fd), nil, &epoch, &epoch)
	}); err != nil {
		return err
	}
	return setErr
}
