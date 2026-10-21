//go:build windows

package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kaimahi-agents/kaimahi/internal/kmx/fileaccess"
)

// kubectl reads --patch-file with os.ReadFile: neither /dev/stdin nor "-"
// supplies stdin on Windows. Keep the payload out of argv in a new private
// directory, and never acknowledge success if cleanup fails after the call.
func (a *App) orkaPatchCapture(ctx context.Context, body []byte, args ...string) (out []byte, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	index := -1
	for i, arg := range args {
		if arg != "--patch-file=/dev/stdin" {
			continue
		}
		if index >= 0 {
			return nil, errors.New("patch input requires exactly one file flag")
		}
		index = i
	}
	if index < 0 {
		return nil, errors.New("patch input requires exactly one file flag")
	}
	dir, err := fileaccess.PrivateTempDir("", "kmx-kubectl-patch-")
	if err != nil {
		return nil, err
	}
	defer func() {
		if cleanupErr := os.RemoveAll(dir); cleanupErr != nil {
			out = nil
			err = errors.Join(err, fmt.Errorf("remove private kubectl patch input: %w", cleanupErr))
		}
	}()
	parent, err := fileaccess.OpenDirectory(dir)
	if err != nil {
		return nil, err
	}
	file, openErr := fileaccess.OpenPrivateAt(parent, "patch.json", os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	closeParentErr := parent.Close()
	if openErr != nil {
		return nil, errors.Join(openErr, closeParentErr)
	}
	if closeParentErr != nil {
		file.Close()
		return nil, closeParentErr
	}
	_, writeErr := file.Write(body)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return nil, err
	}
	command := append([]string(nil), args...)
	command[index] = "--patch-file=" + filepath.Join(dir, "patch.json")
	return a.orkaCapture(ctx, nil, command...)
}
