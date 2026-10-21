//go:build !windows

package config

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// openDestinationsRoot walks abs one component at a time from "/" without
// following links or blocking on a substituted special file.
func openDestinationsRoot(abs string) (*os.File, error) {
	fd, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	dir := os.NewFile(uintptr(fd), "/")
	for _, part := range strings.Split(strings.TrimPrefix(abs, "/"), "/") {
		if part == "" {
			continue
		}
		fd, err = unix.Openat(int(dir.Fd()), part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		dir.Close()
		if err != nil {
			return nil, err
		}
		dir = os.NewFile(uintptr(fd), part)
	}
	return dir, nil
}

// openDestinationsFile opens kmx.yaml in dir without following a link or
// blocking on a FIFO. Absence is the raw ENOENT, which os.IsNotExist reports.
func openDestinationsFile(dir *os.File) (*os.File, error) {
	fd, err := unix.Openat(int(dir.Fd()), "kmx.yaml", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "kmx.yaml"), nil
}
