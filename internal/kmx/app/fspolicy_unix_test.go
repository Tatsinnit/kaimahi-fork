//go:build !windows

package app

import (
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// makeSpecialFileForTest creates a FIFO: a non-regular object that would
// block an unguarded open.
func makeSpecialFileForTest(t *testing.T, path string) {
	t.Helper()
	if err := unix.Mkfifo(path, 0644); err != nil {
		t.Fatal(err)
	}
}

func processExitedForTest(pid int) (bool, error) {
	err := syscall.Kill(pid, 0)
	return err == syscall.ESRCH, err
}
