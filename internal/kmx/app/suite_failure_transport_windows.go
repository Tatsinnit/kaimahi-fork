//go:build windows

package app

import (
	"errors"
	"syscall"

	"golang.org/x/sys/windows"
)

// Actual Winsock failures use WSA codes, not Go's synthetic portable errno.
// Match typed error chains only; untrusted diagnostic text is not a class.
func suiteFailureConnectionRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, windows.WSAECONNREFUSED)
}
