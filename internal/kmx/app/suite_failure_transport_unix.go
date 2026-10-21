//go:build !windows

package app

import (
	"errors"
	"syscall"
)

func suiteFailureConnectionRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}
