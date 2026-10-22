//go:build windows

package fileaccess

import (
	"errors"
)

func unsupportedCause(reason string) error {
	return &classifiedCause{class: ClassUnsupported, reason: reason}
}

func unreadableError(err error) error {
	var classified *classifiedCause
	if errors.As(err, &classified) {
		return err
	}
	return &classifiedCause{class: ClassUnreadable, cause: err}
}
