package app

import (
	"errors"

	"github.com/kaimahi-agents/kaimahi/internal/kmx/fileaccess"
)

// filesystemBoundaryError keeps a redacted boundary class while preserving
// only the concrete Linux Windows-drive-mount refusal, whose message is the
// offending path and remedy with no file content. Any other cause stays
// redacted.
func filesystemBoundaryError(class, err error) error {
	if mount := windowsDriveMountCause(err); mount != nil {
		return errors.Join(class, mount)
	}
	return class
}

// windowsDriveMountCause returns the leaf drive-mount refusal from err's tree,
// dropping wrappers and siblings that could carry private payload.
func windowsDriveMountCause(err error) error {
	switch e := err.(type) {
	case nil:
		return nil
	case interface{ Unwrap() error }:
		return windowsDriveMountCause(e.Unwrap())
	case interface{ Unwrap() []error }:
		for _, child := range e.Unwrap() {
			if mount := windowsDriveMountCause(child); mount != nil {
				return mount
			}
		}
		return nil
	}
	if errors.Is(err, fileaccess.ErrWindowsDriveMount) {
		return err
	}
	return nil
}
