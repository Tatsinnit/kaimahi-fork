package scaffold

import (
	"fmt"
	"os"

	"github.com/kaimahi-agents/kaimahi/internal/kmx/fileaccess"
)

// WriteNew writes the manifest with an EXCLUSIVE create.
//
// The file is the artifact and the operator owns it: once they have edited
// it, a second `kmx agent create` with the same name must not silently
// replace their work. There is no --force; the remedy is to name a different
// file, or to delete the one you have decided you do not want.
func WriteNew(path, content string) error {
	// A Linux output on a Windows drive mount is refused before any write.
	if err := fileaccess.RefuseWindowsDriveMount(path); err != nil {
		return err
	}
	f, err := createNew(path)
	if err != nil {
		if os.IsExist(err) {
			return &fileExistsError{path: path, cause: err}
		}
		return err
	}
	defer f.Close()
	if _, err := f.WriteString(content); err != nil {
		return err
	}
	return nil
}

// fileExistsError preserves the shared diagnostic while letting callers with
// different artifact semantics supply their own advice via errors.Is.
type fileExistsError struct {
	path  string
	cause error
}

func (e *fileExistsError) Error() string {
	return fmt.Sprintf("%s already exists — refusing to overwrite it.\n"+
		"  It may be a manifest you have edited. Apply it as it stands:\n"+
		"    kubectl apply -f %s\n"+
		"  or scaffold under another name with --out <path>.", e.path, e.path)
}

func (e *fileExistsError) Unwrap() error { return e.cause }
