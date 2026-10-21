//go:build !windows

package scaffold

import (
	"os"
	"path/filepath"
)

// createNew is WriteNew's existing Unix creation: missing directories 0755,
// then an exclusive 0644 file.
func createNew(path string) (*os.File, error) {
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
}
