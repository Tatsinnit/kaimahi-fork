//go:build !windows

package config

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// The original Unix cases, unchanged: leaf symlink, FIFO, directory and a
// symlinked root.
func unsafeDestinationCases() []unsafeDestinationCase {
	return []unsafeDestinationCase{
		{"symlink", func(t *testing.T, root, path string) string {
			other := filepath.Join(t.TempDir(), "config")
			os.WriteFile(other, []byte("version: 1\n"), 0600)
			if err := os.Symlink(other, path); err != nil {
				t.Fatal(err)
			}
			return root
		}},
		{"fifo", func(t *testing.T, root, path string) string {
			if err := unix.Mkfifo(path, 0600); err != nil {
				t.Fatal(err)
			}
			return root
		}},
		{"directory", func(t *testing.T, root, path string) string {
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			return root
		}},
		{"root link", func(t *testing.T, root, path string) string {
			os.WriteFile(path, []byte("version: 1\n"), 0600)
			link := filepath.Join(t.TempDir(), "link")
			os.Symlink(root, link)
			return link
		}},
	}
}
