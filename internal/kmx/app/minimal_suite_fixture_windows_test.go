//go:build windows

package app

import (
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/kaimahi-agents/kaimahi/internal/kmx/fileaccess"
)

var minimalSuiteCopy struct {
	sync.Once
	path string
}

// minimalSuiteFixture copies the checked-in suite once into a new protected
// current-user-only tree: AgentSuite v0.6 refuses a Windows input root with
// an inherited DACL, and the checkout's ACL is not changed. The copy lives
// under the process TEMP for the test binary's lifetime.
func minimalSuiteFixture(source string) string {
	minimalSuiteCopy.Do(func() {
		root, err := fileaccess.PrivateTempDir("", "kmx-minimal-suite-")
		if err != nil {
			panic(err)
		}
		err = filepath.WalkDir(source, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(source, path)
			if err != nil || rel == "." {
				return err
			}
			target := filepath.Join(root, rel)
			if entry.IsDir() {
				return fileaccess.EnsurePrivatePath(target)
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			return fileaccess.WritePrivateFile(target, raw, 0o600)
		})
		if err != nil {
			panic(err)
		}
		minimalSuiteCopy.path = root
	})
	return minimalSuiteCopy.path
}
