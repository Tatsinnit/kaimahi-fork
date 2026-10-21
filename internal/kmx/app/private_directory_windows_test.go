//go:build windows

package app

import (
	"testing"

	"github.com/kaimahi-agents/kaimahi/internal/kmx/fileaccess"
)

func privateSuiteDir(t *testing.T) string {
	t.Helper()
	dir, err := fileaccess.PrivateTempDir(t.TempDir(), "private-")
	if err != nil {
		t.Fatal(err)
	}
	return dir
}
