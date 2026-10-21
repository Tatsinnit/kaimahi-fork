//go:build !windows

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExistingStateDirRetainsUnixGetter(t *testing.T) {
	home := filepath.Join(t.TempDir(), "absent")
	t.Setenv("KMX_HOME", home)
	got, err := ExistingStateDir()
	if err != nil || got != home {
		t.Fatalf("Unix getter = %q, %v", got, err)
	}
	if _, err := os.Lstat(home); !os.IsNotExist(err) {
		t.Fatalf("Unix getter created state: %v", err)
	}
}
