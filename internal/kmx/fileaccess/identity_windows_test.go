//go:build windows

package fileaccess

import (
	"regexp"
	"testing"
)

func TestWindowsIdentityUsesFullFileID(t *testing.T) {
	dir := foundationTempDir(t)
	file := openTestDirectory(t, dir)
	id, err := PhysicalIdentity(t.Context(), file)
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[0-9a-f]{16}-[0-9a-f]{32}$`).MatchString(id) {
		t.Fatalf("identity %q does not contain a 64-bit volume and 128-bit file ID", id)
	}
}
