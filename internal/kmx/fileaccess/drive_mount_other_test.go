//go:build !linux

package fileaccess

import "testing"

// Only Linux can see WSL drive mounts; elsewhere the guard is a no-op.
func TestRefuseWindowsDriveMountIsLinuxOnly(t *testing.T) {
	for _, path := range []string{t.TempDir(), "", "/mnt/c/kmx"} {
		if err := RefuseWindowsDriveMount(path); err != nil {
			t.Errorf("%q: %v", path, err)
		}
	}
}
