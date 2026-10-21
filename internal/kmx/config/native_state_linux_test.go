//go:build linux

package config

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/kaimahi-agents/kaimahi/internal/kmx/fileaccess"
)

// liveWindowsDrive returns an existing WSL Windows drive mount point by
// asking the production guard about each mount point, or "" when the host has
// none. Callers disclose the gap instead of passing silently.
func liveWindowsDrive(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || strings.Contains(fields[4], `\`) {
			continue
		}
		if info, err := os.Stat(fields[4]); err != nil || !info.IsDir() {
			continue
		}
		if errors.Is(fileaccess.RefuseWindowsDriveMount(fields[4]), fileaccess.ErrWindowsDriveMount) {
			return fields[4]
		}
	}
	return ""
}

// Every state resolution, including KMX_HOME and the derived directories,
// refuses a Windows drive before any writer can create a file there.
func TestLinuxStateOnWindowsDriveIsRefusedBeforeCreation(t *testing.T) {
	drive := liveWindowsDrive(t)
	if drive == "" {
		t.Skip("LIVE GAP: no Windows drive mount on this host; StateDir refusal not exercised live")
	}
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	owned := filepath.Join(drive, "kmx-w462-state-"+hex.EncodeToString(nonce))
	home := filepath.Join(owned, "kmx")
	refused := func(name string, err error, path string) {
		t.Helper()
		if !errors.Is(err, fileaccess.ErrWindowsDriveMount) || !strings.Contains(err.Error(), strconv.Quote(path)) ||
			!strings.Contains(err.Error(), "use a Linux path or run native Windows kmx") {
			t.Fatalf("%s: got %v, want named refusal of %s", name, err, path)
		}
	}
	t.Setenv("KMX_HOME", home)
	t.Setenv("KUBE_CTX", "")
	for name, get := range map[string]func() (string, error){
		"state": StateDir, "cache": CacheDir, "lift": LiftRecordDir, "toolchain": ToolchainDir,
	} {
		_, err := get()
		refused(name, err, home)
	}
	_, err := WriteSelectedContext("kind-demo")
	refused("context write", err, home)
	_, err = Load("")
	refused("load", err, home)

	t.Setenv("KMX_HOME", "")
	t.Setenv("XDG_CONFIG_HOME", owned)
	_, err = StateDir()
	refused("XDG default", err, home)

	link := filepath.Join(t.TempDir(), "home")
	if err := os.Symlink(owned, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KMX_HOME", link)
	_, err = WriteSelectedContext("kind-demo")
	refused("linked home", err, link)

	if _, err := os.Lstat(owned); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("refused state created %s: %v", owned, err)
	}
	t.Logf("LIVE: state under %s refused without creation", owned)
}
