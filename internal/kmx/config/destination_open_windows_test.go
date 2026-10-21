//go:build windows

package config

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// junction creates an NTFS directory junction, which needs no symlink
// privilege, so this reparse case always runs.
func junction(t *testing.T, link, target string) {
	t.Helper()
	if out, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J %s %s: %v: %s", link, target, err, out)
	}
}

func writeValidConfig(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("version: 1\n"), 0600); err != nil {
		t.Fatal(err)
	}
}

// Windows counterparts of the Unix link/FIFO cases: directories, junctions
// at the leaf, root and an ancestor, a file symlink where the host permits
// one, and named-pipe/device/UNC namespaces that must never be opened as a
// local workspace.
func unsafeDestinationCases() []unsafeDestinationCase {
	return []unsafeDestinationCase{
		{"directory", func(t *testing.T, root, path string) string {
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			return root
		}},
		{"leaf junction", func(t *testing.T, root, path string) string {
			other := t.TempDir()
			writeValidConfig(t, filepath.Join(other, "kmx.yaml"))
			junction(t, path, other)
			return root
		}},
		{"root junction", func(t *testing.T, root, path string) string {
			writeValidConfig(t, path)
			link := filepath.Join(t.TempDir(), "link")
			junction(t, link, root)
			return link
		}},
		{"ancestor junction", func(t *testing.T, root, path string) string {
			writeValidConfig(t, path)
			link := filepath.Join(t.TempDir(), "link")
			junction(t, link, filepath.Dir(root))
			return filepath.Join(link, filepath.Base(root))
		}},
		{"file symlink", func(t *testing.T, root, path string) string {
			other := filepath.Join(t.TempDir(), "config")
			writeValidConfig(t, other)
			if err := os.Symlink(other, path); err != nil {
				t.Skipf("LIVE GAP: file symlink creation unavailable in this session (%v); junction cases cover reparse refusal", err)
			}
			return root
		}},
		{"named pipe", func(t *testing.T, root, path string) string {
			nonce := make([]byte, 8)
			if _, err := rand.Read(nonce); err != nil {
				t.Fatal(err)
			}
			name := `\\.\pipe\kmx-w462-` + hex.EncodeToString(nonce)
			name16, err := windows.UTF16PtrFromString(name)
			if err != nil {
				t.Fatal(err)
			}
			pipe, err := windows.CreateNamedPipe(name16, windows.PIPE_ACCESS_DUPLEX,
				windows.PIPE_TYPE_BYTE|windows.PIPE_WAIT, 1, 512, 512, 0, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { windows.CloseHandle(pipe) })
			return name
		}},
		{"pipe namespace", func(t *testing.T, root, path string) string { return `\\.\pipe\` }},
		{"device namespace", func(t *testing.T, root, path string) string {
			writeValidConfig(t, path)
			return `\\?\GLOBALROOT\Device\NamedPipe`
		}},
		{"UNC admin share", func(t *testing.T, root, path string) string {
			writeValidConfig(t, path)
			volume := filepath.VolumeName(root)
			if len(volume) != 2 || volume[1] != ':' {
				t.Fatalf("temp root %q is not on a drive letter", root)
			}
			return `\\localhost\` + volume[:1] + `$` + root[len(volume):]
		}},
	}
}

// kmx.yaml is public operator input: an inherited (non-private) ACL is
// accepted exactly as on Unix, through ordinary and extended local paths, and
// absence stays optional.
func TestWindowsDestinationsAcceptPublicLocalPaths(t *testing.T) {
	root := t.TempDir()
	if doc, err := LoadDestinations(root); err != nil || doc != nil {
		t.Fatalf("optional missing: %v %v", doc, err)
	}
	writeValidConfig(t, filepath.Join(root, "kmx.yaml"))
	for _, path := range []string{root, `\\?\` + root} {
		if doc, err := LoadDestinations(path); err != nil || doc == nil || doc.Version != 1 {
			t.Fatalf("%s: %+v, %v", path, doc, err)
		}
	}
}
