//go:build windows

package config

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestWindowsSelectedContextRefusesUnsafeLeafWithoutRepair(t *testing.T) {
	for _, kind := range []string{"broad ACL", "directory", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			home := privateStateHome(t)
			t.Setenv("KMX_HOME", home)
			path := filepath.Join(home, "context")
			switch kind {
			case "directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "oversized":
				if err := os.WriteFile(path, bytes.Repeat([]byte("c"), (1<<20)+1), 0600); err != nil {
					t.Fatal(err)
				}
			default:
				if err := os.WriteFile(path, []byte("kind-owned\n"), 0600); err != nil {
					t.Fatal(err)
				}
				grantEveryone(t, path)
			}
			before := securityDescriptor(t, path).String()
			if got, err := ReadSelectedContext(); err == nil || got != "" {
				t.Fatalf("unsafe %s context returned %d bytes, %v; want refusal without contents", kind, len(got), err)
			}
			if after := securityDescriptor(t, path).String(); after != before {
				t.Fatal("context reader repaired the existing leaf")
			}
			if kind == "broad ACL" {
				got, err := os.ReadFile(path)
				if err != nil || string(got) != "kind-owned\n" {
					t.Fatalf("context reader changed existing bytes: %q, %v", got, err)
				}
			}
		})
	}
}
