//go:build !windows

package oras

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// The Windows read-only source fix must not silently replace Unix's existing
// oci.New construction, including its observable setup before a missing tag.
func TestPullRetainsUnixSourceStoreConstruction(t *testing.T) {
	source := t.TempDir()
	for name, body := range map[string]string{
		"oci-layout": `{"imageLayoutVersion":"1.0.0"}`,
		"index.json": `{"schemaVersion":2,"manifests":[]}`,
	} {
		if err := os.WriteFile(filepath.Join(source, name), []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	output := filepath.Join(t.TempDir(), "out")
	if _, err := Pull(context.Background(), source, "missing", output); err == nil {
		t.Fatal("missing tag accepted")
	}
	info, err := os.Stat(filepath.Join(source, "blobs"))
	if err != nil || !info.IsDir() {
		t.Fatalf("Unix source-store construction changed: %v", err)
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatalf("missing tag published output: %v", err)
	}
}
