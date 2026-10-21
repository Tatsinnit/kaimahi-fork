//go:build !windows

package oras

import (
	"context"
	"os"

	"oras.land/oras-go/v2/content/oci"
)

type layoutSourceStore = oci.Store

func openLayoutSource(_ context.Context, path string) (*layoutSourceStore, error) {
	return oci.New(path)
}

// Unix keeps KMX's existing mode-based behavior for ORAS stores, staged
// outputs and archives; the helpers below are the original calls.

func verifyPrivateTree(string) error { return nil }

// physicalWithin adds nothing on Unix: the existing lexical and
// symlink-resolved fences remain the authority.
func physicalWithin(string, string) (bool, error) { return false, nil }

func checkExistingLayout(string) error { return nil }

func finishOutputDirectory(stage string) error { return os.Chmod(stage, 0o755) }

func publishDirectory(stage, destination string) error { return os.Rename(stage, destination) }

func createArchiveTemp() (*os.File, func(), error) {
	archive, err := os.CreateTemp("", "agentsuite-content-*.tar.gz")
	if err != nil {
		return nil, nil, err
	}
	archivePath := archive.Name()
	return archive, func() { os.Remove(archivePath) }, nil
}
