//go:build !windows

package config

import (
	"fmt"
	"os"
	"path/filepath"
)

// nativeStateDirectory is os.UserConfigDir()/kmx, unchanged from before
// Windows support.
func nativeStateDirectory() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("cannot locate a config directory (set KMX_HOME): %w", err)
	}
	return filepath.Join(dir, "kmx"), nil
}

// prepareStateDirectory is deliberately a no-op on Unix: resolving state
// never creates it, and writers keep their own 0700/0600 creation.
func prepareStateDirectory(string) error { return nil }

func readSelectedContextFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func writeSelectedContextFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}
