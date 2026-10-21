//go:build !windows

package agentkit

import "os"

func createBuildxWorkDir() (string, error) {
	return os.MkdirTemp("", "kmx-agentkit-build-*")
}

func writeBuildxInput(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}

func cancelBuildxProcess(process *os.Process) error {
	return process.Signal(os.Interrupt)
}
