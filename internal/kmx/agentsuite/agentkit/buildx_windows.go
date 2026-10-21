//go:build windows

package agentkit

import (
	"os"

	"github.com/kaimahi-agents/kaimahi/internal/kmx/fileaccess"
)

func createBuildxWorkDir() (string, error) {
	return fileaccess.PrivateTempDir("", "kmx-agentkit-build-")
}

func writeBuildxInput(path string, data []byte) error {
	return fileaccess.WritePrivateFile(path, data, 0o600)
}

func cancelBuildxProcess(process *os.Process) error {
	// os.Interrupt is not implemented on Windows. Terminate only the owned
	// direct child; WaitDelay still bounds inherited output pipes, as on Unix.
	return process.Kill()
}
