//go:build windows

package app

import (
	"errors"
	"net"
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsSuiteFailureConnectionRefused(t *testing.T) {
	err := &net.OpError{Op: "dial", Err: &os.SyscallError{Syscall: "connectex", Err: windows.WSAECONNREFUSED}}
	if got := suiteFailureClass(err); got != "connection-refused" {
		t.Fatalf("Winsock refused class = %q", got)
	}
	if got := suiteFailureClass(errors.New("connection refused: private canary")); got != "unknown" {
		t.Fatalf("untrusted text granted a transport class: %q", got)
	}
}
