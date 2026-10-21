//go:build windows

// windows-tests is a test-only launcher; product kmx never adjusts tokens.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"github.com/kaimahi-agents/kaimahi/internal/kmx/fileaccess"

	"golang.org/x/sys/windows"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("a test command is required")
	}
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		return err
	}
	owner, err := defaultOwner(token)
	if err != nil {
		return err
	}
	cmd := testCommand(args, stdout, stderr)
	if owner.Equals(user.User.Sid) {
		if err := fileaccess.CheckDefaultPrivateOwner(); err != nil {
			return err
		}
		fmt.Fprintln(stdout, "Windows tests: existing current-user default owner")
		return cmd.Run()
	}
	// Prove the product refuses this real group-owner context before using
	// an isolated child token for happy-path tests. Never adjust our token.
	if err := fileaccess.CheckDefaultPrivateOwner(); !errors.Is(err, fileaccess.ErrDefaultOwnerNotUser) {
		return errors.New("product did not refuse the original non-user default owner")
	}
	var source windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE, &source); err != nil {
		return err
	}
	defer source.Close()
	var child windows.Token
	if err := windows.DuplicateTokenEx(source, windows.TOKEN_ALL_ACCESS, nil, windows.SecurityImpersonation, windows.TokenPrimary, &child); err != nil {
		return err
	}
	defer child.Close()
	childOwner := struct{ Owner *windows.SID }{user.User.Sid}
	if err := windows.SetTokenInformation(child, windows.TokenOwner, (*byte)(unsafe.Pointer(&childOwner)), uint32(unsafe.Sizeof(childOwner))); err != nil {
		return err
	}
	verified, err := defaultOwner(child)
	if err != nil || !verified.Equals(user.User.Sid) {
		return errors.New("isolated test token did not retain the user as default owner")
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Token: syscall.Token(child)}
	fmt.Fprintln(stdout, "Windows tests: original group-owner refusal verified; isolated child user-owner token")
	return cmd.Run()
}

func testCommand(args []string, stdout, stderr io.Writer) *exec.Cmd {
	cmd := exec.Command(args[0], args[1:]...)
	// With a token, nil Env loads profile defaults instead of inheriting
	// setup-go and the runner's process-only environment.
	cmd.Env = os.Environ()
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, stdout, stderr
	return cmd
}

func defaultOwner(token windows.Token) (*windows.SID, error) {
	size := uint32(64)
	for {
		buffer := make([]byte, size)
		err := windows.GetTokenInformation(token, windows.TokenOwner, &buffer[0], uint32(len(buffer)), &size)
		if err == nil {
			owner := (*struct{ Owner *windows.SID })(unsafe.Pointer(&buffer[0])).Owner
			if owner == nil || !owner.IsValid() {
				return nil, errors.New("invalid token default owner")
			}
			return owner.Copy()
		}
		if err != windows.ERROR_INSUFFICIENT_BUFFER || size <= uint32(len(buffer)) {
			return nil, err
		}
	}
}
