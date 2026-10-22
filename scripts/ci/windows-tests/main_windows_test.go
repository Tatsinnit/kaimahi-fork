//go:build windows

package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsTestLauncherKeepsParentTokenUnchanged(t *testing.T) {
	token := windows.GetCurrentProcessToken()
	before, err := defaultOwner(token)
	if err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "child-ready")
	if err := run([]string{exe, "-test.run=^TestWindowsTestLauncherChild$", "--", marker}, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(marker); err != nil || string(got) != "user-owner child" {
		t.Fatalf("child did not run in the isolated owner context: %v", err)
	}
	after, err := defaultOwner(token)
	if err != nil || !before.Equals(after) {
		t.Fatal("launcher modified its parent token")
	}
}

func TestWindowsTestLauncherChild(t *testing.T) {
	args := os.Args
	if len(args) < 2 || args[len(args)-2] != "--" {
		return
	}
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	owner, err := defaultOwner(token)
	if err != nil || !owner.Equals(user.User.Sid) {
		t.Fatal("test child does not have its user as default owner")
	}
	if err := os.WriteFile(args[len(args)-1], []byte("user-owner child"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsTestLauncherRetainsEnvironmentWithToken(t *testing.T) {
	const key = "KMX_TEST_LAUNCHER_ENVIRONMENT"
	t.Setenv(key, "process-only-canary")
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE, &token); err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	cmd := testCommand([]string{"unused"}, io.Discard, io.Discard)
	cmd.SysProcAttr = &syscall.SysProcAttr{Token: syscall.Token(token)}
	for _, entry := range cmd.Environ() {
		name, value, _ := strings.Cut(entry, "=")
		if strings.EqualFold(name, key) && value == "process-only-canary" {
			return
		}
	}
	t.Fatal("token child lost the launcher's process environment")
}

func TestWindowsTestLauncherRejectsMissingCommand(t *testing.T) {
	if err := run(nil, io.Discard, io.Discard); err == nil {
		t.Fatal("missing command reported success")
	}
}
