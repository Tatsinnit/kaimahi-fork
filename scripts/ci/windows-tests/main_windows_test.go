//go:build windows

package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestWindowsTestLauncherKeepsParentTokenUnchanged(t *testing.T) {
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	before, err := defaultOwner(token)
	if err != nil {
		t.Fatal(err)
	}
	if !before.Equals(user.User.Sid) {
		t.Skip("no-adjustment branch requires the current user as default owner")
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

func TestWindowsTestLauncherAdjustsOnlyChildToken(t *testing.T) {
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	groupOwner, err := nonUserDefaultOwner(token, user.User.Sid)
	if errors.Is(err, errNoNonUserOwner) {
		t.Skip("token has no non-user group eligible as a default owner")
	}
	if err != nil {
		t.Fatal(err)
	}
	var source windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE, &source); err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	var groupToken windows.Token
	if err := windows.DuplicateTokenEx(source, windows.TOKEN_ALL_ACCESS, nil, windows.SecurityImpersonation, windows.TokenPrimary, &groupToken); err != nil {
		t.Fatal(err)
	}
	defer groupToken.Close()
	owner := struct{ Owner *windows.SID }{groupOwner}
	if err := windows.SetTokenInformation(groupToken, windows.TokenOwner, (*byte)(unsafe.Pointer(&owner)), uint32(unsafe.Sizeof(owner))); err != nil {
		t.Fatal(err)
	}
	verified, err := defaultOwner(groupToken)
	if err != nil || verified.Equals(user.User.Sid) || !verified.Equals(groupOwner) {
		t.Fatalf("non-user parent token fixture is invalid: owner=%v err=%v", verified, err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "group-owner-parent-ready")
	cmd := testCommand([]string{exe, "-test.run=^TestWindowsTestLauncherNonUserParent$", "--", marker}, io.Discard, io.Discard)
	cmd.SysProcAttr = &syscall.SysProcAttr{Token: syscall.Token(groupToken)}
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(marker); err != nil || string(got) != "group-owner parent unchanged" {
		t.Fatalf("adjustment branch was not verified: %q, %v", got, err)
	}
}

func TestWindowsTestLauncherNonUserParent(t *testing.T) {
	args := os.Args
	if len(args) < 2 || args[len(args)-2] != "--" {
		return
	}
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	before, err := defaultOwner(token)
	if err != nil {
		t.Fatal(err)
	}
	if before.Equals(user.User.Sid) {
		t.Fatal("non-user parent fixture unexpectedly has the user as owner")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	childMarker := args[len(args)-1] + ".child"
	if err := run([]string{exe, "-test.run=^TestWindowsTestLauncherChild$", "--", childMarker}, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	after, err := defaultOwner(token)
	if err != nil || !before.Equals(after) {
		t.Fatal("launcher modified its non-user parent token")
	}
	if got, err := os.ReadFile(childMarker); err != nil || string(got) != "user-owner child" {
		t.Fatalf("adjusted child is not user-owned: %q, %v", got, err)
	}
	if err := os.WriteFile(args[len(args)-1], []byte("group-owner parent unchanged"), 0o600); err != nil {
		t.Fatal(err)
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

var errNoNonUserOwner = errors.New("no non-user default owner group")

func nonUserDefaultOwner(token windows.Token, user *windows.SID) (*windows.SID, error) {
	groups, err := token.GetTokenGroups()
	if err != nil {
		return nil, err
	}
	for _, group := range groups.AllGroups() {
		if group.Sid != nil && group.Sid.IsValid() && !group.Sid.Equals(user) &&
			group.Attributes&windows.SE_GROUP_OWNER != 0 && group.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY == 0 {
			return group.Sid.Copy()
		}
	}
	return nil, errNoNonUserOwner
}
