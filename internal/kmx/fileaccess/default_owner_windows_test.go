//go:build windows

package fileaccess

import (
	"errors"
	"testing"

	"golang.org/x/sys/windows"
)

// The qualified native context is an ordinary, non-elevated session whose
// token default owner is its user. An elevated or service token (default
// owner Administrators) is refused; that real negative context is not
// available to an unprivileged test, so the comparison is exercised directly.
func TestCheckDefaultPrivateOwnerOrdinaryContext(t *testing.T) {
	token := windows.GetCurrentProcessToken()
	owner, err := tokenDefaultOwner(token)
	if err != nil {
		t.Fatal(err)
	}
	user, err := currentUser()
	if err != nil {
		t.Fatal(err)
	}
	if !owner.Equals(user) {
		t.Fatalf("this test needs an ordinary session: token default owner %s is not user %s", owner, user)
	}
	if err := CheckDefaultPrivateOwner(); err != nil {
		t.Fatalf("CheckDefaultPrivateOwner() = %v in an ordinary session", err)
	}
}

func TestCheckDefaultOwnerRefusesGroupOwner(t *testing.T) {
	user, err := currentUser()
	if err != nil {
		t.Fatal(err)
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkDefaultOwner(admins, user); !errors.Is(err, ErrDefaultOwnerNotUser) {
		t.Fatalf("Administrators default owner = %v, want ErrDefaultOwnerNotUser", err)
	}
	if err := checkDefaultOwner(nil, user); !errors.Is(err, ErrDefaultOwnerNotUser) {
		t.Fatalf("missing default owner = %v, want ErrDefaultOwnerNotUser", err)
	}
	if err := checkDefaultOwner(user, user); err != nil {
		t.Fatalf("user default owner = %v", err)
	}
}
