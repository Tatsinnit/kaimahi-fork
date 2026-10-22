//go:build windows

package fileaccess

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

const (
	sidSystem         = "SY"
	sidAdministrators = "BA"
	sidEveryone       = "WD"
)

var unsupportedObjectACE = "(OA;;FR;" + strings.Trim((windows.GUID{Data1: 1}).String(), "{}") + ";;WD)"

func checkPrivatePath(t *testing.T, path string, root bool) error {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	var object Object
	if info.IsDir() {
		object, err = OpenDirectory(t.Context(), path)
	} else {
		parent := openTestDirectory(t, filepath.Dir(path))
		object, err = OpenRegularAt(t.Context(), parent, filepath.Base(path))
	}
	if err != nil {
		return err
	}
	defer rawObject(object).Close()
	return CheckPrivate(t.Context(), object, root)
}

func TestWindowsPrivateDACLs(t *testing.T) {
	user := windowsTestUser(t)
	owner := "(A;OICI;FA;;;" + user + ")"
	for _, tc := range []struct {
		name, dacl string
		protected  bool
		ok         bool
	}{
		{"OwnerOnly", "P" + owner, true, true},
		{"OwnerReadOnly", "P(A;;FRFX;;;" + user + ")", true, true},
		{"BroadExplicit", "P" + owner + "(A;;FR;;;" + sidEveryone + ")", true, false},
		{"System", "P" + owner + "(A;OICI;FA;;;" + sidSystem + ")", true, false},
		{"Administrators", "P" + owner + "(A;OICI;FA;;;" + sidAdministrators + ")", true, false},
		{"InheritOnlyBroad", "P" + owner + "(A;OICIIO;FA;;;" + sidEveryone + ")", true, false},
		{"Unprotected", owner, false, false},
		{"NullDACL", "NO_ACCESS_CONTROL", true, false},
		{"ObjectACE", "P" + owner + unsupportedObjectACE, true, false},
		{"DenyACE", "P(D;;0x2;;;" + sidEveryone + ")" + owner, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(foundationTempDir(t), "object")
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
			setTestACL(t, path, tc.dacl, tc.protected)
			before := securitySnapshot(t, path)
			err := checkPrivatePath(t, path, true)
			if (err == nil) != tc.ok {
				t.Fatalf("CheckPrivate = %v, want ok=%v", err, tc.ok)
			}
			if !tc.ok && !errors.Is(err, ErrUnsafe) {
				t.Fatalf("refusal class = %v, want unsafe", err)
			}
			if after := securitySnapshot(t, path); after != before {
				t.Fatalf("refusal repaired security: %s -> %s", before, after)
			}
		})
	}
}

func TestWindowsPrivateRegularFile(t *testing.T) {
	dir := foundationTempDir(t)
	path := filepath.Join(dir, "private-file")
	if err := os.WriteFile(path, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	user := windowsTestUser(t)
	setTestACL(t, path, "P(A;;FR;;;"+user+")", true)
	if err := checkPrivatePath(t, path, false); err != nil {
		t.Fatalf("protected owner-only regular file = %v", err)
	}
	if err := checkPrivatePath(t, path, true); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("regular file accepted as a private root: %v", err)
	}
}

func TestWindowsPrivateRefusesInheritedDACLs(t *testing.T) {
	user := windowsTestUser(t)
	parent := filepath.Join(foundationTempDir(t), "parent")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	setTestACL(t, parent, "P(A;OICI;FA;;;"+user+")", true)
	child := filepath.Join(parent, "child")
	if err := os.Mkdir(child, 0o700); err != nil {
		t.Fatal(err)
	}
	current, err := currentUser(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(child, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, current, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(child, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := sd.Owner()
	if err != nil || !owner.Equals(current) {
		t.Fatalf("child fixture owner is not current user: %v", err)
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED != 0 {
		t.Fatalf("child fixture DACL is not inherited/unprotected: control=%#x err=%v", control, err)
	}
	before := securitySnapshot(t, child)
	if err := checkPrivatePath(t, child, false); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("inherited child = %v", err)
	}
	if after := securitySnapshot(t, child); after != before {
		t.Fatalf("check changed inherited security: %s -> %s", before, after)
	}
}

func TestWindowsUnreadableStateIsDistinctAndNotRepaired(t *testing.T) {
	path := filepath.Join(foundationTempDir(t), "unreadable")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	user := windowsTestUser(t)
	// Preserve READ_CONTROL for the non-mutating snapshot and WRITE_DAC for
	// cleanup while denying list/traverse rights required by the product open.
	setTestACL(t, path, "P(D;;0x21;;;"+user+")(A;;RCWD;;;"+user+")", true)
	before := securitySnapshot(t, path)
	if file, err := OpenDirectory(t.Context(), path); !errors.Is(err, ErrUnreadable) {
		if err == nil {
			file.Close()
		}
		t.Fatalf("unreadable directory = %v", err)
	}
	if after := securitySnapshot(t, path); after != before {
		t.Fatalf("read refusal repaired security: %s -> %s", before, after)
	}
}

func TestWindowsPrivateRefusesForeignOwner(t *testing.T) {
	user, err := currentUser(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("O:SYD:P(A;;FA;;;SY)")
	if err != nil {
		t.Fatal(err)
	}
	control, _, _ := sd.Control()
	dacl, _, _ := sd.DACL()
	if err := checkPrivateSecurity(t.Context(), system, control, dacl, user); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("controlled foreign owner = %v", err)
	}
}

func TestWindowsPrivateRefusesProtectedInheritedACE(t *testing.T) {
	user, err := currentUser(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("O:" + user.String() + "D:P(A;OICIID;FA;;;" + user.String() + ")")
	if err != nil {
		t.Fatal(err)
	}
	owner, _, _ := sd.Owner()
	control, _, _ := sd.Control()
	dacl, _, _ := sd.DACL()
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil {
		t.Fatal(err)
	}
	ace.Header.AceFlags |= windows.INHERITED_ACE
	if err := checkPrivateSecurity(t.Context(), owner, control, dacl, user); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("protected inherited ACE = %v", err)
	}
}

func TestWindowsPublicAncestorDACLs(t *testing.T) {
	user := windowsTestUser(t)
	owner := "(A;OICI;FA;;;" + user + ")"
	for _, tc := range []struct {
		name, dacl          string
		ancestor, immediate bool
	}{
		{"OwnerOnly", owner, true, true},
		{"SystemAdministrators", owner + "(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", true, true},
		{"EveryoneReadExecute", owner + "(A;OICI;0x1200a9;;;WD)", true, true},
		{"InheritOnlyModify", owner + "(A;OICIIO;FA;;;AU)", true, true},
		{"DenyEveryone", "(D;;0x2;;;WD)" + owner, true, true},
		{"AddSubdirectory", owner + "(A;;0x4;;;AU)", true, false},
		{"AddFile", owner + "(A;;0x2;;;AU)", false, false},
		{"WriteEA", owner + "(A;;0x10;;;WD)", false, false},
		{"DeleteChild", owner + "(A;;0x40;;;WD)", false, false},
		{"GenericWrite", owner + "(A;;GW;;;WD)", false, false},
		{"ObjectACE", owner + unsupportedObjectACE, false, false},
		{"NullDACL", "NO_ACCESS_CONTROL", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(foundationTempDir(t), "ancestor")
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
			dacl := "P" + tc.dacl
			if tc.dacl == "NO_ACCESS_CONTROL" {
				dacl = tc.dacl
			}
			setTestACL(t, path, dacl, true)
			file := openTestDirectory(t, path)
			if err := CheckSafeDirectory(t.Context(), file, false); (err == nil) != tc.ancestor {
				t.Errorf("ancestor = %v, want ok=%v", err, tc.ancestor)
			}
			if err := CheckSafeDirectory(t.Context(), file, true); (err == nil) != tc.immediate {
				t.Errorf("immediate = %v, want ok=%v", err, tc.immediate)
			}
		})
	}
}

func TestWindowsPublicSecurityRefusesUnknownRights(t *testing.T) {
	user := windowsTestUser(t)
	for _, tc := range []struct {
		name, ace string
		ok        bool
	}{
		{"ReadExecute", "(A;;0x1200a9;;;WD)", true},
		{"SystemSecurity", "(A;;0x1000000;;;WD)", false},
		{"MaximumAllowed", "(A;;0x2000000;;;WD)", false},
		{"UndefinedSpecificBit", "(A;;0x200;;;WD)", false},
		{"InheritOnlyUndefined", "(A;OICIIO;0x200;;;WD)", true},
		{"Callback", "(XA;;FR;;;WD;(Member_of {SID(BA)}))", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString("O:" + user + "D:P(A;OICI;FA;;;" + user + ")" + tc.ace)
			if err != nil {
				t.Fatal(err)
			}
			owner, _, _ := sd.Owner()
			dacl, _, _ := sd.DACL()
			if err := checkPublicSecurity(t.Context(), owner, dacl, false); (err == nil) != tc.ok {
				t.Fatalf("checkPublicSecurity = %v, want ok=%v", err, tc.ok)
			}
		})
	}
}

func TestWindowsPublicSecurityTrustsQualifiedOwners(t *testing.T) {
	user := windowsTestUser(t)
	sd, err := windows.SecurityDescriptorFromString("O:" + user + "D:P(A;OICI;FA;;;" + user + ")")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	current, err := currentUser(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	installer, err := windows.StringToSid(trustedInstaller)
	if err != nil {
		t.Fatal(err)
	}
	for _, owner := range []*windows.SID{current, system, admins, installer} {
		if err := checkPublicSecurity(t.Context(), owner, dacl, true); err != nil {
			t.Errorf("trusted owner %s = %v", owner, err)
		}
	}
}
