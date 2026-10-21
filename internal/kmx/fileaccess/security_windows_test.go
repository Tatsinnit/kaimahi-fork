//go:build windows

package fileaccess

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

const (
	sidSystem          = "SY"
	sidAdministrators  = "BA"
	sidEveryone        = "WD"
	unsupportedObjectA = "(OA;;FR;00112233-4455-6677-8899-aabbccddeeff;;WD)"
)

func faCheckPrivatePath(t *testing.T, path string, root bool) error {
	t.Helper()
	return checkPrivateHandle(openNoFollow(t, path), root)
}

func TestCheckPrivateFixtures(t *testing.T) {
	user := faUser(t)
	owner := "(A;OICI;FA;;;" + user + ")"
	for _, tc := range []struct {
		name, dacl string
		protected  bool
		want       string
	}{
		{"OwnerOnly", "P" + owner, true, ""},
		{"OwnerReadOnly", "P(A;;FR;;;" + user + ")", true, ""},
		{"BroadExplicit", "P" + owner + "(A;;FR;;;" + sidEveryone + ")", true, "non-owner grant"},
		{"System", "P" + owner + "(A;OICI;FA;;;" + sidSystem + ")", true, "non-owner grant"},
		{"Administrators", "P" + owner + "(A;OICI;FA;;;" + sidAdministrators + ")", true, "non-owner grant"},
		{"InheritOnlyBroad", "P" + owner + "(A;OICIIO;FA;;;" + sidEveryone + ")", true, "non-owner grant"},
		{"Unprotected", owner, false, "root DACL is not protected"},
		{"NullDACL", "NO_ACCESS_CONTROL", true, "missing or null DACL"},
		{"ObjectACE", "P" + owner + unsupportedObjectA, true, "unsupported ACE"},
		{"DenyACE", "P(D;;0x2;;;" + sidEveryone + ")" + owner, true, "unsupported ACE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := faMkdir(t, filepath.Join(faPrivateDir(t), "root"))
			faSetACL(t, dir, tc.dacl, tc.protected)
			err := faCheckPrivatePath(t, dir, true)
			if tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("CheckPrivate(%s) = %v, want %q", tc.dacl, err, tc.want)
			}
		})
	}
}

func TestCheckPrivateInheritance(t *testing.T) {
	user := faUser(t)
	for _, tc := range []struct {
		name, grants, want string
	}{
		{"OwnerOnly", "", ""},
		{"BroadInherited", "(A;OICI;FR;;;WD)", "non-owner grant"},
		{"SystemInherited", "(A;OICI;FA;;;SY)", "non-owner grant"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := faMkdir(t, filepath.Join(faPrivateDir(t), "root"))
			faSetACL(t, root, "P(A;OICI;FA;;;"+user+")"+tc.grants, true)
			child := faMkdir(t, filepath.Join(root, "child"))
			file := filepath.Join(child, "file")
			if err := os.WriteFile(file, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{child, file} {
				err := faCheckPrivatePath(t, path, false)
				if tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
					t.Fatalf("CheckPrivate(%s inherited) = %v, want %q", path, err, tc.want)
				}
			}
			// An inherited (unprotected) DACL never qualifies as a private root.
			if err := faCheckPrivatePath(t, child, true); err == nil || !strings.Contains(err.Error(), "not protected") {
				t.Fatalf("CheckPrivate(child as root) = %v, want unprotected refusal", err)
			}
		})
	}
}

func TestCheckPrivateRefusesForeignOwnerAndBroadInheritedTemp(t *testing.T) {
	windowsDir, err := windows.GetSystemWindowsDirectory()
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckPrivate(faOpenDir(t, windowsDir), false); err == nil || !strings.Contains(err.Error(), "owner is not the current user") {
		t.Fatalf("CheckPrivate(%s) = %v, want owner refusal", windowsDir, err)
	}
	// Set the broad inheritance explicitly: TEMP itself may already be private.
	parent := faMkdir(t, filepath.Join(faPrivateDir(t), "broad-parent"))
	faSetACL(t, parent, "P(A;OICI;FA;;;"+faUser(t)+")(A;OICI;FR;;;WD)", true)
	child := faMkdir(t, filepath.Join(parent, "inherited-temp"))
	if err := CheckPrivate(faOpenDir(t, child), false); err == nil || !strings.Contains(err.Error(), "non-owner grant") {
		t.Fatalf("CheckPrivate(broad inherited temp) = %v, want non-owner refusal", err)
	}
}

// TestCheckSafeDirectoryNativeAncestors runs the public ancestor policy on the
// real profile, LOCALAPPDATA and TEMP chains of this ordinary user session.
func TestCheckSafeDirectoryNativeAncestors(t *testing.T) {
	for _, path := range []string{t.TempDir(), os.Getenv("LOCALAPPDATA")} {
		p, err := parseLocalPath(path)
		if err != nil {
			t.Fatalf("parse %q: %v", path, err)
		}
		for i := 0; i <= len(p.parts); i++ {
			ancestor := localPath{drive: p.drive, parts: p.parts[:i]}.String()
			dir := faOpenDir(t, ancestor)
			if err := CheckSafeDirectory(dir, false); err != nil {
				t.Errorf("CheckSafeDirectory(%s, ancestor) = %v\n%s", ancestor, err, faSecuritySnapshot(t, ancestor))
			}
		}
		if err := CheckSafeDirectory(faOpenDir(t, path), true); err != nil {
			t.Errorf("CheckSafeDirectory(%s, immediate) = %v\n%s", path, err, faSecuritySnapshot(t, path))
		}
	}
	// The system drive root lets Authenticated Users create subdirectories:
	// tolerated for an ancestor, refused for an immediate parent.
	if err := CheckSafeDirectory(faOpenDir(t, `C:\`), true); err == nil || !strings.Contains(err.Error(), "untrusted access") {
		t.Fatalf(`CheckSafeDirectory(C:\, immediate) = %v, want refusal`+"\n%s", err, faSecuritySnapshot(t, `C:\`))
	}
	windowsDir, err := windows.GetSystemWindowsDirectory()
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{windowsDir, `C:\Users`} {
		for _, immediate := range []bool{false, true} {
			if err := CheckSafeDirectory(faOpenDir(t, path), immediate); err != nil {
				t.Errorf("CheckSafeDirectory(%s, immediate=%v) = %v\n%s", path, immediate, err, faSecuritySnapshot(t, path))
			}
		}
	}
}

func TestCheckSafeDirectoryFixtures(t *testing.T) {
	user := faUser(t)
	owner := "(A;OICI;FA;;;" + user + ")"
	for _, tc := range []struct {
		name, dacl          string
		ancestor, immediate string
	}{
		{"OwnerOnly", owner, "", ""},
		{"SystemAdministrators", owner + "(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", "", ""},
		{"EveryoneReadExecute", owner + "(A;OICI;0x1200a9;;;WD)", "", ""},
		{"UsersGenericRead", owner + "(A;OICIIO;GRGX;;;BU)(A;;0x1200a9;;;BU)", "", ""},
		{"InheritOnlyModify", owner + "(A;OICIIO;FA;;;AU)", "", ""},
		{"DenyEveryone", "(D;;0x2;;;WD)" + owner, "", ""},
		{"AddSubdirectory", owner + "(A;;0x4;;;AU)", "", "untrusted access"},
		{"AddFile", owner + "(A;;0x2;;;AU)", "untrusted access", "untrusted access"},
		{"WriteEA", owner + "(A;;0x10;;;WD)", "untrusted access", "untrusted access"},
		{"DeleteChild", owner + "(A;;0x40;;;WD)", "untrusted access", "untrusted access"},
		{"WriteAttributes", owner + "(A;;0x100;;;WD)", "untrusted access", "untrusted access"},
		{"Delete", owner + "(A;;SD;;;WD)", "untrusted access", "untrusted access"},
		{"WriteDAC", owner + "(A;;WD;;;WD)", "untrusted access", "untrusted access"},
		{"WriteOwner", owner + "(A;;WO;;;WD)", "untrusted access", "untrusted access"},
		{"GenericWrite", owner + "(A;;GW;;;WD)", "untrusted access", "untrusted access"},
		{"GenericAll", owner + "(A;;GA;;;WD)", "untrusted access", "untrusted access"},
		{"FullControl", owner + "(A;OICI;FA;;;BU)", "untrusted access", "untrusted access"},
		{"Modify", owner + "(A;OICI;0x1301bf;;;AU)", "untrusted access", "untrusted access"},
		{"ObjectACE", owner + unsupportedObjectA, "unsupported ACE", "unsupported ACE"},
		{"NullDACL", "NO_ACCESS_CONTROL", "missing or null DACL", "missing or null DACL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := faMkdir(t, filepath.Join(t.TempDir(), "dir"))
			dacl := "P" + tc.dacl
			if tc.dacl == "NO_ACCESS_CONTROL" {
				dacl = tc.dacl
			}
			faSetACL(t, dir, dacl, true)
			for _, immediate := range []bool{false, true} {
				want := tc.ancestor
				if immediate {
					want = tc.immediate
				}
				err := checkSafeDirectoryHandle(openNoFollow(t, dir), immediate)
				if want == "" && err != nil || want != "" && (err == nil || !strings.Contains(err.Error(), want)) {
					t.Errorf("CheckSafeDirectory(%s, immediate=%v) = %v, want %q; actual %s", tc.dacl, immediate, err, want, faSecuritySnapshot(t, dir))
				}
			}
		})
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkSafeDirectoryHandle(openNoFollow(t, file), false); err == nil {
		t.Fatal("CheckSafeDirectory accepted a regular file")
	}
}

// NTFS discards ACEs carrying ACCESS_SYSTEM_SECURITY or undefined file bits
// when a DACL is stored, so those masks are evaluated in memory: the policy
// must refuse them rather than treat unknown rights as harmless.
func TestCheckPublicSecurityRefusesUnknownRights(t *testing.T) {
	user := faUser(t)
	for _, tc := range []struct {
		name, ace string
		ok        bool
	}{
		{"ReadExecute", "(A;;0x1200a9;;;WD)", true},
		{"SystemSecurity", "(A;;0x1000000;;;WD)", false},
		{"MaximumAllowed", "(A;;0x2000000;;;WD)", false},
		{"UndefinedSpecificBit", "(A;;0x200;;;WD)", false},
		{"UndefinedStandardBit", "(A;;0x800000;;;WD)", false},
		{"InheritOnlyUndefined", "(A;OICIIO;0x200;;;WD)", true},
		{"AuditOnlyFlag", "(A;;FR;;;WD)", false},
		{"Callback", "(XA;;FR;;;WD;(Member_of {SID(BA)}))", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString("O:" + user + "D:P(A;OICI;FA;;;" + user + ")" + tc.ace)
			if err != nil {
				t.Fatalf("SDDL: %v", err)
			}
			owner, _, err := sd.Owner()
			if err != nil {
				t.Fatal(err)
			}
			dacl, _, err := sd.DACL()
			if err != nil {
				t.Fatal(err)
			}
			if tc.name == "AuditOnlyFlag" {
				// SDDL refuses audit flags in a DACL; set
				// SUCCESSFUL_ACCESS_ACE_FLAG in memory instead.
				var ace *windows.ACCESS_ALLOWED_ACE
				if err := windows.GetAce(dacl, 1, &ace); err != nil {
					t.Fatal(err)
				}
				ace.Header.AceFlags |= 0x40
			}
			for _, immediate := range []bool{false, true} {
				if err := checkPublicSecurity(owner, dacl, immediate); (err == nil) != tc.ok {
					t.Errorf("checkPublicSecurity(%s, immediate=%v) = %v, want ok=%v", tc.ace, immediate, err, tc.ok)
				}
			}
		})
	}
}
