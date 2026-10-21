//go:build windows

package toolchain

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/kaimahi-agents/kaimahi/internal/kmx/fileaccess"
	"golang.org/x/sys/windows"
)

func TestNativeAliasFailedStagePreservesPublishedFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "aliases")
	if err := prepareManagedDir(dir); err != nil {
		t.Fatal(err)
	}
	old := []byte("verified existing pin")
	path, err := publishAlias(dir, "kubectl", "", old)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	setAccess := func(access uint32) {
		t.Helper()
		sid := user.User.Sid
		sd, err := windows.SecurityDescriptorFromString(fmt.Sprintf("O:%sD:P(A;;0x%x;;;%s)", sid, access, sid))
		if err != nil {
			t.Fatal(err)
		}
		acl, _, err := sd.DACL()
		if err != nil {
			t.Fatal(err)
		}
		if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
			nil, nil, acl, nil); err != nil {
			t.Fatal(err)
		}
	}
	// Refuse creating a stage but retain the published file's own DELETE
	// grant. This is a disposable fixture, not repair of user state.
	setAccess(windows.FILE_GENERIC_READ | windows.FILE_TRAVERSE)
	t.Cleanup(func() { setAccess(windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0x1ff) })
	parent, err := openManagedDir(dir)
	if err != nil {
		t.Fatalf("fault fixture must remain a valid private readable root: %v", err)
	}
	if err := fileaccess.CheckPrivate(parent, true); err != nil {
		parent.Close()
		t.Fatal(err)
	}
	parent.Close()
	got, err := publishAlias(dir, "kubectl", "", []byte("new selected pin"))
	if err == nil || !errors.Is(err, os.ErrPermission) || got != "" {
		t.Fatalf("failed publication returned path=%q error=%v; want fatal permission refusal and no runnable result", got, err)
	}
	data, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(data, old) {
		t.Fatalf("failed stage deleted/changed an already published alias: data=%q error=%v", data, err)
	}
	after, err := os.Stat(path)
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("failed stage replaced published identity: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != filepath.Base(path) {
		t.Fatalf("failed stage left unexpected entries: %v, %v", entries, err)
	}
}
