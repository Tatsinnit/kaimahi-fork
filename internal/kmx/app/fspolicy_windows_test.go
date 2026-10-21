//go:build windows

package app

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kaimahi-agents/kaimahi/internal/kmx/fileaccess"
	agentruntime "github.com/kaimahi-agents/kaimahi/internal/kmx/runtime"
	"golang.org/x/sys/windows"
)

// makeSpecialFileForTest creates a junction: the Windows non-regular,
// reparse-point object that strict opens must refuse. Junctions need no
// symbolic-link privilege, so this runs as an ordinary user.
func makeSpecialFileForTest(t *testing.T, path string) {
	t.Helper()
	winJunction(t, path, t.TempDir())
}

func processExitedForTest(pid int) (bool, error) {
	h, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		return true, err
	}
	if err != nil {
		return false, err
	}
	defer windows.CloseHandle(h)
	event, err := windows.WaitForSingleObject(h, 0)
	return event == windows.WAIT_OBJECT_0, err
}

func winJunction(t *testing.T, link, target string) {
	t.Helper()
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J %s %s: %v: %s", link, target, err, out)
	}
}

func winUser(t *testing.T) string {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	return user.User.Sid.String()
}

// winBroaden installs an owner-plus-Everyone-read DACL on a disposable
// fixture this test created. It is never production repair.
func winBroaden(t *testing.T, path string) {
	t.Helper()
	user := winUser(t)
	sd, err := windows.SecurityDescriptorFromString("O:" + user + "D:P(A;OICI;FA;;;" + user + ")(A;;FR;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	flags := windows.SECURITY_INFORMATION(windows.OWNER_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, flags, owner, nil, acl, nil); err != nil {
		t.Fatalf("SetNamedSecurityInfo(%s): %v", path, err)
	}
}

func winShortPath(t *testing.T, path string) string {
	t.Helper()
	long, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]uint16, 1024)
	n, err := windows.GetShortPathName(long, &buf[0], uint32(len(buf)))
	if err != nil {
		t.Fatalf("GetShortPathName(%s): %v", path, err)
	}
	return windows.UTF16ToString(buf[:n])
}

func winCheckPrivate(t *testing.T, path string, root bool) {
	t.Helper()
	var file *os.File
	var err error
	if info, statErr := os.Lstat(path); statErr == nil && info.IsDir() {
		file, err = fileaccess.OpenDirectory(path)
	} else {
		var dir *os.File
		dir, err = fileaccess.OpenDirectory(filepath.Dir(path))
		if err == nil {
			file, err = fileaccess.OpenRegularAt(dir, filepath.Base(path), os.O_RDONLY)
			dir.Close()
		}
	}
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer file.Close()
	if err := fileaccess.CheckPrivate(file, root); err != nil {
		t.Fatalf("%s is not private (root=%v): %v", path, root, err)
	}
}

// winRequireProtected proves a file got an explicit protected descriptor
// (fileaccess creation) rather than Go's inherited default DACL.
func winRequireProtected(t *testing.T, path string) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("%s DACL not protected: %v", path, err)
	}
}

func winNoEntries(t *testing.T, dir string, want int) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != want {
		t.Fatalf("%s entries = %v, %v; want %d", dir, entries, err, want)
	}
}

// Private exports require a handle-checked owner-only parent, create the
// stage with the explicit private descriptor, and refuse Win32-rewritten,
// stream and device leaf names before any Root operation.
func TestWindowsSuitePassingExportUsesHandleACLs(t *testing.T) {
	dir := privateSuiteDir(t)
	destination := filepath.Join(dir, "receipt.json")
	export, err := preflightSuitePassingExport(t.Context(), destination, t.TempDir(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := export.publishBytes(t.Context(), []byte("private\n")); err != nil {
		t.Fatal(err)
	}
	if err := export.Close(); err != nil {
		t.Fatal(err)
	}
	winCheckPrivate(t, destination, false)
	// The stage carried an explicit protected descriptor, not inherited grants.
	winRequireProtected(t, destination)

	broad := t.TempDir()
	winBroaden(t, broad)
	if out, err := preflightSuitePassingExport(t.Context(), filepath.Join(broad, "receipt.json"), t.TempDir(), t.TempDir()); !errors.Is(err, errSuitePassingFile) {
		if out != nil {
			out.Close()
		}
		t.Fatalf("broad parent admitted for private export: %v", err)
	}
	public, err := preflightSuitePublicExport(t.Context(), filepath.Join(broad, "public.json"), t.TempDir(), t.TempDir())
	if err != nil {
		t.Fatalf("trusted public parent refused: %v", err)
	}
	public.Close()

	for _, leaf := range []string{"r.json:ads", "r.json::$DATA", "r.json.", "r.json ", "CON", "nul.json", "COM1.txt"} {
		if out, err := preflightSuitePassingExport(t.Context(), dir+`\`+leaf, t.TempDir(), t.TempDir()); err == nil {
			out.Close()
			t.Errorf("leaf %q admitted", leaf)
		}
	}
	winNoEntries(t, dir, 1)

	link := filepath.Join(t.TempDir(), "junction")
	winJunction(t, link, dir)
	if out, err := preflightSuitePassingExport(t.Context(), filepath.Join(link, "other.json"), t.TempDir(), t.TempDir()); err == nil {
		out.Close()
		t.Fatal("junction parent admitted")
	}
	if out, err := preflightSuitePassingExport(t.Context(), destination, t.TempDir(), t.TempDir()); err == nil {
		out.Close()
		t.Fatal("existing output admitted")
	}
	winNoEntries(t, dir, 1)
}

// unchanged rechecks the parent's real DACL; FileInfo bits never change here.
func TestWindowsSuitePassingExportRechecksParentACL(t *testing.T) {
	dir := privateSuiteDir(t)
	destination := filepath.Join(dir, "receipt.json")
	export, err := preflightSuitePassingExport(t.Context(), destination, t.TempDir(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer export.Close()
	winBroaden(t, dir)
	if err := export.publishBytes(t.Context(), []byte("x")); !errors.Is(err, errSuitePassingExport) || export.linked {
		t.Fatalf("broadened parent = %v linked=%v", err, export.linked)
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		t.Fatalf("broadened parent published output: %v", err)
	}
}

func TestWindowsSuitePassingReceiptReadChecksHandleACLs(t *testing.T) {
	dir := privateSuiteDir(t)
	path := filepath.Join(dir, "receipt.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	// An inherited owner-only file passes privacy and reaches the parser.
	if _, err := readSuitePassingReceipt(t.Context(), path); err == nil || errors.Is(err, errSuitePassingFile) {
		t.Fatalf("private file = %v, want parser refusal", err)
	}
	winBroaden(t, path)
	if _, err := readSuitePassingReceipt(t.Context(), path); !errors.Is(err, errSuitePassingFile) {
		t.Fatalf("broad file = %v, want privacy refusal", err)
	}
	broadDir := t.TempDir()
	winBroaden(t, broadDir)
	other := filepath.Join(broadDir, "receipt.json")
	if err := os.WriteFile(other, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSuitePassingReceipt(t.Context(), other); !errors.Is(err, errSuitePassingFile) {
		t.Fatalf("broad parent = %v, want privacy refusal", err)
	}
}

func TestWindowsWorkspaceIdentityIsPhysical(t *testing.T) {
	base := t.TempDir()
	workspace := filepath.Join(base, "Workspace Root")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	want, err := suitePassWorkspaceIdentity(workspace)
	if err != nil {
		t.Fatal(err)
	}
	aliases := []string{strings.ToUpper(workspace), strings.ToLower(workspace), `\\?\` + workspace, workspace + `\`}
	if short := winShortPath(t, workspace); short != workspace {
		aliases = append(aliases, short)
	} else {
		t.Log("8.3 short names unavailable on this volume; short alias not exercised")
	}
	for _, alias := range aliases {
		if got, err := suitePassWorkspaceIdentity(alias); err != nil || got != want {
			t.Errorf("identity(%s) = %s, %v; want %s", alias, got, err, want)
		}
	}
	other := filepath.Join(base, "Other")
	if err := os.Mkdir(other, 0o700); err != nil {
		t.Fatal(err)
	}
	if got, err := suitePassWorkspaceIdentity(other); err != nil || got == want {
		t.Fatalf("distinct workspace identity = %s, %v", got, err)
	}
	link := filepath.Join(base, "junction")
	winJunction(t, link, workspace)
	if _, err := suitePassWorkspaceIdentity(link); err == nil {
		t.Fatal("junction workspace spelling admitted without resolution")
	}
}

func TestWindowsReceiptFenceUsesPhysicalLocation(t *testing.T) {
	base := t.TempDir()
	tree := filepath.Join(base, "Workspace Tree")
	if err := os.MkdirAll(filepath.Join(tree, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "junction")
	winJunction(t, link, tree)
	inside := []string{
		filepath.Join(tree, "out.json"),
		filepath.Join(strings.ToUpper(tree), "out.json"),
		`\\?\` + filepath.Join(tree, "out.json"),
		filepath.Join(tree, "sub", "missing", "out.json"),
		filepath.Join(link, "out.json"),
		tree,
	}
	if short := winShortPath(t, tree); short != tree {
		inside = append(inside, filepath.Join(short, "out.json"))
	} else {
		t.Log("8.3 short names unavailable on this volume; short alias not exercised")
	}
	for _, path := range inside {
		if !suiteReceiptInside(path, tree) {
			t.Errorf("%s not fenced inside %s", path, tree)
		}
	}
	for _, path := range []string{filepath.Join(base, "out.json"), filepath.Join(base, "Workspace Tree2", "out.json")} {
		if suiteReceiptInside(path, tree) {
			t.Errorf("%s wrongly fenced inside %s", path, tree)
		}
	}
	if !suiteReceiptInside(filepath.Join(base, "out.json"), "") {
		t.Error("empty tree not treated as inside")
	}
}

// The release intent and every snapshot are durable private objects before
// native effects; the store lock is exclusive and released on close.
func TestWindowsReleaseLiftIntentBarrier(t *testing.T) {
	summary, receipt, annotation := recordTestInput(t)
	state := privateSuiteDir(t)
	t.Setenv("KMX_HOME", state)
	if err := preflightReleaseLiftStorage(t.Context()); err != nil {
		t.Fatalf("storage probe: %v", err)
	}
	winNoEntries(t, filepath.Join(state, "release-lifts"), 1) // only the lock
	w, err := preflightReleaseLiftRecord(t.Context(), recordTestID, summary, receipt, annotation)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	winCheckPrivate(t, recordTestPath("intent.json"), false)
	winRequireProtected(t, recordTestPath("intent.json"))
	winCheckPrivate(t, filepath.Join(state, "release-lifts"), true)
	winCheckPrivate(t, recordTestPath(""), true)
	if other, err := openReleaseLiftStorage(t.Context()); err == nil {
		other.Close()
		t.Fatal("second reservation acquired the held lock")
	}
	result := ReleaseLiftResult{State: "partial", Resources: []ReleaseLiftOutcome{{ReleaseLiftResource: summary.Resources[0], Outcome: "created"}}}
	for i := 1; i <= 3; i++ {
		if err := w.checkpoint(t.Context(), result); err != nil {
			t.Fatalf("checkpoint %d: %v", i, err)
		}
	}
	for _, name := range []string{"1.json", "2.json", "3.json"} {
		winCheckPrivate(t, recordTestPath(name), false)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := openReleaseLiftStorage(t.Context())
	if err != nil {
		t.Fatalf("lock not released on close: %v", err)
	}
	if err := again.Close(); err != nil {
		t.Fatal(err)
	}
	if err := mkdirPrivate(mustOpenRoot(t, filepath.Join(state, "release-lifts")), recordTestID); !os.IsExist(err) {
		t.Fatalf("existing attempt directory = %v, want exist", err)
	}
}

func mustOpenRoot(t *testing.T, path string) *os.Root {
	t.Helper()
	root, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return root
}

func TestWindowsReleaseLiftRefusesBroadState(t *testing.T) {
	summary, receipt, annotation := recordTestInput(t)
	state := t.TempDir()
	t.Setenv("KMX_HOME", state)
	if w, err := preflightReleaseLiftRecord(t.Context(), recordTestID, summary, receipt, annotation); err == nil {
		w.Close()
		t.Fatal("inherited broad state root admitted")
	}
	winNoEntries(t, state, 0)
}

func TestWindowsPrivateMkdirHasOneConcurrentWinner(t *testing.T) {
	root := mustOpenRoot(t, privateSuiteDir(t))
	start := make(chan struct{})
	results := make(chan error, 32)
	for i := 0; i < cap(results); i++ {
		go func() {
			<-start
			results <- mkdirPrivate(root, "reservation")
		}()
	}
	close(start)
	winners := 0
	for i := 0; i < cap(results); i++ {
		err := <-results
		if err == nil {
			winners++
		} else if !os.IsExist(err) {
			t.Errorf("reservation contender: %v", err)
		}
	}
	if winners != 1 {
		t.Fatalf("private directory had %d concurrent winners, want 1", winners)
	}
}

func TestWindowsPrivateDirectoryHelpers(t *testing.T) {
	dir := privateSuiteDir(t)
	root := mustOpenRoot(t, dir)
	if err := mkdirPrivate(root, "child"); err != nil {
		t.Fatal(err)
	}
	winCheckPrivate(t, filepath.Join(dir, "child"), true)
	if err := mkdirPrivate(root, "child"); !os.IsExist(err) {
		t.Fatalf("existing child = %v, want exist", err)
	}
	child, err := openChildRoot(root, "child")
	if err != nil {
		t.Fatal(err)
	}
	child.Close()
	winJunction(t, filepath.Join(dir, "link"), filepath.Join(dir, "child"))
	if child, err := openChildRoot(root, "link"); err == nil {
		child.Close()
		t.Fatal("junction child root admitted")
	}
	if absentLeaf(root, "child") || absentLeaf(root, "link") || absentLeaf(root, "x:ads") || absentLeaf(root, "x.") || absentLeaf(root, "AUX") {
		t.Fatal("existing or invalid leaf reported absent")
	}
	if !absentLeaf(root, "missing.json") {
		t.Fatal("valid absent leaf not reported absent")
	}
}

func TestWindowsSuitePassStoreLockAndPartitionAliases(t *testing.T) {
	t.Setenv("KMX_HOME", privateSuiteDir(t))
	workspace := filepath.Join(t.TempDir(), "Workspace")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	cache := t.TempDir()
	digest := "sha256:" + strings.Repeat("ab", 32)
	first, err := openSuitePassStore(t.Context(), workspace, cache, digest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.scan(t.Context(), nil); err != nil {
		t.Fatalf("empty private partition scan: %v", err)
	}
	if err := first.reserve(t.Context()); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	alias := strings.ToUpper(workspace)
	if second, err := openSuitePassStore(t.Context(), alias, cache, digest); err == nil {
		second.Close()
		t.Fatal("case alias split the workspace lock")
	}
	identity := first.identity
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := openSuitePassStore(t.Context(), alias, cache, digest)
	if err != nil {
		t.Fatalf("lock not released on close: %v", err)
	}
	defer second.Close()
	if second.identity != identity {
		t.Fatalf("alias identity %s != %s", second.identity, identity)
	}
}

func TestWindowsSessionReferenceManifestPrivacy(t *testing.T) {
	dir := privateSuiteDir(t)
	path := filepath.Join(dir, "references.yaml")
	if err := appendSessionReferenceManifest(path, []agentruntime.SessionReferenceCase{sessionReferenceAppCase(t, "first", "uid-1")}); err != nil {
		t.Fatal(err)
	}
	winCheckPrivate(t, path, false)
	winRequireProtected(t, path)
	if _, err := readSessionReferenceManifest(path); err != nil {
		t.Fatal(err)
	}
	winNoEntries(t, dir, 1)
	winBroaden(t, path)
	if _, err := readSessionReferenceManifest(path); !errors.Is(err, errSessionReferenceFile) {
		t.Fatalf("broad manifest = %v, want refusal", err)
	}
	if err := appendSessionReferenceManifest(dir+`\refs.yaml:ads`, []agentruntime.SessionReferenceCase{sessionReferenceAppCase(t, "second", "uid-2")}); err == nil {
		t.Fatal("stream output admitted")
	}
	winNoEntries(t, dir, 1)
}

func TestWindowsSessionsHostRequiresPrivateHandles(t *testing.T) {
	dir := privateSuiteDir(t)
	path := filepath.Join(dir, "host.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := readPrivateSuiteSessionsHost(path); err != nil {
		t.Fatalf("private host file: %v", err)
	}
	winBroaden(t, path)
	if _, _, _, err := readPrivateSuiteSessionsHost(path); !errors.Is(err, errSuiteSessionsHost) {
		t.Fatalf("broad host file = %v", err)
	}
	broadDir := t.TempDir()
	winBroaden(t, broadDir)
	broad := filepath.Join(broadDir, "host.json")
	if err := os.WriteFile(broad, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := readPrivateSuiteSessionsHost(broad); !errors.Is(err, errSuiteSessionsHost) {
		t.Fatalf("broad host parent = %v", err)
	}
}
