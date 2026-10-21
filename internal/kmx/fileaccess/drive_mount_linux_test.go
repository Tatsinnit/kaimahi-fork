//go:build linux

package fileaccess

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Lines observed verbatim in this repository's WSL2 host /proc/self/mountinfo,
// plus a legacy drvfs entry and a Linux root.
const observedMountInfo = `70 50 8:48 / / rw,relatime - ext4 /dev/sdd rw,discard,errors=remount-ro,data=ordered
62 70 0:36 / /usr/lib/wsl/drivers ro,nosuid,nodev,noatime - 9p drivers ro,aname=drivers;fmask=222;dmask=222,cache=0x5,access=client,msize=65536,trans=fd,rfd=8,wfd=8
88 70 0:55 / /mnt/c rw,noatime - 9p C:\134 rw,aname=drvfs;path=C:\;uid=1000;gid=1000;symlinkroot=/mnt/,cache=0x5,access=client,msize=65536,trans=fd,rfd=6,wfd=6
90 70 0:57 / /mnt/d rw,noatime - drvfs D:\134 rw,uid=1000,gid=1000
91 70 0:58 / /srv/export rw,relatime shared:3 master:1 - 9p export rw,trans=virtio,version=9p2000.L
`

func TestParseMountInfoClassifiesObservedWSLMounts(t *testing.T) {
	mounts, err := parseMountInfo([]byte(observedMountInfo))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"/":                    false,
		"/usr/lib/wsl/drivers": false, // read-only WSL driver share must stay allowed
		"/mnt/c":               true,
		"/mnt/d":               true,
		"/srv/export":          false, // unrelated 9p export
	}
	if len(mounts) != len(want) {
		t.Fatalf("parsed %d mounts, want %d: %+v", len(mounts), len(want), mounts)
	}
	for _, m := range mounts {
		drive, ok := want[m.mountPoint]
		if !ok {
			t.Fatalf("unexpected mount point %q", m.mountPoint)
		}
		if m.windowsDrive() != drive {
			t.Errorf("%s (%s %q %q): windowsDrive=%v, want %v", m.mountPoint, m.fsType, m.source, m.superOptions, !drive, drive)
		}
	}
	if mounts[2].source != `C:\` || mounts[2].major != 0 || mounts[2].minor != 55 {
		t.Fatalf("escaped source/device not decoded: %+v", mounts[2])
	}
}

func TestWindowsDriveRecognitionIsNarrow(t *testing.T) {
	for _, tc := range []struct {
		fsType, source, options string
		want                    bool
	}{
		{"drvfs", "C:", "rw", true},
		{"9p", `E:\`, "rw,trans=fd", true},                // Windows drive source alone
		{"9p", "drvfs", "rw,aname=drvfs;path=Z:\\", true}, // aname alone
		{"9p", `\\server\share`, "rw,trans=fd", true},     // network drive through drvfs
		{"9p", "drivers", "ro,aname=drivers", false},
		{"9p", "rootfs", "rw,trans=virtio", false},
		{"9p", "C", "rw,aname=drvfsx", false},
		{"ext4", `C:\`, "rw", false},
		{"virtiofs", "C:", "rw", false}, // unobserved; not guessed
		{"nfs", "server:/c", "rw", false},
	} {
		m := mountEntry{fsType: tc.fsType, source: tc.source, superOptions: tc.options}
		if got := m.windowsDrive(); got != tc.want {
			t.Errorf("%s %q %q = %v, want %v", tc.fsType, tc.source, tc.options, got, tc.want)
		}
	}
}

func TestParseMountInfoRejectsMalformedInput(t *testing.T) {
	for name, raw := range map[string]string{
		"empty":            "",
		"no separator":     "1 0 8:1 / / rw ext4 /dev/sda rw\n",
		"short":            "1 0 8:1 / / - ext4\n",
		"too many after -": "1 0 8:1 / / rw - ext4 /dev/sda rw extra\n",
		"bad device":       "1 0 81 / / rw - ext4 /dev/sda rw\n",
		"relative mount":   "1 0 8:1 / mnt rw - ext4 /dev/sda rw\n",
		"bad escape":       "1 0 8:1 / /mnt/\\12x rw - ext4 /dev/sda rw\n",
		"escape overflow":  "1 0 8:1 / /mnt/\\777 rw - ext4 /dev/sda rw\n",
	} {
		if _, err := parseMountInfo([]byte(raw)); err == nil {
			t.Errorf("%s: malformed mountinfo accepted", name)
		}
	}
}

func TestMountSelectionUsesDeepestLatestAndDevice(t *testing.T) {
	raw := `1 0 8:1 / / rw - ext4 /dev/sda rw
2 1 0:55 / /mnt/c rw - 9p C:\134 rw,aname=drvfs;path=C:\
3 2 8:2 / /mnt/c/linux rw - ext4 /dev/sdb rw
4 1 8:3 / /mnt/over rw - ext4 /dev/sdc rw
5 1 0:56 / /mnt/over rw - 9p D:\134 rw,aname=drvfs;path=D:\
6 1 0:57 / /mnt/my\040drive\134x rw - drvfs E:\134 rw
7 1 0:55 /Users /home/me/winbind rw - 9p C:\134 rw,aname=drvfs;path=C:\
`
	mounts, err := parseMountInfo([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path         string
		major, minor uint32
		want         bool
	}{
		{"/home/me/work", 8, 1, false},
		{"/mnt/c", 0, 55, true},
		{"/mnt/c/Users/me", 0, 55, true},
		{"/mnt/c/linux/out", 8, 2, false},  // nested Linux mount below a drive
		{"/mnt/cc", 8, 1, false},           // prefix of a name is not a parent
		{"/mnt/over/x", 0, 56, true},       // later mount over the same point wins
		{`/mnt/my drive\x/y`, 0, 57, true}, // escaped space and backslash
		{"/home/me/winbind/kmx", 0, 55, true},
		{"/elsewhere", 0, 55, true}, // device identity alone identifies the drive
	} {
		got, err := onWindowsDrive(mounts, tc.path, tc.major, tc.minor)
		if err != nil || got != tc.want {
			t.Errorf("%s: got %v, %v; want %v", tc.path, got, err, tc.want)
		}
	}
	if _, err := onWindowsDrive(mounts[1:2], "/home", 8, 1); err == nil {
		t.Fatal("uncovered path reported clean")
	}
}

// fixtureMountInfo writes a mountinfo whose root is an unrelated device and
// which mounts a Windows drive at driveDir, so path resolution is exercised
// on real temporary directories without mounting anything.
func fixtureMountInfo(t *testing.T, driveDir string, extra string) string {
	t.Helper()
	escape := strings.NewReplacer(`\`, `\134`, " ", `\040`, "\t", `\011`, "\n", `\012`)
	raw := "1 0 254:254 / / rw - ext4 /dev/fixture rw\n" +
		"2 1 254:253 / " + escape.Replace(driveDir) + " rw - 9p C:\\134 rw,aname=drvfs;path=C:\\;uid=1000\n" + extra
	path := filepath.Join(t.TempDir(), "mountinfo")
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func evalTempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func assertDriveRefusal(t *testing.T, err error, path string) {
	t.Helper()
	if !errors.Is(err, ErrWindowsDriveMount) {
		t.Fatalf("%s: got %v, want Windows drive refusal", path, err)
	}
	msg := err.Error()
	if !strings.Contains(msg, strconv.Quote(path)) || !strings.Contains(msg, "Linux path") || !strings.Contains(msg, "native Windows kmx") {
		t.Fatalf("refusal must name %q and the remedy: %q", path, msg)
	}
}

func TestRefuseWindowsDriveMountResolvesNonexistentAndLinkedPaths(t *testing.T) {
	base := evalTempDir(t)
	drive := filepath.Join(base, `win drive\x`)
	linux := filepath.Join(base, "linux")
	for _, dir := range []string{drive, linux, filepath.Join(drive, "nested")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	mountinfo := fixtureMountInfo(t, drive,
		"3 2 254:252 / "+strings.ReplaceAll(strings.ReplaceAll(filepath.Join(drive, "nested"), `\`, `\134`), " ", `\040`)+" rw - ext4 /dev/nested rw\n")
	if err := os.Symlink(drive, filepath.Join(base, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(drive, "missing", "dir"), filepath.Join(base, "dangling")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(`win drive\x/missing`, filepath.Join(base, "relative")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("chain", filepath.Join(base, "loop")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("loop", filepath.Join(base, "chain")); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{
		drive,
		filepath.Join(drive, "kmx", "state", "out"),
		filepath.Join(base, "link", "kmx"),
		filepath.Join(base, "dangling", "out"),
		filepath.Join(base, "dangling"),
		filepath.Join(base, "relative", "a", "b"),
	} {
		assertDriveRefusal(t, refuseWindowsDriveMount(path, mountinfo), path)
	}
	if _, err := os.Lstat(filepath.Join(drive, "kmx")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("guard created output: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(drive, "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("guard created symlink target: %v", err)
	}
	for _, path := range []string{
		linux,
		filepath.Join(linux, "missing", "out"),
		filepath.Join(drive, "nested", "out"),
	} {
		if err := refuseWindowsDriveMount(path, mountinfo); err != nil {
			t.Errorf("%s: unexpected refusal %v", path, err)
		}
	}
	if err := refuseWindowsDriveMount(filepath.Join(base, "loop", "out"), mountinfo); err == nil || errors.Is(err, ErrWindowsDriveMount) {
		t.Fatalf("symlink loop must be an inspection error, got %v", err)
	}
}

func TestRefuseWindowsDriveMountReportsInspectionFailures(t *testing.T) {
	base := evalTempDir(t)
	oversize := filepath.Join(base, "oversize")
	if err := os.WriteFile(oversize, []byte(strings.Repeat("x", maxMountInfoBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	uncovered := filepath.Join(base, "uncovered")
	if err := os.WriteFile(uncovered, []byte("1 0 0:1 / /nowhere rw - tmpfs none rw\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, mountinfo := range map[string]string{
		"missing":   filepath.Join(base, "absent"),
		"oversize":  oversize,
		"uncovered": uncovered,
	} {
		err := refuseWindowsDriveMount(filepath.Join(base, "out"), mountinfo)
		if err == nil || errors.Is(err, ErrWindowsDriveMount) || !strings.Contains(err.Error(), "cannot check") {
			t.Errorf("%s: inspection failure reported as %v", name, err)
		}
	}
	if err := RefuseWindowsDriveMount(""); err == nil {
		t.Fatal("empty path accepted")
	}
}

// The live test exercises the real kernel table. A host without a Windows
// drive mount says so in -v output; that is not evidence of refusal.
func TestRefuseWindowsDriveMountLiveHost(t *testing.T) {
	raw, err := os.ReadFile(mountInfoPath)
	if err != nil {
		t.Fatal(err)
	}
	mounts, err := parseMountInfo(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := RefuseWindowsDriveMount(t.TempDir()); err != nil {
		t.Fatalf("Linux temp dir refused: %v", err)
	}
	checkedOther := false
	for _, m := range mounts {
		if m.fsType == "9p" && !m.windowsDrive() {
			if _, err := os.Stat(m.mountPoint); err == nil {
				if err := RefuseWindowsDriveMount(m.mountPoint); err != nil {
					t.Errorf("unrelated 9p mount %s refused: %v", m.mountPoint, err)
				} else {
					t.Logf("LIVE: unrelated 9p mount %s (source %q) allowed", m.mountPoint, m.source)
				}
				checkedOther = true
			}
		}
	}
	if !checkedOther {
		t.Log("LIVE GAP: no unrelated 9p mount present; drivers-share allowance checked by fixtures only")
	}
	var drive string
	for _, m := range mounts {
		if info, err := os.Stat(m.mountPoint); m.windowsDrive() && err == nil && info.IsDir() {
			drive = m.mountPoint
			break
		}
	}
	if drive == "" {
		t.Skip("LIVE GAP: no Windows drive mount on this host; live refusal not exercised")
	}
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	owned := filepath.Join(drive, "kmx-w462-guard-"+hex.EncodeToString(nonce))
	target := filepath.Join(owned, "state", "out")
	assertDriveRefusal(t, RefuseWindowsDriveMount(target), target)
	link := filepath.Join(t.TempDir(), "to-windows")
	if err := os.Symlink(owned, link); err != nil {
		t.Fatal(err)
	}
	assertDriveRefusal(t, RefuseWindowsDriveMount(filepath.Join(link, "out")), filepath.Join(link, "out"))
	if _, err := os.Lstat(owned); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("guard created %s: %v", owned, err)
	}
	t.Logf("LIVE: refused nonexistent %s on %s without creating it", target, drive)
}
