//go:build linux

package fileaccess

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	mountInfoPath     = "/proc/self/mountinfo"
	maxMountInfoBytes = 16 << 20
	maxSymlinkHops    = 40
)

type windowsDriveMountError struct{ path string }

func (e *windowsDriveMountError) Error() string {
	return fmt.Sprintf("%q is on a Windows drive mount; use a Linux path or run native Windows kmx", e.path)
}

func (e *windowsDriveMountError) Is(target error) bool { return target == ErrWindowsDriveMount }

// RefuseWindowsDriveMount refuses a KMX state, cache or output path whose
// effective filesystem is a WSL Windows drive (drvfs, including 9p with
// aname=drvfs or a Windows drive source). A nonexistent path is judged by the
// mount of its nearest existing ancestor after resolving symlinks, so the
// refusal happens before anything is created. It inspects metadata only and
// is meant for one call per state/cache/output boundary; read-only inputs and
// Windows tools are not its concern. Failure to inspect is an error, never a
// clean result.
func RefuseWindowsDriveMount(path string) error {
	return refuseWindowsDriveMount(path, mountInfoPath)
}

func refuseWindowsDriveMount(path, mountInfo string) error {
	fail := func(err error) error {
		return fmt.Errorf("cannot check whether %q is on a Windows drive mount: %w", path, err)
	}
	if path == "" {
		return fail(errors.New("empty path"))
	}
	resolved, err := nearestExistingPath(path)
	if err != nil {
		return fail(err)
	}
	var st unix.Stat_t
	if err := unix.Stat(resolved, &st); err != nil {
		return fail(&fs.PathError{Op: "stat", Path: resolved, Err: err})
	}
	raw, err := readBounded(mountInfo, maxMountInfoBytes)
	if err != nil {
		return fail(err)
	}
	mounts, err := parseMountInfo(raw)
	if err != nil {
		return fail(err)
	}
	drive, err := onWindowsDrive(mounts, resolved, unix.Major(st.Dev), unix.Minor(st.Dev))
	if err != nil {
		return fail(err)
	}
	if drive {
		return &windowsDriveMountError{path: path}
	}
	return nil
}

// nearestExistingPath returns the symlink-resolved nearest existing ancestor
// of path. Dangling links are followed textually, because writing through
// one creates its target.
func nearestExistingPath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	for hops := 0; ; {
		p := abs
	walk:
		for {
			info, err := os.Lstat(p)
			switch {
			case err == nil && info.Mode()&fs.ModeSymlink == 0:
				return filepath.EvalSymlinks(p)
			case err == nil:
				resolved, err := filepath.EvalSymlinks(p)
				if err == nil {
					return resolved, nil
				}
				if !errors.Is(err, fs.ErrNotExist) {
					return "", err
				}
				if hops++; hops > maxSymlinkHops {
					return "", &fs.PathError{Op: "resolve", Path: path, Err: syscall.ELOOP}
				}
				target, err := os.Readlink(p)
				if err != nil {
					return "", err
				}
				if !filepath.IsAbs(target) {
					parent, err := filepath.EvalSymlinks(filepath.Dir(p))
					if err != nil {
						return "", err
					}
					target = filepath.Join(parent, target)
				}
				rest, err := filepath.Rel(p, abs)
				if err != nil {
					return "", err
				}
				abs = filepath.Join(target, rest)
				break walk
			case errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR):
				parent := filepath.Dir(p)
				if parent == p {
					return "", err
				}
				p = parent
			default:
				return "", err
			}
		}
	}
}

func readBounded(path string, limit int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > limit {
		return nil, fmt.Errorf("%s exceeds %d bytes", path, limit)
	}
	return raw, nil
}

type mountEntry struct {
	major, minor                             uint32
	mountPoint, fsType, source, superOptions string
}

// parseMountInfo reads proc(5) mountinfo lines:
// id parent major:minor root mountpoint options [optional...] - fstype source superoptions.
func parseMountInfo(raw []byte) ([]mountEntry, error) {
	var mounts []mountEntry
	for n, line := range bytes.Split(raw, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		bad := func(why string) error { return fmt.Errorf("mountinfo line %d: %s", n+1, why) }
		fields := strings.Split(string(line), " ")
		sep := -1
		for i := 6; i < len(fields); i++ {
			if fields[i] == "-" {
				sep = i
				break
			}
		}
		if sep < 0 || len(fields) != sep+4 {
			return nil, bad("unexpected field layout")
		}
		majorText, minorText, ok := strings.Cut(fields[2], ":")
		major, errMajor := strconv.ParseUint(majorText, 10, 32)
		minor, errMinor := strconv.ParseUint(minorText, 10, 32)
		if !ok || errMajor != nil || errMinor != nil {
			return nil, bad("invalid device")
		}
		var decoded [3]string
		for i, field := range []string{fields[4], fields[sep+2], fields[sep+3]} {
			value, err := unescapeMountField(field)
			if err != nil {
				return nil, bad(err.Error())
			}
			decoded[i] = value
		}
		if !strings.HasPrefix(decoded[0], "/") {
			return nil, bad("relative mount point")
		}
		mounts = append(mounts, mountEntry{
			major: uint32(major), minor: uint32(minor),
			mountPoint: decoded[0], fsType: fields[sep+1], source: decoded[1], superOptions: decoded[2],
		})
	}
	if len(mounts) == 0 {
		return nil, errors.New("mountinfo has no entries")
	}
	return mounts, nil
}

// unescapeMountField decodes the kernel's \ooo escapes (space, tab, newline
// and backslash). Other backslashes, such as those in drvfs options, are
// literal.
func unescapeMountField(s string) (string, error) {
	if !strings.Contains(s, `\`) {
		return s, nil
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) || !isOctal(s[i+1]) {
			b.WriteByte(s[i])
			continue
		}
		if i+3 >= len(s) || !isOctal(s[i+2]) || !isOctal(s[i+3]) {
			return "", errors.New("invalid escape")
		}
		v, err := strconv.ParseUint(s[i+1:i+4], 8, 8)
		if err != nil {
			return "", errors.New("invalid escape")
		}
		b.WriteByte(byte(v))
		i += 3
	}
	return b.String(), nil
}

func isOctal(c byte) bool { return c >= '0' && c <= '7' }

// windowsDrive recognizes only observed WSL drive mounts: legacy drvfs, and
// 9p carrying aname=drvfs or a Windows drive/UNC source. Other 9p shares,
// such as the read-only /usr/lib/wsl/drivers, and unknown filesystems are
// not guessed to be Windows drives.
func (m mountEntry) windowsDrive() bool {
	switch m.fsType {
	case "drvfs":
		return true
	case "9p":
		if windowsDriveSource(m.source) {
			return true
		}
		for _, opt := range strings.FieldsFunc(m.superOptions, func(r rune) bool { return r == ',' || r == ';' }) {
			if opt == "aname=drvfs" {
				return true
			}
		}
	}
	return false
}

func windowsDriveSource(s string) bool {
	if strings.HasPrefix(s, `\\`) {
		return true
	}
	if len(s) < 2 || s[1] != ':' || !(s[0] >= 'A' && s[0] <= 'Z' || s[0] >= 'a' && s[0] <= 'z') {
		return false
	}
	return len(s) == 2 || s[2] == '\\' || s[2] == '/'
}

// onWindowsDrive reports whether resolved (an existing, symlink-free path
// with the given device) lies on a Windows drive. Either signal suffices: a
// mount entry with the same device, or the deepest (latest, for stacked
// mounts) mount point containing the path.
func onWindowsDrive(mounts []mountEntry, resolved string, major, minor uint32) (bool, error) {
	var best *mountEntry
	for i := range mounts {
		m := &mounts[i]
		if m.major == major && m.minor == minor && m.windowsDrive() {
			return true, nil
		}
		if containsPath(m.mountPoint, resolved) && (best == nil || len(m.mountPoint) >= len(best.mountPoint)) {
			best = m
		}
	}
	if best == nil {
		return false, fmt.Errorf("no mount entry covers %s", resolved)
	}
	return best.windowsDrive(), nil
}

func containsPath(mountPoint, path string) bool {
	return mountPoint == "/" || path == mountPoint || strings.HasPrefix(path, mountPoint+"/")
}
