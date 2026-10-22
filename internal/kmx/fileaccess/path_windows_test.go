//go:build windows

package fileaccess

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsPathForms(t *testing.T) {
	root := currentVolumeRoot(t)
	drive := root[:2]
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	cwd, err := parseLocalPath(wd)
	if err != nil {
		t.Fatal(err)
	}
	valid := []struct{ input, want string }{
		{drive + `\`, strings.ToUpper(drive) + `\`},
		{strings.ToLower(drive) + `/Users/x`, strings.ToUpper(drive) + `\Users\x`},
		{`\\?\` + drive + `\Users\x`, strings.ToUpper(drive) + `\Users\x`},
		{`relative\child`, cwd.String() + `\relative\child`},
	}
	for _, tc := range valid {
		got, err := parseLocalPath(tc.input)
		if err != nil || got.String() != tc.want {
			t.Errorf("parseLocalPath(%q) = %q, %v; want %q", tc.input, got.String(), err, tc.want)
		}
	}
	unsafePaths := []string{
		"", drive + "\\a\x00b", drive + `\\`, `.`, `..`, `a\.\b`, `a\..\b`, `a\\b`,
		drive + `\a:b`, drive + `\data:stream:$DATA`, drive + `\name.`, drive + `\name `,
		drive + `\CON`, drive + `\nul.txt`, drive + `\COM1`, drive + `\conin$`,
	}
	for _, input := range unsafePaths {
		if got, err := parseLocalPath(input); !errors.Is(err, ErrUnsafe) {
			t.Errorf("parseLocalPath(%q) = %q, %v; want unsafe", input, got.String(), err)
		}
	}
	unsupportedPaths := []string{
		`\\server\share\x`, `//server/share/x`, `\\.\PhysicalDrive0`,
		`\\?\UNC\server\share\x`, `\\?\GLOBALROOT\Device\Null`, `\??\` + drive + `\x`,
		drive, drive + `relative`, `\Windows`, `/Windows`,
	}
	for _, input := range unsupportedPaths {
		if got, err := parseLocalPath(input); !errors.Is(err, ErrUnsupported) {
			t.Errorf("parseLocalPath(%q) = %q, %v; want unsupported", input, got.String(), err)
		}
	}
}

func TestWindowsNTStatusClassification(t *testing.T) {
	for _, status := range []windows.NTStatus{
		windows.STATUS_OBJECT_TYPE_MISMATCH,
		windows.STATUS_FILE_IS_A_DIRECTORY,
		windows.STATUS_NOT_A_DIRECTORY,
		windows.STATUS_REPARSE_POINT_ENCOUNTERED,
	} {
		if err := normalizeNTStatus(status); !errors.Is(err, ErrUnsafe) {
			t.Errorf("normalizeNTStatus(%v) = %v, want unsafe", status, err)
		}
	}
	for _, status := range []windows.NTStatus{windows.STATUS_OBJECT_NAME_NOT_FOUND, windows.STATUS_OBJECT_PATH_NOT_FOUND} {
		if err := normalizeNTStatus(status); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("normalizeNTStatus(%v) = %v, want not-exist", status, err)
		}
	}
}

func TestWindowsVolumeRootAliases(t *testing.T) {
	root := currentVolumeRoot(t)
	for _, path := range []string{root, strings.ToLower(root), strings.ReplaceAll(root, `\`, `/`), `\\?\` + root} {
		opened, err := OpenDirectory(t.Context(), path)
		if err != nil {
			t.Fatalf("OpenDirectory(%q): %v", path, err)
		}
		requireSameFile(t, opened, root)
		opened.Close()
	}
	if _, err := OpenDirectory(t.Context(), filepath.VolumeName(root)); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("drive-relative path = %v", err)
	}
}
