package toolchain

import (
	"archive/zip"
	"bytes"
	"hash/crc32"
	"os"
	"strings"
	"testing"
)

const zipMember = "windows-amd64/helm.exe"

// rawZip writes entries exactly as given — sizes, CRC and flags included —
// so the reader is confronted with what a hostile or damaged archive says.
func rawZip(t *testing.T, headers []*zip.FileHeader, bodies [][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for i, header := range headers {
		w, err := zw.CreateRaw(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(bodies[i]); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func storedHeader(name string, body []byte) *zip.FileHeader {
	header := &zip.FileHeader{
		Name:               name,
		Method:             zip.Store,
		CRC32:              crc32.ChecksumIEEE(body),
		CompressedSize64:   uint64(len(body)),
		UncompressedSize64: uint64(len(body)),
	}
	header.SetMode(0o755)
	return header
}

func TestZipMemberExtractsExactlyTheNamedRegularFile(t *testing.T) {
	want := []byte("MZ helm")
	archive := zipOf(t,
		zipEntry{name: "windows-amd64/", mode: os.ModeDir | 0o755},
		zipEntry{name: "windows-amd64/LICENSE", body: []byte("license")},
		zipEntry{name: zipMember, body: want},
		zipEntry{name: "windows-amd64/helm.exe.sig", body: []byte("not this")})
	got, err := zipMemberOf(archive, zipMember)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("extracted %q, want %q", got, want)
	}
	empty, err := zipMemberOf(zipOf(t, zipEntry{name: zipMember}), zipMember)
	if err != nil || len(empty) != 0 {
		t.Fatalf("an empty regular member: %q, %v", empty, err)
	}
}

// Every way a zip can make "the bytes of windows-amd64/helm.exe" ambiguous,
// redirected, special, oversized or short is refused — never resolved by
// picking one, following it, or installing a truncated binary.
func TestZipMemberRefusesUnsafeArchives(t *testing.T) {
	body := []byte("MZ helm")
	symlink := storedHeader(zipMember, []byte("../../evil"))
	symlink.SetMode(os.ModeSymlink | 0o777)
	pipe := storedHeader(zipMember, nil)
	pipe.SetMode(os.ModeNamedPipe | 0o644)
	device := storedHeader(zipMember, nil)
	device.SetMode(os.ModeDevice | 0o644)
	oversize := storedHeader(zipMember, body)
	oversize.UncompressedSize64 = maxBinarySize + 1
	truncated := storedHeader(zipMember, body)
	truncated.UncompressedSize64 = uint64(len(body)) + 16
	badCRC := storedHeader(zipMember, body)
	badCRC.CRC32++
	encrypted := storedHeader(zipMember, body)
	encrypted.Flags |= 0x1
	whole := zipOf(t, zipEntry{name: zipMember, body: body})

	for _, tc := range []struct {
		name    string
		archive []byte
		want    string
	}{
		{"missing", zipOf(t, zipEntry{name: "windows-amd64/LICENSE", body: body}), "does not contain"},
		{"duplicate", zipOf(t, zipEntry{name: zipMember, body: body}, zipEntry{name: zipMember, body: []byte("MZ other")}), "more than one"},
		{"case variant", zipOf(t, zipEntry{name: zipMember, body: body}, zipEntry{name: strings.ToUpper(zipMember), body: []byte("MZ other")}), "more than one"},
		{"directory", zipOf(t, zipEntry{name: zipMember + "/", mode: os.ModeDir | 0o755}), "does not contain"},
		{"directory named as member", rawZip(t, []*zip.FileHeader{func() *zip.FileHeader {
			h := storedHeader(zipMember, nil)
			h.SetMode(os.ModeDir | 0o755)
			return h
		}()}, [][]byte{nil}), "not a regular file"},
		{"symlink", rawZip(t, []*zip.FileHeader{symlink}, [][]byte{[]byte("../../evil")}), "not a regular file"},
		{"named pipe", rawZip(t, []*zip.FileHeader{pipe}, [][]byte{nil}), "not a regular file"},
		{"device", rawZip(t, []*zip.FileHeader{device}, [][]byte{nil}), "not a regular file"},
		{"parent traversal", zipOf(t, zipEntry{name: "../evil.exe", body: body}, zipEntry{name: zipMember, body: body}), "unsafe name"},
		{"nested traversal", zipOf(t, zipEntry{name: "windows-amd64/../../evil.exe", body: body}, zipEntry{name: zipMember, body: body}), "unsafe name"},
		{"absolute", zipOf(t, zipEntry{name: "/evil.exe", body: body}, zipEntry{name: zipMember, body: body}), "unsafe name"},
		{"backslash", zipOf(t, zipEntry{name: `windows-amd64\helm.exe`, body: body}, zipEntry{name: zipMember, body: body}), "unsafe name"},
		{"drive", zipOf(t, zipEntry{name: "C:evil.exe", body: body}, zipEntry{name: zipMember, body: body}), "unsafe name"},
		{"stream", zipOf(t, zipEntry{name: zipMember + ":stream", body: body}, zipEntry{name: zipMember, body: body}), "unsafe name"},
		{"dot component", zipOf(t, zipEntry{name: "windows-amd64/./helm.exe", body: body}), "unsafe name"},
		{"empty component", zipOf(t, zipEntry{name: "windows-amd64//helm.exe", body: body}), "unsafe name"},
		{"nul", zipOf(t, zipEntry{name: "windows-amd64/helm.exe\x00.txt", body: body}, zipEntry{name: zipMember, body: body}), "unsafe name"},
		{"oversize", rawZip(t, []*zip.FileHeader{oversize}, [][]byte{body}), "larger than"},
		{"truncated member", rawZip(t, []*zip.FileHeader{truncated}, [][]byte{body}), "cannot read"},
		{"crc mismatch", rawZip(t, []*zip.FileHeader{badCRC}, [][]byte{body}), "cannot read"},
		{"encrypted", rawZip(t, []*zip.FileHeader{encrypted}, [][]byte{body}), "encrypted"},
		{"truncated archive", whole[:len(whole)-10], "cannot read the downloaded archive"},
		{"not a zip", []byte("MZ this is not an archive"), "cannot read the downloaded archive"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := zipMemberOf(tc.archive, zipMember)
			if err == nil {
				t.Fatalf("accepted %q", got)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not say %q", err, tc.want)
			}
		})
	}
}

// Windows names its cached binaries and managed commands .exe; every other
// platform keeps exactly the names it had.
func TestManagedFileNames(t *testing.T) {
	for _, tc := range []struct{ goos, goarch, cache, alias string }{
		{"linux", "amd64", "kind-0.33.0-linux-amd64", "kind"},
		{"darwin", "arm64", "kind-0.33.0-darwin-arm64", "kind"},
		{"windows", "amd64", "kind-0.33.0-windows-amd64.exe", "kind.exe"},
		{"windows", "arm64", "kind-0.33.0-windows-arm64.exe", "kind.exe"},
	} {
		if got := cacheFileName("kind", "0.33.0", tc.goos, tc.goarch); got != tc.cache {
			t.Errorf("%s/%s cache name %q, want %q", tc.goos, tc.goarch, got, tc.cache)
		}
		if got := aliasFileName("kind", tc.goos); got != tc.alias {
			t.Errorf("%s alias name %q, want %q", tc.goos, got, tc.alias)
		}
	}
}

// Only a .zip asset is parsed as a zip; everything else keeps the existing
// tar.gz extraction.
func TestArchiveFormatFollowsTheAssetName(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows"} {
		spec, _ := Pinned("helm", goos, "amd64")
		if got, want := isZipAsset(spec), goos == "windows"; got != want {
			t.Errorf("%s: zip=%v, want %v (%s)", goos, got, want, spec.URL)
		}
	}
}
