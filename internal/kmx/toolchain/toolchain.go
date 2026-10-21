// Package toolchain fetches the external binaries kmx shells out to, pinned
// and checksum-verified, so that a machine with a container engine and
// nothing else can still run the journey.
//
// This began as the fetcher for one pinned CLI, generalised. That package
// already had to solve the whole problem for a single tool — a kmx installed with
// `go install` or downloaded from a release has no checkout to put a binary
// in, so the binary is cached, keyed by version and platform, and re-verified
// on every use rather than only when it was downloaded. The same reasoning
// applies to kind and kubectl, which is why the prerequisite list could be
// several items long: kmx knew how to fetch exactly one of the things it
// needs.
//
// Two rules that path established, kept here because they are the whole
// value of the mechanism:
//
//   - A CACHE HIT IS RE-VERIFIED. "Checksum-verified" has to mean the bytes
//     about to be executed, not the bytes that were fetched some other day.
//     Anything with write access to the cache could otherwise substitute a
//     binary that then runs with the operator's kubeconfig.
//   - A MISMATCH LEAVES NOTHING BEHIND. A rejected download must not be
//     sitting in the cache when the next run looks.
//
// What is deliberately NOT claimed: this is TLS trust in the publisher's own
// download host, not an independent signature. The digest and the bytes come
// from the same origin, so a compromised origin defeats both. It buys
// integrity against a corrupted or truncated transfer and against a tampered
// cache.
package toolchain

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/kaimahi-agents/kaimahi/internal/kmx/fileaccess"
)

// Pinned versions. They are pins rather than "latest" for the reason every
// other version in this repository is pinned: a journey that silently changes
// underneath an operator is not reproducible, and a first run is exactly when
// nobody can tell a new upstream bug from their own mistake.
const (
	KubectlVersion = "1.37.0"
	KindVersion    = "0.33.0"
	HelmVersion    = "3.20.0"
)

// Spec is one fetchable binary.
type Spec struct {
	// Name is the command name, as it appears on PATH.
	Name string
	// Version is the pinned upstream version, without a leading "v".
	Version string
	// URL is what gets downloaded: the binary itself, or an archive when
	// ArchiveMember is set.
	URL string
	// ChecksumURL serves a line whose FIRST field is the sha256 of the bytes
	// at URL. Every upstream here publishes that file; the rest of the line
	// is the publisher's own build path and is not ours to trust.
	ChecksumURL string
	// ArchiveMember, when set, is the path inside a .tar.gz — or a .zip, when
	// URL names one — whose bytes are the binary. The published digest covers
	// the ARCHIVE, so the archive is what gets verified, before anything is
	// extracted from it.
	//
	// Helm uses this: verify what the publisher checksummed before extraction.
	ArchiveMember string
	// Why is the one-line reason this tool is needed, for the fetch line.
	Why string
}

// Platform returns the os/arch pair the upstreams name their assets with.
// Go's GOOS/GOARCH values are already the normalized names all three use.
func Platform() (string, string) { return runtime.GOOS, runtime.GOARCH }

// Pinned returns the spec for one of the tools kmx can fetch. The second
// return is false for anything else — a container engine, notably, which is a
// daemon and a system package rather than a binary that can be dropped into a
// cache directory.
//
// Windows assets differ in shape, as published: kubectl is kubectl.exe, Helm
// is a .zip holding helm.exe, and kind ships only a windows/amd64 binary (no
// extension in its asset name). There is no pinned kind for windows/arm64 —
// substituting the amd64 build would be a guess, so that operator supplies
// their own kind on PATH.
func Pinned(name, goos, goarch string) (Spec, bool) {
	switch name {
	case "kubectl":
		binary := "kubectl"
		if goos == "windows" {
			binary = "kubectl.exe"
		}
		return Spec{
			Name:        "kubectl",
			Version:     KubectlVersion,
			URL:         fmt.Sprintf("https://dl.k8s.io/release/v%s/bin/%s/%s/%s", KubectlVersion, goos, goarch, binary),
			ChecksumURL: fmt.Sprintf("https://dl.k8s.io/release/v%s/bin/%s/%s/%s.sha256", KubectlVersion, goos, goarch, binary),
			Why:         "to read and write Kubernetes resources",
		}, true
	case "kind":
		if goos == "windows" && goarch != "amd64" {
			return Spec{}, false
		}
		return Spec{
			Name:        "kind",
			Version:     KindVersion,
			URL:         fmt.Sprintf("https://github.com/kubernetes-sigs/kind/releases/download/v%s/kind-%s-%s", KindVersion, goos, goarch),
			ChecksumURL: fmt.Sprintf("https://github.com/kubernetes-sigs/kind/releases/download/v%s/kind-%s-%s.sha256sum", KindVersion, goos, goarch),
			Why:         "to manage the local Kubernetes cluster",
		}, true
	case "helm":
		archive, member := "tar.gz", fmt.Sprintf("%s-%s/helm", goos, goarch)
		if goos == "windows" {
			archive, member = "zip", member+".exe"
		}
		return Spec{
			Name:          "helm",
			Version:       HelmVersion,
			URL:           fmt.Sprintf("https://get.helm.sh/helm-v%s-%s-%s.%s", HelmVersion, goos, goarch, archive),
			ChecksumURL:   fmt.Sprintf("https://get.helm.sh/helm-v%s-%s-%s.%s.sha256sum", HelmVersion, goos, goarch, archive),
			ArchiveMember: member,
			Why:           "to install Orka from its Helm chart",
		}, true
	}
	return Spec{}, false
}

// Fetchable lists the tools Pinned knows, in the order an operator meets them.
var Fetchable = []string{"kind", "kubectl", "helm"}

// ExpectedDigest extracts the digest from a published checksum file.
//
// The file is `<digest>[  <path>]`, and the path is the PUBLISHER's, not
// anything on this machine — so only the first field may be trusted, and a
// file that does not start with a 64-character hex digest is refused rather
// than compared loosely. kubectl publishes the bare digest with no path at
// all, which is the same rule with one field.
func ExpectedDigest(checksumFile []byte) (string, error) {
	fields := strings.Fields(string(checksumFile))
	if len(fields) == 0 {
		return "", fmt.Errorf("checksum file is empty")
	}
	digest := strings.ToLower(fields[0])
	if len(digest) != 64 {
		return "", fmt.Errorf("checksum file does not begin with a sha256 digest")
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return "", fmt.Errorf("checksum file does not begin with a sha256 digest")
	}
	return digest, nil
}

// Verify fails closed when bytes do not match a published digest.
func Verify(what string, payload, checksumFile []byte) error {
	want, err := ExpectedDigest(checksumFile)
	if err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	sum := sha256.Sum256(payload)
	if got := hex.EncodeToString(sum[:]); got != want {
		return fmt.Errorf("%s checksum mismatch: got %s, want %s", what, got, want)
	}
	return nil
}

// Options configure a fetch.
type Options struct {
	CacheDir string
	// Log receives one line when a download actually happens. Fetching a
	// binary onto someone's machine is not something to do silently.
	Log io.Writer
	// BaseOverride replaces the scheme+host of both URLs (tests).
	BaseOverride string
}

func digest(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// maxBinarySize bounds any one executable read out of an archive or out of
// the Windows cache: a preposterous size must not exhaust memory on the way
// to being rejected.
const maxBinarySize = 512 << 20

// CachePath is where a spec's binary lives once fetched. The version is in
// the name, so bumping a pin can never be served the previous version.
func (s Spec) CachePath(cacheDir string) string {
	goos, goarch := Platform()
	return filepath.Join(cacheDir, cacheFileName(s.Name, s.Version, goos, goarch))
}

// cacheFileName carries .exe on Windows, where only an executable extension
// makes a file runnable; other platforms keep the historical name.
func cacheFileName(name, version, goos, goarch string) string {
	file := fmt.Sprintf("%s-%s-%s-%s", name, version, goos, goarch)
	if goos == "windows" {
		file += ".exe"
	}
	return file
}

// aliasFileName is the plain command name published in the managed command
// directory: <name>.exe on Windows, so exec.LookPath resolves it via PATHEXT.
func aliasFileName(name, goos string) string {
	if goos == "windows" {
		return name + ".exe"
	}
	return name
}

// Ensure returns the path to a verified binary, downloading it only when the
// cache does not already hold that exact version — and re-verifying it when
// it does.
func Ensure(spec Spec, opt Options) (string, error) {
	path, _, err := EnsureReporting(spec, opt)
	return path, err
}

// EnsureReporting is Ensure, and also says which of the two things happened.
//
// The caller cannot work this out beforehand: a cache entry that EXISTS may
// still be re-fetched here, because an entry whose recorded digest no longer
// matches is deleted rather than run. Deciding from an os.Stat before the
// call reports the tampered case — the one an operator most needs named — as
// an ordinary cache hit.
func EnsureReporting(spec Spec, opt Options) (string, Source, error) {
	path, _, source, err := ensure(spec, opt)
	return path, source, err
}

// ensure is EnsureReporting that also returns the verified bytes, so a
// platform that publishes the managed command as a copy (Windows) writes
// exactly what was verified rather than re-reading the cache by name.
func ensure(spec Spec, opt Options) (string, []byte, Source, error) {
	path := spec.CachePath(opt.CacheDir)

	// The cache is shared state: on WSL it must not be a Windows drive, which
	// native Windows kmx could be writing too. Refused before it is read.
	if err := fileaccess.RefuseWindowsDriveMount(opt.CacheDir); err != nil {
		return "", nil, FromDownload, err
	}
	if err := prepareManagedDir(opt.CacheDir); err != nil {
		return "", nil, FromDownload, err
	}

	// A cache hit is re-verified against the digest recorded beside it when
	// it was installed. Hashing a few tens of megabytes costs milliseconds; a
	// substituted binary holds the kubeconfig.
	cached, found, err := readManagedFile(path)
	if err != nil {
		return "", nil, FromDownload, err
	}
	if found {
		recorded, recordedFound, err := readManagedFile(path + ".sha256")
		if err != nil {
			return "", nil, FromDownload, err
		}
		if recordedFound && Verify(spec.Name, cached, recorded) == nil {
			return path, cached, FromCache, nil
		}
		if opt.Log != nil {
			fmt.Fprintf(opt.Log, "cached %s at %s does not match its recorded digest — re-fetching\n", spec.Name, path)
		}
		// Unverifiable: no record, or it no longer matches. Fetch again
		// rather than run it.
		if err := discardCacheEntry(path); err != nil {
			return "", nil, FromDownload, err
		}
	}

	url, checksumURL := spec.URL, spec.ChecksumURL
	if opt.BaseOverride != "" {
		url = rebase(url, opt.BaseOverride)
		checksumURL = rebase(checksumURL, opt.BaseOverride)
	}
	if opt.Log != nil {
		fmt.Fprintf(opt.Log, "fetching %s v%s (%s), checksum-verified — %s\n", spec.Name, spec.Version, url, spec.Why)
	}

	payload, err := get(url)
	if err != nil {
		return "", nil, FromDownload, err
	}
	checksumFile, err := get(checksumURL)
	if err != nil {
		return "", nil, FromDownload, err
	}
	// The published digest covers what was published: the binary, or the
	// archive it travels in. Verify THAT, then extract — never the other way
	// round, which would run an unverified archive through a decompressor.
	if err := Verify(spec.Name, payload, checksumFile); err != nil {
		return "", nil, FromDownload, err
	}
	binary := payload
	if spec.ArchiveMember != "" {
		extract := memberOf
		if isZipAsset(spec) {
			extract = zipMemberOf
		}
		if binary, err = extract(payload, spec.ArchiveMember); err != nil {
			return "", nil, FromDownload, fmt.Errorf("%s: %w", spec.Name, err)
		}
	}

	if err := install(path, binary); err != nil {
		return "", nil, FromDownload, err
	}
	// Record the digest of the file that was installed, so the next run can
	// re-verify what it is about to execute without going back to the
	// network. Written after the rename: a digest with no binary is harmless,
	// a binary with no digest is simply re-fetched.
	line := fmt.Sprintf("%s  %s\n", digest(binary), spec.Name)
	if err := writeDigest(path+".sha256", []byte(line)); err != nil {
		return "", nil, FromDownload, err
	}
	return path, binary, FromDownload, nil
}

// isZipAsset selects zip extraction from the asset the spec names. Only a
// .zip is parsed as one; every other archive keeps the tar.gz path.
func isZipAsset(spec Spec) bool { return strings.HasSuffix(spec.URL, ".zip") }

// memberOf pulls one file out of a verified .tar.gz.
func memberOf(archive []byte, member string) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, fmt.Errorf("cannot read the downloaded archive: %w", err)
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			return nil, fmt.Errorf("the archive does not contain %s", member)
		}
		if err != nil {
			return nil, fmt.Errorf("cannot read the downloaded archive: %w", err)
		}
		if header.Name != member || header.Typeflag != tar.TypeReg {
			continue
		}
		// Bounded: an archive claiming a preposterous size must not be able
		// to exhaust memory on the way to being rejected.
		body, err := io.ReadAll(io.LimitReader(tr, maxBinarySize))
		if err != nil {
			return nil, fmt.Errorf("cannot read %s out of the archive: %w", member, err)
		}
		return body, nil
	}
}

// zipMemberOf pulls exactly one regular file out of a verified .zip.
//
// The archive was checksum-verified before this runs, so this is about not
// trusting its STRUCTURE: nothing is extracted but the one named member, and
// anything that makes "the bytes of that member" ambiguous, redirected,
// special, oversized or short is refused rather than resolved.
func zipMemberOf(archive []byte, member string) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if errors.Is(err, zip.ErrInsecurePath) {
		return nil, fmt.Errorf("the archive has an unsafe name")
	}
	if err != nil {
		return nil, fmt.Errorf("cannot read the downloaded archive: %w", err)
	}
	var found *zip.File
	for _, f := range zr.File {
		if !safeZipName(f.Name) {
			return nil, fmt.Errorf("the archive has an unsafe name %q", f.Name)
		}
		// A case-folded twin is refused too: on a case-insensitive
		// filesystem the two would be the same file.
		if !strings.EqualFold(f.Name, member) {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("the archive contains more than one %s", member)
		}
		if f.Name != member {
			return nil, fmt.Errorf("the archive contains more than one %s (case variant %q)", member, f.Name)
		}
		found = f
	}
	if found == nil {
		return nil, fmt.Errorf("the archive does not contain %s", member)
	}
	if !found.Mode().IsRegular() {
		return nil, fmt.Errorf("%s in the archive is not a regular file", member)
	}
	if found.Flags&0x1 != 0 {
		return nil, fmt.Errorf("%s in the archive is encrypted", member)
	}
	if found.UncompressedSize64 > maxBinarySize {
		return nil, fmt.Errorf("%s in the archive is larger than %d bytes", member, maxBinarySize)
	}
	rc, err := found.Open()
	if err != nil {
		return nil, fmt.Errorf("cannot read %s out of the archive: %w", member, err)
	}
	defer rc.Close()
	// The reader checks the declared size and CRC at EOF, so reading to EOF
	// is what rejects a short or corrupted member; the limit only bounds a
	// lying header.
	body, err := io.ReadAll(io.LimitReader(rc, maxBinarySize+1))
	if err != nil {
		return nil, fmt.Errorf("cannot read %s out of the archive: %w", member, err)
	}
	if uint64(len(body)) != found.UncompressedSize64 {
		return nil, fmt.Errorf("cannot read %s out of the archive: %d bytes, header declares %d", member, len(body), found.UncompressedSize64)
	}
	return body, nil
}

// safeZipName admits only plain relative slash-separated names. Nothing is
// written by name, but a name that could escape or alias on a filesystem
// (absolute, drive, stream, backslash, dot or empty components) marks an
// archive that is not what the publisher's tooling produces.
func safeZipName(name string) bool {
	name = strings.TrimSuffix(name, "/")
	if name == "" || strings.HasPrefix(name, "/") || strings.ContainsAny(name, "\\:\x00") {
		return false
	}
	for _, part := range strings.Split(name, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

func rebase(url, base string) string {
	if i := strings.Index(url, "://"); i >= 0 {
		if j := strings.Index(url[i+3:], "/"); j >= 0 {
			return strings.TrimSuffix(base, "/") + url[i+3+j:]
		}
	}
	return url
}

func get(url string) ([]byte, error) {
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("cannot download %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cannot download %s: HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}
