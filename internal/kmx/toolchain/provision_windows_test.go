//go:build windows

package toolchain

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// The native tests serve a REAL Windows executable — this test binary,
// with a label appended as PE overlay data the loader ignores — so the
// alias kmx publishes is launched as a process, not merely found on disk.
const helperEnv = "KMX_TOOLCHAIN_TEST_HELPER"

// overlayTag is built at run time so the marker never appears in the test
// binary's own read-only data, which would make an unlabeled copy look
// labeled.
var overlayTag = []byte("\n" + strings.ToUpper("kmx-toolchain-overlay:"))

func TestMain(m *testing.M) {
	if os.Getenv(helperEnv) == "1" {
		os.Exit(runHelper())
	}
	os.Exit(m.Run())
}

// runHelper reports which file it was launched as and the label its own
// bytes carry, so a test can tell exactly which verified bytes ran.
func runHelper() int {
	exe, err := os.Executable()
	if err != nil {
		fmt.Println("helper: executable:", err)
		return 2
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		fmt.Println("helper: read:", err)
		return 2
	}
	label := "unlabeled"
	if i := bytes.LastIndex(data, overlayTag); i >= 0 {
		label = strings.TrimSpace(string(data[i+len(overlayTag):]))
	}
	fmt.Printf("kmx-toolchain-helper %s %s\n", strings.ToLower(filepath.Base(exe)), label)
	if os.Getenv("KMX_TOOLCHAIN_TEST_HOLD") == "1" {
		if _, err := io.Copy(io.Discard, os.Stdin); err != nil {
			return 2
		}
	}
	return 0
}

var (
	selfOnce  sync.Once
	selfBytes []byte
	selfErr   error
)

// labeledExe returns this test binary's bytes plus a label in its overlay.
func labeledExe(t *testing.T, label string) []byte {
	t.Helper()
	selfOnce.Do(func() {
		exe, err := os.Executable()
		if err != nil {
			selfErr = err
			return
		}
		selfBytes, selfErr = os.ReadFile(exe)
	})
	if selfErr != nil {
		t.Fatal(selfErr)
	}
	out := append(append(append([]byte{}, selfBytes...), overlayTag...), label...)
	return append(out, '\n')
}

func launch(t *testing.T, path string) string {
	t.Helper()
	cmd := exec.Command(path)
	cmd.Env = append(os.Environ(), helperEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("launching %s: %v\n%s", path, err, out)
	}
	return strings.TrimSpace(string(out))
}

// release is a throwaway upstream: each asset path serves its bytes, and
// the asset path plus .sha256 or .sha256sum serves its digest.
type release struct {
	mu     sync.Mutex
	assets map[string][]byte
	hits   int
}

func newRelease(t *testing.T) (*release, *httptest.Server) {
	rel := &release{assets: map[string][]byte{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rel.mu.Lock()
		defer rel.mu.Unlock()
		if body, ok := rel.assets[r.URL.Path]; ok {
			rel.hits++
			w.Write(body)
			return
		}
		for _, suffix := range []string{".sha256sum", ".sha256"} {
			if body, ok := rel.assets[strings.TrimSuffix(r.URL.Path, suffix)]; ok && strings.HasSuffix(r.URL.Path, suffix) {
				fmt.Fprintf(w, "%s  %s\n", digestOf(body), filepath.Base(strings.TrimSuffix(r.URL.Path, suffix)))
				return
			}
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return rel, srv
}

func (r *release) publish(t *testing.T, spec Spec, body []byte) {
	t.Helper()
	u, err := url.Parse(spec.URL)
	if err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.assets[u.Path] = body
}

func (r *release) downloads() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.hits
}

// grantEveryone replaces path's DACL with a protected Everyone:FullControl
// grant — the kind of broad ACL a private kmx root must refuse, not repair.
func grantEveryone(t *testing.T, path string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatalf("setting a broad DACL on %s: %v", path, err)
	}
}

// junction makes link a directory junction to target. Junctions need no
// symlink privilege, so an ordinary user can plant one.
func junction(t *testing.T, link, target string) {
	t.Helper()
	if out, err := exec.Command("cmd.exe", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v\n%s", err, out)
	}
}

func samePath(a, b string) bool { return strings.EqualFold(filepath.Clean(a), filepath.Clean(b)) }

// The native happy path: a tool missing from PATH is fetched, verified,
// cached under an .exe name, and published as <name>.exe in the managed
// directory — which exec.LookPath then resolves and Windows can launch.
func TestNativeProvisionReusesIdenticalRunningAlias(t *testing.T) {
	spec, ok := Pinned("kubectl", runtime.GOOS, runtime.GOARCH)
	if !ok {
		t.Fatal("missing native kubectl pin")
	}
	rel, srv := newRelease(t)
	rel.publish(t, spec, labeledExe(t, "running-pin"))
	root := managedDir(t)
	link := filepath.Join(root, "bin")
	opt := Options{CacheDir: filepath.Join(root, "cache"), BaseOverride: srv.URL}
	t.Setenv("PATH", t.TempDir())
	first, err := Provision([]string{"kubectl"}, link, opt)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(first[0].Path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, first[0].Path)
	cmd.Env = append(os.Environ(), helperEnv+"=1", "KMX_TOOLCHAIN_TEST_HOLD=1")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stdin.Close()
		if err := cmd.Wait(); err != nil {
			t.Errorf("stopping owned running alias: %v", err)
		}
	})
	ready, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || !strings.Contains(ready, "kubectl.exe running-pin") {
		t.Fatalf("running alias readiness = %q, %v", ready, err)
	}
	second, err := Provision([]string{"kubectl"}, link, opt)
	if err != nil {
		t.Fatalf("identical verified running alias must remain usable: %v", err)
	}
	after, err := os.Stat(second[0].Path)
	if err != nil || !os.SameFile(before, after) || rel.downloads() != 1 {
		t.Fatalf("reused alias changed or re-downloaded: same=%v downloads=%d err=%v", err == nil && os.SameFile(before, after), rel.downloads(), err)
	}
}

func TestNativeProvisionPublishesALaunchableExeAlias(t *testing.T) {
	spec, ok := Pinned("kubectl", runtime.GOOS, runtime.GOARCH)
	if !ok {
		t.Fatalf("kubectl has no pinned %s/%s download", runtime.GOOS, runtime.GOARCH)
	}
	rel, srv := newRelease(t)
	rel.publish(t, spec, labeledExe(t, "kubectl-v1"))

	root := managedDir(t)
	cache, link := filepath.Join(root, "cache"), filepath.Join(root, "bin")
	opt := Options{CacheDir: cache, BaseOverride: srv.URL}
	t.Setenv("PATH", t.TempDir())
	tools, err := Provision([]string{"kubectl"}, link, opt)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	alias := filepath.Join(link, "kubectl.exe")
	if len(tools) != 1 || !samePath(tools[0].Path, alias) || tools[0].Source != FromDownload || tools[0].Version != KubectlVersion {
		t.Fatalf("provisioned %+v, want a downloaded %s", tools, alias)
	}
	cached := spec.CachePath(cache)
	if want := fmt.Sprintf("kubectl-%s-windows-%s.exe", KubectlVersion, runtime.GOARCH); filepath.Base(cached) != want {
		t.Errorf("cache entry %q, want %q", filepath.Base(cached), want)
	}
	for _, path := range []string{cached, cached + ".sha256"} {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("cache entry missing: %v", err)
		}
	}

	t.Setenv("PATH", link)
	found, err := exec.LookPath("kubectl")
	if err != nil {
		t.Fatalf("LookPath does not find the managed alias: %v", err)
	}
	if !samePath(found, alias) {
		t.Fatalf("LookPath found %s, want %s", found, alias)
	}
	if got := launch(t, found); got != "kmx-toolchain-helper kubectl.exe kubectl-v1" {
		t.Fatalf("the launched alias reported %q", got)
	}

	// A second run re-verifies the cache entry rather than downloading.
	t.Setenv("PATH", t.TempDir())
	tools, err = Provision([]string{"kubectl"}, link, opt)
	if err != nil {
		t.Fatal(err)
	}
	if tools[0].Source != FromCache || rel.downloads() != 1 {
		t.Fatalf("second provision: source %q after %d downloads, want a verified cache hit", tools[0].Source, rel.downloads())
	}
}

// Replacing the alias never leaves the old bytes behind under the plain
// name: after the verified bytes change, the launched alias is the new one.
func TestNativeProvisionReplacesTheAliasWithNewlyVerifiedBytes(t *testing.T) {
	spec, _ := Pinned("kubectl", runtime.GOOS, runtime.GOARCH)
	rel, srv := newRelease(t)
	rel.publish(t, spec, labeledExe(t, "kubectl-v1"))
	root := managedDir(t)
	cache, link := filepath.Join(root, "cache"), filepath.Join(root, "bin")
	opt := Options{CacheDir: cache, BaseOverride: srv.URL}
	t.Setenv("PATH", t.TempDir())
	if _, err := Provision([]string{"kubectl"}, link, opt); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(link, "kubectl.exe")
	if got := launch(t, alias); !strings.HasSuffix(got, " kubectl-v1") {
		t.Fatalf("first alias reported %q", got)
	}

	// The cache entry is substituted, so it fails re-verification and is
	// re-fetched; upstream now serves different (verified) bytes.
	v2 := labeledExe(t, "kubectl-v2")
	rel.publish(t, spec, v2)
	if err := os.WriteFile(spec.CachePath(cache), []byte("MZ tampered"), 0o755); err != nil {
		t.Fatal(err)
	}
	tools, err := Provision([]string{"kubectl"}, link, opt)
	if err != nil {
		t.Fatal(err)
	}
	if tools[0].Source != FromDownload {
		t.Fatalf("re-fetched alias reported %q", tools[0].Source)
	}
	if got := launch(t, alias); !strings.HasSuffix(got, " kubectl-v2") {
		t.Fatalf("the alias still runs stale bytes: %q", got)
	}
	got, err := os.ReadFile(alias)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, v2) {
		t.Fatal("the alias does not hold exactly the newly verified bytes")
	}
}

// Helm ships as a zip on Windows: verified, then exactly helm.exe is
// extracted and published, and it launches.
func TestNativeHelmZipProvisionLaunches(t *testing.T) {
	spec, ok := Pinned("helm", runtime.GOOS, runtime.GOARCH)
	if !ok {
		t.Fatalf("helm has no pinned %s/%s download", runtime.GOOS, runtime.GOARCH)
	}
	rel, srv := newRelease(t)
	dir := strings.TrimSuffix(spec.ArchiveMember, "helm.exe")
	rel.publish(t, spec, zipOf(t,
		zipEntry{name: dir, mode: os.ModeDir | 0o755},
		zipEntry{name: dir + "LICENSE", body: []byte("license")},
		zipEntry{name: spec.ArchiveMember, body: labeledExe(t, "helm-zip")}))
	root := managedDir(t)
	link := filepath.Join(root, "bin")
	t.Setenv("PATH", t.TempDir())
	if _, err := Provision([]string{"helm"}, link, Options{CacheDir: filepath.Join(root, "cache"), BaseOverride: srv.URL}); err != nil {
		t.Fatalf("provision: %v", err)
	}
	t.Setenv("PATH", link)
	found, err := exec.LookPath("helm")
	if err != nil {
		t.Fatal(err)
	}
	if got := launch(t, found); got != "kmx-toolchain-helper helm.exe helm-zip" {
		t.Fatalf("the launched helm reported %q", got)
	}
}

// A cache root anyone can write is not a place to keep executables kmx
// runs: it is refused, not repaired, and nothing is fetched into it.
func TestNativeEnsureRefusesABroadCacheRoot(t *testing.T) {
	spec, _ := Pinned("kubectl", runtime.GOOS, runtime.GOARCH)
	rel, srv := newRelease(t)
	rel.publish(t, spec, labeledExe(t, "kubectl-v1"))
	cache := filepath.Join(t.TempDir(), "cache")
	if err := os.Mkdir(cache, 0o700); err != nil {
		t.Fatal(err)
	}
	grantEveryone(t, cache)
	if _, err := Ensure(spec, Options{CacheDir: cache, BaseOverride: srv.URL}); err == nil {
		t.Fatal("a world-writable cache root was accepted")
	}
	if rel.downloads() != 0 {
		t.Errorf("downloaded %d times into a refused cache root", rel.downloads())
	}
	if entries, _ := os.ReadDir(cache); len(entries) != 0 {
		t.Errorf("the refused cache root was written: %v", entries)
	}
}

// An existing cache entry or digest record whose ACL is not owner-only is
// refused before its bytes are read — a fatal error, not a silent refetch.
func TestNativeEnsureRefusesABroadCacheEntry(t *testing.T) {
	for _, target := range []string{"binary", "digest"} {
		t.Run(target, func(t *testing.T) {
			spec, _ := Pinned("kubectl", runtime.GOOS, runtime.GOARCH)
			rel, srv := newRelease(t)
			rel.publish(t, spec, labeledExe(t, "kubectl-v1"))
			cache := filepath.Join(managedDir(t), "cache")
			opt := Options{CacheDir: cache, BaseOverride: srv.URL}
			path, err := Ensure(spec, opt)
			if err != nil {
				t.Fatal(err)
			}
			broad := path
			if target == "digest" {
				broad += ".sha256"
			}
			grantEveryone(t, broad)
			if _, err := Ensure(spec, opt); err == nil {
				t.Fatalf("a cache %s with a broad ACL was accepted", target)
			}
			if rel.downloads() != 1 {
				t.Errorf("a refused %s was silently re-fetched (%d downloads)", target, rel.downloads())
			}
			if _, err := os.Stat(broad); err != nil {
				t.Errorf("the refused %s was removed rather than reported: %v", target, err)
			}
		})
	}
}

// A junction (no privilege needed to plant one) must not redirect where
// kmx keeps or publishes executables.
func TestNativeProvisionRefusesJunctionedManagedDirectories(t *testing.T) {
	for _, which := range []string{"cache", "bin"} {
		t.Run(which, func(t *testing.T) {
			spec, _ := Pinned("kubectl", runtime.GOOS, runtime.GOARCH)
			rel, srv := newRelease(t)
			rel.publish(t, spec, labeledExe(t, "kubectl-v1"))
			root := managedDir(t)
			// A genuinely private target, made by kmx itself.
			real := filepath.Join(root, "real")
			if _, err := Ensure(spec, Options{CacheDir: real, BaseOverride: srv.URL}); err != nil {
				t.Fatal(err)
			}
			redirected := filepath.Join(root, which)
			junction(t, redirected, real)
			var err error
			if which == "cache" {
				// The junction leads to a valid, verified entry: only the
				// junction itself makes this unsafe.
				_, err = Ensure(spec, Options{CacheDir: redirected, BaseOverride: srv.URL})
			} else {
				t.Setenv("PATH", t.TempDir())
				_, err = Provision([]string{"kubectl"}, redirected, Options{CacheDir: filepath.Join(root, "cache"), BaseOverride: srv.URL})
			}
			if err == nil {
				t.Fatalf("a junctioned %s directory was followed", which)
			}
			if rel.downloads() != 1 {
				t.Errorf("downloaded through a junctioned %s directory (%d downloads)", which, rel.downloads())
			}
		})
	}
}

// A broad managed alias directory is refused before anything is fetched.
func TestNativeProvisionRefusesABroadAliasDirectory(t *testing.T) {
	spec, _ := Pinned("kubectl", runtime.GOOS, runtime.GOARCH)
	rel, srv := newRelease(t)
	rel.publish(t, spec, labeledExe(t, "kubectl-v1"))
	link := filepath.Join(t.TempDir(), "bin")
	if err := os.Mkdir(link, 0o700); err != nil {
		t.Fatal(err)
	}
	grantEveryone(t, link)
	t.Setenv("PATH", t.TempDir())
	if _, err := Provision([]string{"kubectl"}, link, Options{CacheDir: filepath.Join(managedDir(t), "cache"), BaseOverride: srv.URL}); err == nil {
		t.Fatal("a world-writable alias directory was accepted")
	}
	if rel.downloads() != 0 {
		t.Errorf("downloaded %d times before refusing the alias directory", rel.downloads())
	}
}

// A pin bump changes the versioned cache name; the plain command must then
// run the NEW verified bytes, with no privilege needed to republish it.
func TestNativeAPinBumpRepublishesTheAlias(t *testing.T) {
	v1, _ := Pinned("kubectl", runtime.GOOS, runtime.GOARCH)
	v2 := v1
	v2.Version = "1.37.1-test"
	v2.URL = strings.Replace(v1.URL, "v"+v1.Version, "v"+v2.Version, 1)
	v2.ChecksumURL = v2.URL + ".sha256"
	rel, srv := newRelease(t)
	rel.publish(t, v1, labeledExe(t, "pin-v1"))
	rel.publish(t, v2, labeledExe(t, "pin-v2"))
	root := managedDir(t)
	cache, link := filepath.Join(root, "cache"), filepath.Join(root, "bin")
	opt := Options{CacheDir: cache, BaseOverride: srv.URL}
	if err := prepareManagedDir(link); err != nil {
		t.Fatal(err)
	}
	for _, step := range []struct {
		spec  Spec
		label string
	}{{v1, "pin-v1"}, {v2, "pin-v2"}} {
		path, binary, _, err := ensure(step.spec, opt)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := publishAlias(link, "kubectl", path, binary); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", link)
		found, err := exec.LookPath("kubectl")
		if err != nil {
			t.Fatal(err)
		}
		if got := launch(t, found); got != "kmx-toolchain-helper kubectl.exe "+step.label {
			t.Fatalf("after publishing %s the command reported %q", step.spec.Version, got)
		}
	}
	for _, spec := range []Spec{v1, v2} {
		if _, err := os.Stat(spec.CachePath(cache)); err != nil {
			t.Errorf("versioned cache entry missing: %v", err)
		}
	}
}
