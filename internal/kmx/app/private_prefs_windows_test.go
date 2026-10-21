//go:build windows

package app

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kaimahi-agents/kaimahi/internal/kmx/fileaccess"
	"github.com/kaimahi-agents/kaimahi/internal/kmx/lift"
	"github.com/kaimahi-agents/kaimahi/internal/kmx/run"
	"golang.org/x/sys/windows"
)

// winPrivateHome points KMX_HOME at a new protected current-user-only root,
// never at t.TempDir's inherited broad descriptor.
func winPrivateHome(t *testing.T) string {
	t.Helper()
	home := privateSuiteDir(t)
	t.Setenv("KMX_HOME", home)
	return home
}

// winGrantEveryoneFull installs an owner-plus-Everyone-full DACL on a
// disposable fixture this test created. It is never production repair.
func winGrantEveryoneFull(t *testing.T, path string) {
	t.Helper()
	user := winUser(t)
	sd, err := windows.SecurityDescriptorFromString("O:" + user + "D:P(A;OICI;FA;;;" + user + ")(A;OICI;FA;;;WD)")
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

// winStillBroad proves a refused fixture was not repaired.
func winStillBroad(t *testing.T, path string) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sd.String(), ";;;WD)") {
		t.Fatalf("%s was repaired: %s", path, sd)
	}
}

func winNoStage(t *testing.T, dir, prefix string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), prefix) {
			t.Fatalf("staged file %s remains in %s", entry.Name(), dir)
		}
	}
}

// requirePrivateFileForTest checks the real owner/DACL and the explicit
// protected descriptor; Windows permission bits are synthetic.
func requirePrivateFileForTest(t *testing.T, path string) {
	t.Helper()
	winCheckPrivate(t, path, false)
	winRequireProtected(t, path)
}

// requireCarriedScriptForTest: Windows has no execute bit (bash runs the
// script by path), so the carried script must be a private file.
func requireCarriedScriptForTest(t *testing.T, path string) {
	t.Helper()
	requirePrivateFileForTest(t, path)
}

const winSecretKubeconfig = "apiVersion: v1\nusers:\n- user:\n    token: kmx-private-test-token\n"

func TestWindowsAgentLocationFilesAreProtectedAndReplacedAtomically(t *testing.T) {
	home := winPrivateHome(t)
	location, err := writeAgentLocation(agentLocation{Agent: "demo", Namespace: OrkaNamespace, Context: "kind-local"}, []byte(winSecretKubeconfig))
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(home, "agentconfigs")
	winCheckPrivate(t, dir, true)
	record := strings.TrimSuffix(location.Kubeconfig, ".kubeconfig") + ".json"
	for _, path := range []string{location.Kubeconfig, record} {
		winCheckPrivate(t, path, false)
		winRequireProtected(t, path)
	}
	if _, err := writeAgentLocation(agentLocation{Agent: "demo", Namespace: OrkaNamespace, Context: "kind-local"}, []byte("apiVersion: v1\n")); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(location.Kubeconfig); err != nil || string(got) != "apiVersion: v1\n" {
		t.Fatalf("replacement = %q, %v", got, err)
	}
	winRequireProtected(t, location.Kubeconfig)
	winNoEntries(t, dir, 2)
	locations, err := loadAgentLocations()
	if err != nil || len(locations) != 1 || locations[0].Kubeconfig != location.Kubeconfig {
		t.Fatalf("locations = %v, %v", locations, err)
	}
}

// An existing destination that is not a private regular file is refused
// before staging, and is neither replaced nor repaired.
func TestWindowsPrivateAgentFileRefusesUnsafeExistingLeaf(t *testing.T) {
	t.Run("broad", func(t *testing.T) {
		dir := privateSuiteDir(t)
		path := filepath.Join(dir, "agent.json")
		if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
			t.Fatal(err)
		}
		winBroaden(t, path)
		err := writePrivateAgentFile(path, []byte(winSecretKubeconfig))
		if err == nil {
			t.Fatal("broad destination replaced")
		}
		if strings.Contains(err.Error(), "kmx-private-test-token") {
			t.Fatal("error disclosed private content")
		}
		if got, _ := os.ReadFile(path); string(got) != "original" {
			t.Fatalf("broad destination modified: %q", got)
		}
		winStillBroad(t, path)
		winNoEntries(t, dir, 1)
	})
	t.Run("junction", func(t *testing.T) {
		dir := privateSuiteDir(t)
		target := privateSuiteDir(t)
		path := filepath.Join(dir, "agent.json")
		winJunction(t, path, target)
		if err := writePrivateAgentFile(path, []byte("new")); err == nil {
			t.Fatal("junction destination replaced")
		}
		if info, err := os.Lstat(path); err != nil || info.Mode().Type() == 0 {
			t.Fatalf("junction removed or replaced: %v %v", info, err)
		}
		winNoEntries(t, target, 0)
		winNoEntries(t, dir, 1)
	})
	t.Run("broad parent", func(t *testing.T) {
		dir := privateSuiteDir(t)
		winBroaden(t, dir)
		if err := writePrivateAgentFile(filepath.Join(dir, "agent.json"), []byte("new")); err == nil {
			t.Fatal("broad parent accepted")
		}
		winNoEntries(t, dir, 0)
	})
}

func TestWindowsPrivatePreferenceReadersCheckHandles(t *testing.T) {
	t.Run("lift preferences broad", func(t *testing.T) {
		home := winPrivateHome(t)
		if err := saveLiftPreference("subscription", "sub-a"); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(home, "lift-selections.json")
		winRequireProtected(t, path)
		winBroaden(t, path)
		if _, err := loadLiftPreferences(); err == nil {
			t.Fatal("broad preferences read")
		}
		if err := saveLiftPreference("subscription", "sub-b"); err == nil {
			t.Fatal("broad preferences replaced")
		}
		winStillBroad(t, path)
	})
	t.Run("lift preferences oversized", func(t *testing.T) {
		home := winPrivateHome(t)
		raw := []byte(`{"subscription":"` + strings.Repeat("a", 1<<20) + `"}`)
		if err := fileaccess.WritePrivateFile(filepath.Join(home, "lift-selections.json"), raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadLiftPreferences(); err == nil {
			t.Fatal("oversized preferences read")
		}
	})
	t.Run("foundry broad", func(t *testing.T) {
		home := winPrivateHome(t)
		if err := saveFoundryChatConfig(foundryChatConfig{Endpoint: "https://example.openai.azure.com", Deployment: "chat"}); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(home, "foundry-inference.json")
		winRequireProtected(t, path)
		if _, err := loadFoundryChatConfig(); err != nil {
			t.Fatal(err)
		}
		winBroaden(t, path)
		if _, err := loadFoundryChatConfig(); err == nil || os.IsNotExist(err) {
			t.Fatalf("broad Foundry config = %v", err)
		}
	})
	t.Run("console inference", func(t *testing.T) {
		home := winPrivateHome(t)
		env := agentTUIEnvironment{Name: "kind-test", Local: true}
		agent := agentTUIAgent{Name: "demo", Namespace: "agents", Runtime: "orka"}
		source := consoleInferenceSource{Kind: "foundry", Name: "test", Endpoint: "https://example.openai.azure.com", Model: "test-model"}
		if err := saveConsoleInference(env, agent, &source); err != nil {
			t.Fatal(err)
		}
		winCheckPrivate(t, filepath.Join(home, "console-inference"), true)
		path, _ := consoleInferencePath(env, agent)
		winRequireProtected(t, path)
		winBroaden(t, path)
		if _, err := loadConsoleInference(env, agent); err == nil {
			t.Fatal("broad console inference read")
		}
		if err := saveConsoleInference(env, agent, nil); err == nil {
			t.Fatal("broad console inference removed")
		}
		winStillBroad(t, path)
	})
	t.Run("agent location broad leaf", func(t *testing.T) {
		home := winPrivateHome(t)
		if _, err := writeAgentLocation(agentLocation{Agent: "demo", Namespace: OrkaNamespace, Context: "kind-local"}, nil); err != nil {
			t.Fatal(err)
		}
		entries, err := os.ReadDir(filepath.Join(home, "agentconfigs"))
		if err != nil || len(entries) != 1 {
			t.Fatal(entries, err)
		}
		winBroaden(t, filepath.Join(home, "agentconfigs", entries[0].Name()))
		if _, err := loadAgentLocations(); err == nil {
			t.Fatal("broad agent location read")
		}
	})
	t.Run("agent locations junction", func(t *testing.T) {
		home := winPrivateHome(t)
		elsewhere := privateSuiteDir(t)
		if err := fileaccess.WritePrivateFile(filepath.Join(elsewhere, "x.json"), []byte(`{"agent":"a","namespace":"n","context":"c"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		winJunction(t, filepath.Join(home, "agentconfigs"), elsewhere)
		if locations, err := loadAgentLocations(); err == nil {
			t.Fatalf("junction directory read: %v", locations)
		}
		if _, err := writeAgentLocation(agentLocation{Agent: "demo", Namespace: OrkaNamespace, Context: "kind-local"}, []byte(winSecretKubeconfig)); err == nil {
			t.Fatal("junction directory written")
		}
		winNoEntries(t, elsewhere, 1)
	})
	t.Run("agent locations broad directory", func(t *testing.T) {
		home := winPrivateHome(t)
		dir := filepath.Join(home, "agentconfigs")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		winGrantEveryoneFull(t, dir)
		if _, err := loadAgentLocations(); err == nil {
			t.Fatal("broad directory read")
		}
		if _, err := writeAgentLocation(agentLocation{Agent: "demo", Namespace: OrkaNamespace, Context: "kind-local"}, []byte(winSecretKubeconfig)); err == nil {
			t.Fatal("broad directory written")
		}
		winNoEntries(t, dir, 0)
	})
}

func TestWindowsLiftRecordIsPrivate(t *testing.T) {
	winPrivateHome(t)
	a := &App{}
	opt := lift.Options{Payload: lift.PayloadOrka, ResourceGroup: "rg", Cluster: "cluster"}
	if _, _, err := a.openLiftRecord(opt, "subscription-id"); err != nil {
		t.Fatal(err)
	}
	path, err := liftRecordPath("rg", "cluster")
	if err != nil {
		t.Fatal(err)
	}
	winCheckPrivate(t, filepath.Dir(path), true)
	winCheckPrivate(t, path, false)
	winRequireProtected(t, path)
	if _, _, err := a.openLiftRecord(opt, "subscription-id"); err != nil {
		t.Fatalf("private record not reopened: %v", err)
	}
	winBroaden(t, path)
	if _, _, err := a.openLiftRecord(opt, "subscription-id"); err == nil {
		t.Fatal("broad record read")
	}
	winStillBroad(t, path)
}

func TestWindowsQuickstartStateIsProtectedRoot(t *testing.T) {
	t.Run("fresh", func(t *testing.T) {
		home := winPrivateHome(t)
		base, err := privateWorkspaceState("quickstart")
		if err != nil {
			t.Fatal(err)
		}
		if base != filepath.Join(home, "quickstart") {
			t.Fatalf("base = %s", base)
		}
		winCheckPrivate(t, base, true)
		if again, err := privateWorkspaceState("quickstart"); err != nil || again != base {
			t.Fatalf("existing private state = %q, %v", again, err)
		}
	})
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, base string)
	}{
		{"inherited", func(t *testing.T, base string) {
			if err := os.Mkdir(base, 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{"broad", func(t *testing.T, base string) {
			if err := os.Mkdir(base, 0o700); err != nil {
				t.Fatal(err)
			}
			winBroaden(t, base)
		}},
		{"junction", func(t *testing.T, base string) { winJunction(t, base, privateSuiteDir(t)) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := winPrivateHome(t)
			base := filepath.Join(home, "quickstart-authored")
			tc.setup(t, base)
			before, _ := windows.GetNamedSecurityInfo(base, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
			if _, err := privateWorkspaceState("quickstart-authored"); err == nil {
				t.Fatal("unsafe quickstart state accepted")
			}
			_, err := (&App{}).authorQuickstartSource(t.Context(), CreateOptions{Name: "private-agent", Description: "A fixture", Namespace: OrkaNamespace, Model: "exact-model", InstructionText: "Answer factual questions."})
			if err == nil {
				t.Fatal("unsafe quickstart state reached authoring")
			}
			after, _ := windows.GetNamedSecurityInfo(base, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
			if before.String() != after.String() {
				t.Fatalf("state descriptor changed: %s -> %s", before, after)
			}
			if tc.name != "junction" {
				winNoEntries(t, base, 0)
			}
		})
	}
}

func TestWindowsQuickstartAuthoredSourceIsPrivate(t *testing.T) {
	home := winPrivateHome(t)
	root, err := (&App{}).authorQuickstartSource(t.Context(), CreateOptions{Name: "private-agent", Description: "A fixture", Namespace: OrkaNamespace, Model: "exact-model", InstructionText: "Answer factual questions."})
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(home, "quickstart-authored")
	winCheckPrivate(t, base, true)
	winCheckPrivate(t, root, true)
	if filepath.Dir(root) != base {
		t.Fatalf("root %s outside %s", root, base)
	}
	winNoStage(t, base, "instructions-")
	if raw, err := os.ReadFile(filepath.Join(root, "agents", "private-agent", "instructions.md")); err != nil || !bytes.Contains(raw, []byte("Answer factual questions.")) {
		t.Fatalf("authored instructions = %q, %v", raw, err)
	}
}

// Confidential and executable temporary content is private even when TMP
// names a custom directory, and a custom directory that admits other writers
// is refused rather than trusted.
func TestWindowsTemporaryWorkspacesArePrivate(t *testing.T) {
	custom := t.TempDir()
	t.Setenv("TMP", custom)
	t.Setenv("TEMP", custom)
	a := &App{Run: nil}
	dir, cleanup, err := a.liftWorkspace()
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(dir) != custom {
		t.Fatalf("lift workspace %s not in custom TMP", dir)
	}
	winCheckPrivate(t, dir, true)
	winCheckPrivate(t, filepath.Join(dir, "scripts"), true)
	for _, name := range []string{"aks-up.sh", "aks-down.sh", "kube-guard.sh"} {
		path := filepath.Join(dir, "scripts", name)
		winCheckPrivate(t, path, false)
		winRequireProtected(t, path)
	}
	cleanup()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("lift workspace survives cleanup: %v", err)
	}

	runner, cleanupAzure, err := (&App{Run: &run.Runner{}}).isolatedAzureRunner()
	if err != nil {
		t.Fatal(err)
	}
	var extensions string
	for _, entry := range runner.Env {
		if value, ok := strings.CutPrefix(entry, "AZURE_EXTENSION_DIR="); ok {
			extensions = value
		}
	}
	if filepath.Dir(extensions) != custom {
		t.Fatalf("extensions %q not in custom TMP", extensions)
	}
	winCheckPrivate(t, extensions, true)
	cleanupAzure()

	winGrantEveryoneFull(t, custom)
	if _, cleanup, err := a.liftWorkspace(); err == nil {
		cleanup()
		t.Fatal("lift workspace created in a TMP other users can write")
	}
	if _, cleanup, err := (&App{Run: &run.Runner{}}).isolatedAzureRunner(); err == nil {
		cleanup()
		t.Fatal("Azure extensions created in a TMP other users can write")
	}
}
