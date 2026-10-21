//go:build windows

package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/kaimahi-agents/kaimahi/internal/kmx/fileaccess"
)

// Re-execute the native test PE as the CLI boundary, before testing parses
// Copilot's flags. No POSIX shell, installed Copilot, login or network is used.
func init() {
	marker := os.Getenv("KMX_TEST_NATIVE_PRIVATE_COPILOT")
	if marker == "" {
		return
	}
	check := func(err error) {
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	}
	directory, err := os.Getwd()
	check(err)
	check(fileaccess.WritePrivateFile(marker, []byte(directory), 0600)) // Records even a refused child cwd.
	root, err := fileaccess.OpenDirectory(directory)
	check(err)
	check(fileaccess.CheckPrivate(root, true))
	check(root.Close())
	entries, err := os.ReadDir(directory)
	check(err)
	if len(entries) != 0 {
		check(fmt.Errorf("Copilot inherited checkout files"))
	}
	fmt.Println(`{"type":"assistant.message","data":{"content":"native-private-answer"}}`)
	os.Exit(0)
}

// Losing the private cwd, inheriting the checkout or omitting cleanup breaks
// this test through the actual owned child process, not a mocked command.
func TestWindowsCopilotPromptPrivateCWDAndCleanup(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(privateSuiteDir(t), "observed-cwd")
	t.Setenv("KMX_TEST_NATIVE_PRIVATE_COPILOT", marker)
	answer, err := copilotPromptModel(context.Background(), executable, "fixture-model", "fixture prompt")
	if err != nil || answer != "native-private-answer" {
		t.Fatalf("native prompt = %q, %v", answer, err)
	}
	directory, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(string(directory)); !os.IsNotExist(err) {
		t.Fatalf("private Copilot cwd survived: %v", err)
	}
}

func TestWindowsCopilotPromptRefusesOtherWritableTEMP(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(privateSuiteDir(t), "unexpected-child")
	t.Setenv("KMX_TEST_NATIVE_PRIVATE_COPILOT", marker)
	temporary := t.TempDir()
	winGrantEveryoneFull(t, temporary)
	t.Setenv("TEMP", temporary)
	t.Setenv("TMP", temporary)
	answer, err := copilotPromptModel(context.Background(), executable, "fixture-model", "fixture prompt")
	if err == nil || answer != "" {
		t.Fatalf("unsafe TEMP accepted: %q, %v", answer, err)
	}
	if _, err := os.Lstat(marker); !os.IsNotExist(err) {
		t.Fatalf("child executed before TEMP refusal: %v", err)
	}
	entries, err := os.ReadDir(temporary)
	if err != nil || len(entries) != 0 {
		t.Fatalf("unsafe TEMP changed: %v, %v", entries, err)
	}
	winStillBroad(t, temporary)
}
