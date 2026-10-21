package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// fakeTool is the native counterpart of the small `case "$*"` shell fakes
// used for external CLIs. Windows uses a small standalone executable that
// replays this table without a shell.
type fakeTool struct {
	// Log, when set, receives LogLine plus a newline per invocation. LogLine
	// is expanded with os.Expand: ${ARGS} is the space-joined argv (the
	// shell's "$*"); any other name reads the environment.
	Log, LogLine string
	// TruncateLog replaces rather than appends (the shell's > redirection).
	TruncateLog bool
	// Rules are tried in order like shell case arms; the first match wins.
	Rules       []fakeToolRule
	DefaultExit int
}

type fakeToolRule struct {
	// Match is "exact", "contains" or "suffix" against ${ARGS}; empty
	// matches every invocation.
	Match, Args, Stdout string
	Exit                int
}

func (f fakeTool) run(args []string, getenv func(string) string, stdout io.Writer) int {
	joined := strings.Join(args, " ")
	if f.Log != "" {
		line := os.Expand(f.LogLine, func(name string) string {
			if name == "ARGS" {
				return joined
			}
			return getenv(name)
		})
		flags := os.O_WRONLY | os.O_CREATE | os.O_APPEND
		if f.TruncateLog {
			flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
		}
		file, err := os.OpenFile(f.Log, flags, 0o600)
		if err != nil {
			return 125
		}
		_, err = io.WriteString(file, line+"\n")
		if closeErr := file.Close(); err != nil || closeErr != nil {
			return 125
		}
	}
	for _, rule := range f.Rules {
		matched := false
		switch rule.Match {
		case "":
			matched = true
		case "exact":
			matched = joined == rule.Args
		case "contains":
			matched = strings.Contains(joined, rule.Args)
		case "suffix":
			matched = strings.HasSuffix(joined, rule.Args)
		}
		if matched {
			if _, err := io.WriteString(stdout, rule.Stdout); err != nil {
				return 125
			}
			return rule.Exit
		}
	}
	return f.DefaultExit
}

func TestFakeToolReplaysFirstMatchingCaseAndLogs(t *testing.T) {
	log := filepath.Join(t.TempDir(), "calls")
	tool := fakeTool{
		Log: log, LogLine: "kind ${ARGS} engine=${ENGINE}",
		Rules: []fakeToolRule{
			{Match: "suffix", Args: "get deploy -o json", Stdout: "json"},
			{Match: "contains", Args: "get deploy", Stdout: "table"},
			{Match: "exact", Args: "version", Exit: 3},
		},
		DefaultExit: 92,
	}
	getenv := func(name string) string { return map[string]string{"ENGINE": "podman"}[name] }
	for _, tc := range []struct {
		args []string
		out  string
		exit int
	}{
		{[]string{"-n", "x", "get", "deploy", "-o", "json"}, "json", 0},
		{[]string{"get", "deploy"}, "table", 0},
		{[]string{"version"}, "", 3},
		{[]string{"version", "--client"}, "", 92},
	} {
		var out bytes.Buffer
		if exit := tool.run(tc.args, getenv, &out); exit != tc.exit || out.String() != tc.out {
			t.Fatalf("%q: exit=%d out=%q", tc.args, exit, &out)
		}
	}
	raw, err := os.ReadFile(log)
	if err != nil || !strings.HasPrefix(string(raw), "kind -n x get deploy -o json engine=podman\nkind get deploy engine=podman\n") || strings.Count(string(raw), "\n") != 4 {
		t.Fatalf("log=%q err=%v", raw, err)
	}
	tool.TruncateLog = true
	if exit := tool.run([]string{"version"}, getenv, io.Discard); exit != 3 {
		t.Fatal(exit)
	}
	if raw, err := os.ReadFile(log); err != nil || string(raw) != "kind version engine=podman\n" {
		t.Fatalf("truncated log=%q err=%v", raw, err)
	}
}

// Resolve the compiler before fixtures replace PATH with only fake tools.
var fakeToolGoBinary, fakeToolGoError = exec.LookPath("go")

// buildFakeToolHelper compiles testdata/faketool (stdlib only) into dir.
func buildFakeToolHelper(dir string) (string, error) {
	if fakeToolGoError != nil {
		return "", fmt.Errorf("locate fixture compiler: %w", fakeToolGoError)
	}
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("locate fake tool source")
	}
	out := filepath.Join(dir, "faketool")
	if runtime.GOOS == "windows" {
		out += ".exe"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, fakeToolGoBinary, "build", "-o", out, ".")
	cmd.Dir = filepath.Join(filepath.Dir(self), "testdata", "faketool")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if output, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("build fake tool: %w: %s", err, output)
	}
	return out, nil
}

// The standalone helper must replay exactly like fakeTool.run.
func TestFakeToolHelperMatchesReplay(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	dir := t.TempDir()
	helper, err := buildFakeToolHelper(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Readiness precedes the replay table and must have no fixture effects.
	if output, err := exec.CommandContext(t.Context(), helper, "--kmx-fixture-ready").CombinedOutput(); err != nil || len(output) != 0 {
		t.Fatalf("fixture readiness before spec: output=%q error=%v", output, err)
	}
	log := filepath.Join(dir, "calls")
	spec := fakeTool{
		Log: log, LogLine: "kind ${ARGS} engine=${ENGINE}",
		Rules: []fakeToolRule{
			{Match: "suffix", Args: "get deploy -o json", Stdout: "json"},
			{Match: "exact", Args: "version", Exit: 3},
		},
		DefaultExit: 92,
	}
	raw, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(helper+".kmx-fake-tool.json", raw, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		args []string
		out  string
		exit int
	}{
		{[]string{"-n", "x", "get", "deploy", "-o", "json"}, "json", 0},
		{[]string{"version"}, "", 3},
		{[]string{"other"}, "", 92},
	} {
		cmd := exec.Command(helper, tc.args...)
		cmd.Env = append(os.Environ(), "ENGINE=podman")
		out, err := cmd.Output()
		exit := cmd.ProcessState.ExitCode()
		if string(out) != tc.out || exit != tc.exit {
			t.Fatalf("%q: exit=%d out=%q err=%v", tc.args, exit, out, err)
		}
	}
	got, err := os.ReadFile(log)
	if err != nil || string(got) != "kind -n x get deploy -o json engine=podman\nkind version engine=podman\nkind other engine=podman\n" {
		t.Fatalf("log=%q err=%v", got, err)
	}
}
