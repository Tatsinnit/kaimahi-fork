//go:build windows

package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	agentsuite "github.com/agent-primitives/suite"
)

func TestWindowsSuiteVerifyDistinguishesDrivePathsFromReferences(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "absent-state")
	t.Setenv("KMX_HOME", home)
	absolute := filepath.Join(root, "layout")
	for _, tc := range []struct{ name, suite, code string }{
		{"drive absolute", absolute, "missing"},
		{"forward separators", filepath.ToSlash(absolute), "missing"},
		{"extended drive", `\\?\` + absolute, "missing"},
		{"drive relative", absolute[:2] + "layout", "artifact"},
		{"URL", "https://registry.example/layout", "artifact"},
		{"registry tag", "registry.example/agents/demo:v1", "artifact"},
		{"registry digest", "registry.example/agents/demo@sha256:bad", "artifact"},
		{"alternate stream", absolute + ":stream", "artifact"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := (&App{}).VerifySuiteEvaluation(context.Background(), SuiteEvaluationVerifyOptions{
				Suite: tc.suite, Evidence: filepath.Join(root, "missing-evidence"), Expect: filepath.Join(root, "missing-expectation"),
			})
			var refusal *agentsuite.EvidenceRefusal
			if !errors.As(err, &refusal) || refusal.Code != tc.code {
				t.Fatalf("verify %q: %v; want %s", tc.suite, err, tc.code)
			}
		})
	}
	if _, err := os.Stat(home); !os.IsNotExist(err) {
		t.Fatalf("offline verification initialized state: %v", err)
	}
}
