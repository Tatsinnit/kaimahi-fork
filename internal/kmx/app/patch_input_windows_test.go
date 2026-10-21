//go:build windows

package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kaimahi-agents/kaimahi/internal/kmx/config"
	"github.com/kaimahi-agents/kaimahi/internal/kmx/fileaccess"
	"github.com/kaimahi-agents/kaimahi/internal/kmx/run"
)

func TestWindowsPatchInputUsesPrivateFileAndCleansUp(t *testing.T) {
	for _, mode := range []string{"success", "capture failure", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			temp := t.TempDir()
			t.Setenv("TEMP", temp)
			t.Setenv("TMP", temp)
			body := []byte(`[{"op":"test","path":"/metadata/uid","value":"private-patch-canary"}]`)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			a := &App{Cfg: &config.Config{}, Run: &run.Runner{}}
			called := false
			a.captureCommand = func(_ context.Context, cmd *exec.Cmd) error {
				called = true
				if base := strings.ToLower(filepath.Base(cmd.Path)); base != "kubectl" && base != "kubectl.exe" {
					t.Fatalf("patch did not invoke kubectl directly: %q", base)
				}
				path := ""
				for _, arg := range cmd.Args {
					if strings.Contains(arg, "private-patch-canary") {
						t.Fatal("patch contents exposed in argv")
					}
					if strings.HasPrefix(arg, "--patch-file=") {
						path = strings.TrimPrefix(arg, "--patch-file=")
					}
				}
				if !filepath.IsAbs(path) || path == "/dev/stdin" || path == "-" {
					t.Fatalf("Windows patch did not use an absolute private file: %q", path)
				}
				parent, err := fileaccess.OpenDirectory(filepath.Dir(path))
				if err != nil {
					t.Fatal(err)
				}
				defer parent.Close()
				if err := fileaccess.CheckPrivate(parent, true); err != nil {
					t.Fatal(err)
				}
				file, err := fileaccess.OpenPrivateAt(parent, filepath.Base(path), os.O_RDONLY)
				if err != nil {
					t.Fatal(err)
				}
				file.Close()
				got, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(got, body) {
					t.Fatal("kubectl's regular-file input did not contain the patch")
				}
				input, err := io.ReadAll(cmd.Stdin)
				if err != nil || len(input) != 0 {
					t.Fatal("Windows patch left payload on stdin")
				}
				if mode == "canceled" {
					cancel()
					return ctx.Err()
				}
				if mode == "capture failure" {
					return errors.New("owned capture refusal")
				}
				_, err = io.WriteString(cmd.Stdout, "{}")
				return err
			}
			out, err := a.orkaPatchCapture(ctx, body, "patch", "configmap", "owned", "--type=json", "--patch-file=/dev/stdin", "-o", "json")
			if !called || (mode == "success" && (err != nil || string(out) != "{}")) || (mode != "success" && err == nil) {
				t.Fatalf("patch outcome called=%v err=%v", called, err)
			}
			if entries, err := os.ReadDir(temp); err != nil || len(entries) != 0 {
				t.Fatalf("patch input was not removed: entries=%d err=%v", len(entries), err)
			}
		})
	}
}

func TestWindowsPatchInputRefusesAmbiguousFlagsBeforeEffects(t *testing.T) {
	temp := t.TempDir()
	t.Setenv("TEMP", temp)
	t.Setenv("TMP", temp)
	a := &App{Cfg: &config.Config{}, Run: &run.Runner{}}
	a.captureCommand = func(context.Context, *exec.Cmd) error { t.Fatal("ambiguous patch input reached kubectl"); return nil }
	for _, args := range [][]string{{"patch", "configmap", "owned"}, {"--patch-file=/dev/stdin", "--patch-file=/dev/stdin"}} {
		if _, err := a.orkaPatchCapture(t.Context(), []byte("private"), args...); err == nil {
			t.Fatal("ambiguous patch flags accepted")
		}
		if entries, err := os.ReadDir(temp); err != nil || len(entries) != 0 {
			t.Fatal("ambiguous patch flags created state")
		}
	}
}
