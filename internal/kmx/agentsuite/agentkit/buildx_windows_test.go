//go:build windows

package agentkit

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/kaimahi-agents/kaimahi/internal/kmx/fileaccess"
)

type privateBuildInputRunner struct{ t *testing.T }

func (r privateBuildInputRunner) Run(_ context.Context, stdout, _ io.Writer, _ string, args ...string) error {
	if len(args) > 1 && args[1] == "version" {
		return nil
	}
	for i, arg := range args {
		if arg != "--file" || i+1 >= len(args) {
			continue
		}
		parent, err := fileaccess.OpenDirectory(filepath.Dir(args[i+1]))
		if err != nil {
			return err
		}
		defer parent.Close()
		if err = fileaccess.CheckPrivate(parent, true); err != nil {
			return err
		}
		file, err := fileaccess.OpenPrivateAt(parent, filepath.Base(args[i+1]), os.O_RDONLY)
		if err != nil {
			return err
		}
		defer file.Close()
		body, err := io.ReadAll(file)
		if err != nil {
			return err
		}
		if string(body) != "hermetic build input" {
			r.t.Fatal("build input changed")
		}
		_, err = stdout.Write([]byte("hermetic output"))
		return err
	}
	r.t.Fatal("missing build input argument")
	return nil
}
func TestWindowsBuildxInputIsPrivateBeforeRunner(t *testing.T) {
	_, err := (buildxExporter{runner: privateBuildInputRunner{t}}).ExportOCI(t.Context(), agentImage{AgentkitFile: []byte("hermetic build input")}, io.Discard)
	if err != nil {
		t.Fatalf("private build input rejected: %v", err)
	}
}

func TestWindowsLocalBuildxRunnerCancellationTerminatesOwnedChild(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan struct{})
	var runErr error
	go func() {
		runErr = (localBuildxRunner{}).Run(ctx, io.Discard, io.Discard, exe, "-test.run=^TestWindowsBuildxCancellationHelper$", "--", dir)
		close(finished)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-finished:
		case <-time.After(15 * time.Second):
			t.Error("owned child did not stop after cancellation")
		}
	})
	waitBuildxHelperReady(t, filepath.Join(dir, "ready"), finished)
	cancel()
	select {
	case <-finished:
		if runErr == nil {
			t.Fatal("canceled child reported success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Windows cancellation waited for unsupported interrupt grace instead of terminating the owned process")
	}
}
func TestWindowsBuildxCancellationHelper(t *testing.T) {
	args := os.Args
	if len(args) < 2 || args[len(args)-2] != "--" {
		return
	}
	if err := os.WriteFile(filepath.Join(args[len(args)-1], "ready"), []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Minute)
}
