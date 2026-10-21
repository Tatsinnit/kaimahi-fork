package fileaccess

import (
	"bufio"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The helper re-executes this test binary rather than building a program, so
// native runs need no Go toolchain on the target host.
const lockHelperEnv = "KMX_FILEACCESS_LOCK_HELPER"

// TestFileaccessLockHelperProcess is the helper body, inert in ordinary runs.
// It opens the lock file named by the environment, reports "locked" or
// "busy", then holds its handle until stdin closes.
func TestFileaccessLockHelperProcess(t *testing.T) {
	path := os.Getenv(lockHelperEnv)
	if path == "" {
		return
	}
	parent, err := OpenDirectory(filepath.Dir(path))
	if err != nil {
		os.Stdout.WriteString("error " + err.Error() + "\n")
		os.Exit(2)
	}
	file, err := OpenPrivateAt(parent, filepath.Base(path), os.O_RDWR)
	if err != nil {
		os.Stdout.WriteString("error " + err.Error() + "\n")
		os.Exit(2)
	}
	if TryLock(file) != nil {
		os.Stdout.WriteString("busy\n")
	} else {
		os.Stdout.WriteString("locked\n")
	}
	_, _ = io.Copy(io.Discard, os.Stdin)
	os.Exit(0)
}

type lockHelper struct {
	cmd   *exec.Cmd
	stdin io.WriteCloser
	state string
}

func startLockHelper(t *testing.T, path string) *lockHelper {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestFileaccessLockHelperProcess$")
	cmd.Env = append(os.Environ(), lockHelperEnv+"="+path)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	h := &lockHelper{cmd: cmd, stdin: stdin}
	t.Cleanup(func() {
		_ = stdin.Close()
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		t.Fatalf("read helper state: %v (%q)", err, line)
	}
	h.state = strings.TrimSpace(line)
	return h
}

func (h *lockHelper) release(t *testing.T) {
	t.Helper()
	_ = h.stdin.Close()
	if err := h.cmd.Wait(); err != nil {
		t.Fatalf("helper exit: %v", err)
	}
}

func (h *lockHelper) kill(t *testing.T) {
	t.Helper()
	if err := h.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = h.cmd.Wait()
}

func faLockFile(t *testing.T) (string, *os.File) {
	t.Helper()
	dir := faPrivateDir(t)
	parent := faOpenDir(t, dir)
	file, err := OpenPrivateAt(parent, "lock", os.O_RDWR|os.O_CREATE|os.O_EXCL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	return filepath.Join(dir, "lock"), file
}

// tryLockEventually allows for the operating system's asynchronous release
// of a dead process's locks; it never waits for a live holder.
func tryLockEventually(t *testing.T, file *os.File) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		err := TryLock(file)
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("lock was not released: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestTryLockAcrossProcesses(t *testing.T) {
	t.Run("HelperHoldsUntilRelease", func(t *testing.T) {
		path, file := faLockFile(t)
		helper := startLockHelper(t, path)
		if helper.state != "locked" {
			t.Fatalf("helper state %q, want locked", helper.state)
		}
		if err := TryLock(file); err == nil {
			t.Fatal("TryLock succeeded while another process holds the lock")
		}
		helper.release(t)
		tryLockEventually(t, file)
	})
	t.Run("ParentHoldsHelperBusy", func(t *testing.T) {
		path, file := faLockFile(t)
		if err := TryLock(file); err != nil {
			t.Fatal(err)
		}
		if helper := startLockHelper(t, path); helper.state != "busy" {
			t.Fatalf("helper state %q, want busy", helper.state)
		}
	})
	t.Run("ProcessDeathReleases", func(t *testing.T) {
		path, file := faLockFile(t)
		helper := startLockHelper(t, path)
		if helper.state != "locked" {
			t.Fatalf("helper state %q, want locked", helper.state)
		}
		helper.kill(t)
		tryLockEventually(t, file)
	})
}
