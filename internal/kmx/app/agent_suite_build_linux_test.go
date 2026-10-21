//go:build linux

package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	kmxsuite "github.com/kaimahi-agents/kaimahi/internal/kmx/agentsuite"
	"github.com/kaimahi-agents/kaimahi/internal/kmx/fileaccess"
)

// A build output on a Windows drive mount is refused by name before the
// builder runs or any stage is created. Hosts without a drvfs mount skip.
func TestBuildSuiteRefusesWindowsDriveMountBeforeBuilding(t *testing.T) {
	for _, drive := range []string{"/mnt/c", "/mnt/d"} {
		if !errors.Is(fileaccess.RefuseWindowsDriveMount(drive), fileaccess.ErrWindowsDriveMount) {
			continue
		}
		dir := filepath.Join(drive, fmt.Sprintf("kmx-build-guard-%d", time.Now().UnixNano()))
		output := filepath.Join(dir, "image.oci.tar")
		called := false
		builder := sandboxBuilderFunc(func(context.Context, kmxsuite.SandboxPlan, io.Writer) (kmxsuite.BuildResult, error) {
			called = true
			return kmxsuite.BuildResult{}, nil
		})
		_, err := (&App{}).BuildSuite(context.Background(), minimalSuitePath(), output, kmxsuite.BuildSelection{}, builder)
		if !errors.Is(err, fileaccess.ErrWindowsDriveMount) || !strings.Contains(err.Error(), output) || called {
			t.Fatalf("drive-mounted output not refused first: called=%v err=%v", called, err)
		}
		if _, err := os.Lstat(dir); !os.IsNotExist(err) {
			t.Fatalf("refused output created %s: %v", dir, err)
		}
		return
	}
	t.Skip("no Windows drive (WSL drvfs) mount on this host")
}
