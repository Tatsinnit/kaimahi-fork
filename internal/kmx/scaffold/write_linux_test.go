//go:build linux

package scaffold

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kaimahi-agents/kaimahi/internal/kmx/fileaccess"
)

// A scaffold output on a Windows drive mount is refused by name before any
// directory or file is created. Hosts without a drvfs mount skip.
func TestWriteNewRefusesWindowsDriveMountFirst(t *testing.T) {
	for _, drive := range []string{"/mnt/c", "/mnt/d"} {
		if !errors.Is(fileaccess.RefuseWindowsDriveMount(drive), fileaccess.ErrWindowsDriveMount) {
			continue
		}
		dir := filepath.Join(drive, fmt.Sprintf("kmx-scaffold-guard-%d", time.Now().UnixNano()))
		path := filepath.Join(dir, "agent.yaml")
		err := WriteNew(path, "x\n")
		if !errors.Is(err, fileaccess.ErrWindowsDriveMount) || !strings.Contains(err.Error(), path) {
			t.Fatalf("drive-mounted output not refused by name: %v", err)
		}
		if _, err := os.Lstat(dir); !os.IsNotExist(err) {
			t.Fatalf("refused output created %s: %v", dir, err)
		}
		return
	}
	t.Skip("no Windows drive (WSL drvfs) mount on this host")
}
