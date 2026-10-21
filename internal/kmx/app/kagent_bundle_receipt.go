package app

import (
	"fmt"
	"io"
	"os"
)

const kagentVersionMarker = "kaimahi.dev/runtime-version"

const maxKagentFileBytes = 1 << 20

// openKagentFile is platform-specific: a single-component no-follow open
// relative to the retained directory handle (see fspolicy_*.go).

// The size limit applies to bytes actually read, not just a pre-read stat.
// Revalidate the same descriptor to refuse growth, truncation or permission
// changes; pathname substitution cannot redirect this read to another file.
// Private files are checked on the opened handle before any byte is read and
// again after the read.

func readKagentOpenedFile(file *os.File, before os.FileInfo, private bool) ([]byte, error) {
	if !before.Mode().IsRegular() || before.Size() > maxKagentFileBytes || private && !privateFileOK(file, before) {
		return nil, fmt.Errorf("Kagent file must be a bounded regular file (private for receipts), not a link")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxKagentFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read Kagent file: %w", err)
	}
	after, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect opened Kagent file: %w", err)
	}
	if len(raw) > maxKagentFileBytes || int64(len(raw)) != before.Size() || after.Size() != before.Size() || after.Mode() != before.Mode() || !after.ModTime().Equal(before.ModTime()) || private && !privateFileOK(file, after) {
		return nil, fmt.Errorf("Kagent file changed or exceeded its bound during read")
	}
	return raw, nil
}
