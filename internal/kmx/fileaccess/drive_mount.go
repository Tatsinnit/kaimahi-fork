package fileaccess

import "errors"

// ErrWindowsDriveMount identifies a Linux-side KMX state, cache or output
// path that lives on a Windows drive mount (WSL drvfs). Mixed native/WSL
// writes to such paths are unsupported rather than silently coordinated.
// The concrete error message names the offending path and the remedy and
// carries no file content, so redacting renderers may print it verbatim.
var ErrWindowsDriveMount = errors.New("path is on a Windows drive mount")
