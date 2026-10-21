package oras

import (
	"github.com/kaimahi-agents/kaimahi/internal/kmx/fileaccess"
	"oras.land/oras-go/v2/content/oci"
)

// newPrivateStore opens an ORAS layout store whose root KMX created as a
// private directory. ORAS creates its own blobs, ingest files and index with
// inherited security, so on Windows the token's default owner must be the
// user before it writes anything; callers check the resulting tree with
// verifyPrivateTree before relying on or publishing it.
func newPrivateStore(root string) (*oci.Store, error) {
	if err := fileaccess.CheckDefaultPrivateOwner(); err != nil {
		return nil, err
	}
	return oci.New(root)
}
