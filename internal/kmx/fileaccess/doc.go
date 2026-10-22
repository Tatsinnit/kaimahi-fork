// Package fileaccess provides package-independent checked, read-only filesystem
// access through opaque handles.
//
// It opens existing files and directories without following links, validates
// private or public-ancestor security, and reports physical object identity. On
// Windows, every retained handle is qualified as local-disk NTFS with persistent
// ACLs. The package remains unwired from operation adapters and deliberately
// provides no create, write, lock, rename, link, delete, sync, state-resolution,
// publication, or repair authority.
package fileaccess
