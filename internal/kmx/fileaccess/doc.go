// Package fileaccess provides checked, read-only filesystem access.
//
// It opens existing files and directories without following links, validates
// private or public-ancestor security, and reports physical object identity.
// It deliberately provides no create, write, lock, rename, link, delete, sync,
// state-resolution, publication, or repair authority.
package fileaccess
