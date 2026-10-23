package fileaccess

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
)

// PublicationResult records whether an exclusive publication crossed its
// visibility boundary. Visible can be true together with an error when complete
// bytes are present but post-link persistence was not acknowledged.
type PublicationResult struct {
	Visible bool
}

var (
	publicationEntropy = rand.Read
	writePrivateBytes  = func(file *PrivateFile, data []byte) error {
		n, err := file.file.Write(data)
		if err == nil && n != len(data) {
			err = io.ErrShortWrite
		}
		return err
	}
	syncPrivateFile    = func(file *PrivateFile) error { return file.file.Sync() }
	afterPrivateLink   = func() error { return nil }
	linkPublishedEntry = linkPrivateEntry
	removeStagedEntry  = removePrivateEntry
	syncPublishedDir   = SyncDirectory
)

// PublishPrivate writes complete private bytes and publishes name exactly once
// below directory. It flushes the staged file before the exclusive hard-link
// visibility point, then removes the owned stage and flushes the anchored
// directory. It never replaces, retries, or removes a visible destination.
func PublishPrivate(ctx context.Context, directory *Directory, name string, data []byte) (result PublicationResult, err error) {
	if err := checkContext(ctx); err != nil {
		return result, err
	}
	if err := checkPrivateComponent(name); err != nil {
		return result, wrapAccess("publish private file", err)
	}
	if err := CheckPrivate(ctx, directory, true); err != nil {
		return result, wrapAccess("publish private file", err)
	}

	stage, file, identity, err := createPublicationStage(ctx, directory)
	if err != nil {
		return result, wrapAccess("publish private file", err)
	}
	stagePresent := true
	stageRemovalAttempted := false
	defer func() {
		var cleanupErr error
		if file != nil {
			if closeErr := file.Close(); closeErr != nil {
				cleanupErr = errors.Join(cleanupErr, closeErr)
			}
		}
		if stagePresent && !stageRemovalAttempted {
			if removeErr := removeStagedEntry(context.Background(), directory, stage, identity); removeErr != nil {
				cleanupErr = errors.Join(cleanupErr, removeErr)
			}
		}
		if cleanupErr != nil {
			err = wrapPublicationError(result.Visible, unreadableCause("private publication cleanup is uncertain"))
			return
		}
		if err != nil {
			err = wrapPublicationError(result.Visible, err)
		}
	}()

	if err := writePrivateBytes(file, data); err != nil {
		return result, wrapAccess("write private stage", err)
	}
	if err := syncPrivateFile(file); err != nil {
		return result, wrapAccess("sync private stage", err)
	}
	if err := checkContext(ctx); err != nil {
		return result, err
	}
	if err := file.Close(); err != nil {
		file = nil
		return result, wrapAccess("close private stage", err)
	}
	file = nil
	if err := CheckPrivate(ctx, directory, true); err != nil {
		return result, wrapAccess("publish private file", err)
	}
	visible, linkErr := linkPublishedEntry(ctx, directory, stage, name, identity)
	result.Visible = visible
	if linkErr == nil {
		linkErr = afterPrivateLink()
	}
	if linkErr != nil {
		return result, wrapAccess("publish private file", linkErr)
	}
	if err := requirePrivateEntryIdentity(ctx, directory, name, identity); err != nil {
		return result, wrapAccess("verify published file", err)
	}
	if err := checkContext(ctx); err != nil {
		return result, err
	}
	stageRemovalAttempted = true
	if err := removeStagedEntry(ctx, directory, stage, identity); err != nil {
		return result, unreadableCause("private publication cleanup is uncertain")
	}
	stagePresent = false
	if err := syncPublishedDir(ctx, directory); err != nil {
		return result, err
	}
	if err := checkContext(ctx); err != nil {
		return result, err
	}
	return result, nil
}

func wrapPublicationError(visible bool, err error) error {
	if err == nil {
		return nil
	}
	operation := "publish private file"
	if visible {
		operation = "persist visible private file"
	}
	return wrapAccess(operation, err)
}

func createPublicationStage(ctx context.Context, directory *Directory) (string, *PrivateFile, string, error) {
	for range 16 {
		raw := make([]byte, 16)
		if _, err := publicationEntropy(raw); err != nil {
			return "", nil, "", err
		}
		name := ".kmx-stage-" + hex.EncodeToString(raw)
		file, err := CreatePrivateFileAt(ctx, directory, name)
		if err != nil {
			if errors.Is(err, errEntryExists) {
				continue
			}
			return "", nil, "", err
		}
		if file.identity == "" {
			closeErr := file.Close()
			return "", nil, "", creationFailure(unreadableCause("created private file identity is unavailable"), closeErr)
		}
		return name, file, file.identity, nil
	}
	return "", nil, "", unsafeCause("private stage names collided")
}

func requirePrivateEntryIdentity(ctx context.Context, directory *Directory, name, identity string) error {
	file, err := openExistingPrivateFileAt(ctx, directory, name)
	if err != nil {
		return err
	}
	got, identityErr := PhysicalIdentity(ctx, file)
	closeErr := file.Close()
	if identityErr != nil || closeErr != nil {
		return errors.Join(identityErr, closeErr)
	}
	if got != identity {
		return unsafeCause("private entry identity changed")
	}
	return nil
}

func observedPrivateEntry(ctx context.Context, directory *Directory, name, identity string, effectErr error) (bool, error) {
	err := requirePrivateEntryIdentity(ctx, directory, name, identity)
	if err == nil {
		return true, effectErr
	}
	if errors.Is(err, ErrMissing) {
		return false, effectErr
	}
	return false, errors.Join(effectErr, err)
}
