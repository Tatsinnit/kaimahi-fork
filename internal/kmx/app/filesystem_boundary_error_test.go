package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/kaimahi-agents/kaimahi/internal/kmx/fileaccess"
)

const boundaryCanary = "PRIVATE-CANARY-payload"

func TestFilesystemBoundaryErrorSurfacesOnlyDriveMountRefusal(t *testing.T) {
	class := errors.New("redacted boundary class")
	for _, err := range []error{nil, errors.New(boundaryCanary), fmt.Errorf("%s: %w", boundaryCanary, os.ErrPermission), errors.Join(errors.New(boundaryCanary), context.Canceled)} {
		if got := filesystemBoundaryError(class, err); got != class {
			t.Fatalf("non-mount cause escaped redaction: %v", got)
		}
	}
	for _, err := range []error{
		fileaccess.ErrWindowsDriveMount,
		fmt.Errorf("%s: %w", boundaryCanary, fileaccess.ErrWindowsDriveMount),
		errors.Join(errors.New(boundaryCanary), fmt.Errorf("%s: %w", boundaryCanary, fileaccess.ErrWindowsDriveMount)),
	} {
		got := filesystemBoundaryError(class, err)
		if !errors.Is(got, class) || !errors.Is(got, fileaccess.ErrWindowsDriveMount) || strings.Contains(got.Error(), boundaryCanary) {
			t.Fatalf("drive-mount refusal lost class or leaked payload: %v", got)
		}
	}
}

func TestSuiteEvaluationErrorKeepsPhaseAndCancelForDriveMount(t *testing.T) {
	mount := fmt.Errorf("%s: %w", boundaryCanary, fileaccess.ErrWindowsDriveMount)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	got := suiteEvaluationError(cancelled, mount, true)
	if !errors.Is(got, errSuiteNativeEvaluation) || !errors.Is(got, context.Canceled) || !errors.Is(got, fileaccess.ErrWindowsDriveMount) || strings.Contains(got.Error(), boundaryCanary) {
		t.Fatalf("ambiguous-phase drive-mount error lost identity or leaked: %v", got)
	}
	got = suiteEvaluationError(context.Background(), mount, false)
	if !errors.Is(got, errSuiteNativeRefused) || errors.Is(got, errSuiteNativeEvaluation) || !errors.Is(got, fileaccess.ErrWindowsDriveMount) || strings.Contains(got.Error(), boundaryCanary) {
		t.Fatalf("pre-change drive-mount error lost phase or leaked: %v", got)
	}
	got = suiteEvaluationError(cancelled, errors.New(boundaryCanary), false)
	if !errors.Is(got, errSuiteNativeRefused) || !errors.Is(got, context.Canceled) || errors.Is(got, fileaccess.ErrWindowsDriveMount) || strings.Contains(got.Error(), boundaryCanary) {
		t.Fatalf("non-mount evaluation error escaped redaction: %v", got)
	}
}
