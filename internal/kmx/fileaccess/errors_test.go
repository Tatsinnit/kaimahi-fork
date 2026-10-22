package fileaccess

import (
	"errors"
	"io/fs"
	"strings"
	"testing"
)

func TestAccessErrorClassesAndText(t *testing.T) {
	canary := "private-path-and-sid-canary"
	for _, tc := range []struct {
		class  ErrorClass
		target error
	}{
		{ClassMissing, ErrMissing},
		{ClassUnsafe, ErrUnsafe},
		{ClassUnsupported, ErrUnsupported},
		{ClassUnreadable, ErrUnreadable},
	} {
		err := wrapAccess("fixed operation", &classifiedCause{class: tc.class, cause: errors.New(canary)})
		if !errors.Is(err, tc.target) {
			t.Errorf("class %s does not match %v: %v", tc.class, tc.target, err)
		}
		if strings.Contains(err.Error(), canary) {
			t.Errorf("class %s leaked its cause: %v", tc.class, err)
		}
		for _, other := range []error{ErrMissing, ErrUnsafe, ErrUnsupported, ErrUnreadable} {
			if other != tc.target && errors.Is(err, other) {
				t.Errorf("class %s also matched %v: %v", tc.class, other, err)
			}
		}
	}
	if err := wrapAccess("read", fs.ErrNotExist); !errors.Is(err, ErrMissing) || !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("not-exist identity lost: %v", err)
	}
	if err := wrapAccess("read", fs.ErrPermission); !errors.Is(err, ErrUnreadable) || !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("permission identity lost: %v", err)
	}
}
