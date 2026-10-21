package run

import (
	"reflect"
	"testing"
)

// Windows must remove every case alias; Unix must retain distinct names.
func TestEnvironPlatformNameMatching(t *testing.T) {
	base := []string{"Path=first", "PATH=second", "OTHER=keep", "=C:=C:\\workspace"}
	for _, tc := range []struct {
		name string
		fold bool
		want []string
	}{
		{"unix", false, []string{"Path=first", "OTHER=keep", "=C:=C:\\workspace", "PATH=explicit"}},
		{"windows", true, []string{"OTHER=keep", "=C:=C:\\workspace", "PATH=explicit"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := environ(base, []string{"PATH=explicit"}, []string{"PATH"}, tc.fold)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("child environment = %q, want %q", got, tc.want)
			}
		})
	}
}
