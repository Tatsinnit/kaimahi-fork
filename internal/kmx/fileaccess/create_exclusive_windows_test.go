//go:build windows

package fileaccess

import (
	"os"
	"testing"
)

func TestCreatePrivateDirectoryAtRefusesAnExistingObject(t *testing.T) {
	parent := faOpenDir(t, faPrivateDir(t))
	created, err := CreatePrivateDirectoryAt(parent, "reservation")
	if err != nil {
		t.Fatal(err)
	}
	defer created.Close()
	if err := CheckPrivate(created, true); err != nil {
		t.Fatal(err)
	}
	if other, err := CreatePrivateDirectoryAt(parent, "reservation"); !os.IsExist(err) {
		if other != nil {
			other.Close()
		}
		t.Fatalf("existing private reservation = %v, want exclusive-create refusal", err)
	}
}
