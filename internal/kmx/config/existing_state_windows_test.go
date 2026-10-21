//go:build windows

package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestExistingStateDirAbsentIsInert(t *testing.T) {
	home := filepath.Join(privateStateHome(t), "absent")
	t.Setenv("KMX_HOME", home)
	if _, err := ExistingStateDir(); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("absent read-only state: %v", err)
	}
	assertAbsent(t, home)
}

func TestExistingStateDirChecksPrivateRootWithoutWrites(t *testing.T) {
	home := privateStateHome(t)
	t.Setenv("KMX_HOME", home)
	got, err := ExistingStateDir()
	if err != nil || got != home {
		t.Fatalf("existing private state = %q, %v", got, err)
	}
	assertOwnerOnly(t, home)
	entries, err := os.ReadDir(home)
	if err != nil || len(entries) != 0 {
		t.Fatalf("read-only lookup changed state: %v, %v", entries, err)
	}
}

func TestExistingStateDirRefusesUnsafeParentWithoutRepair(t *testing.T) {
	parent := privateStateHome(t)
	home := filepath.Join(parent, "state")
	t.Setenv("KMX_HOME", home)
	if _, err := StateDir(); err != nil {
		t.Fatal(err)
	}
	grantEveryone(t, parent)
	assertOwnerOnly(t, home)
	before := securityDescriptor(t, parent).String()
	if _, err := ExistingStateDir(); err == nil {
		t.Fatal("read-only state accepted an unsafe immediate parent")
	}
	if after := securityDescriptor(t, parent).String(); after != before {
		t.Fatal("read-only lookup repaired the parent DACL")
	}
}

func TestExistingStateDirRefusesUnsafeRootWithoutRepair(t *testing.T) {
	home := privateStateHome(t)
	t.Setenv("KMX_HOME", home)
	grantEveryone(t, home)
	before := securityDescriptor(t, home).String()
	if _, err := ExistingStateDir(); err == nil {
		t.Fatal("read-only lookup accepted broad state")
	}
	if after := securityDescriptor(t, home).String(); after != before {
		t.Fatal("read-only lookup repaired the root DACL")
	}
}
