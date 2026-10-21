package app

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSuitePassingExportExclusiveCompletePrivate(t *testing.T) {
	root, prepared, suite, placement, observations := passingFixture(t)
	receipt, err := newSuitePassingReceipt(t.Context(), prepared, placement, observations)
	if err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(privateSuiteDir(t), "receipt.json")
	first, err := preflightSuitePassingExport(t.Context(), destination, root, filepath.Dir(prepared.Path))
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := preflightSuitePassingExport(t.Context(), destination, root, filepath.Dir(prepared.Path))
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	results := make(chan error, 2)
	for _, export := range []*suitePassingExport{first, second} {
		go func() { results <- export.publish(t.Context(), receipt, suite) }()
	}
	a, b := <-results, <-results
	if (a == nil) == (b == nil) {
		t.Fatalf("exclusive winner missing: %v / %v", a, b)
	}
	info, err := os.Stat(destination)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("not a private receipt", err)
	}
	entries, err := os.ReadDir(filepath.Dir(destination))
	if err != nil || len(entries) != 1 {
		t.Fatal("staging residue", err)
	}
	read, err := readSuitePassingReceipt(t.Context(), destination)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := canonicalSuitePassingReceipt(t.Context(), receipt, suite)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := canonicalSuitePassingReceipt(t.Context(), read, suite)
	if err != nil || !bytes.Equal(actual, expected) {
		t.Fatal("publication incomplete", err)
	}
}

func TestSuitePassingExportPreflightAndPublishRefusals(t *testing.T) {
	root, prepared, suite, placement, observations := passingFixture(t)
	receipt, err := newSuitePassingReceipt(t.Context(), prepared, placement, observations)
	if err != nil {
		t.Fatal(err)
	}
	for _, refusal := range []string{"existing", "directory", "symlink file", "symlink parent", "public parent", "workspace", "cache", "canceled", "collision after preflight", "cancel after preflight", "incoherent", "parent moved"} {
		t.Run(refusal, func(t *testing.T) {
			parent := privateSuiteDir(t)
			destination := filepath.Join(parent, "receipt.json")
			ctx := t.Context()
			switch refusal {
			case "existing":
				writeFile(t, destination, "original")
			case "directory":
				if err := os.Mkdir(destination, 0700); err != nil {
					t.Fatal(err)
				}
			case "symlink file":
				if err := os.Symlink(filepath.Join(parent, "missing"), destination); err != nil {
					t.Fatal(err)
				}
			case "symlink parent":
				alias := filepath.Join(t.TempDir(), "alias")
				if err := os.Symlink(parent, alias); err != nil {
					t.Fatal(err)
				}
				destination = filepath.Join(alias, "receipt.json")
			case "public parent":
				if err := os.Chmod(parent, 0750); err != nil {
					t.Fatal(err)
				}
			case "workspace":
				if err := os.Chmod(root, 0700); err != nil {
					t.Fatal(err)
				}
				destination = filepath.Join(root, "eval", "..", "receipt.json")
			case "cache":
				destination = filepath.Join(filepath.Dir(prepared.Path), "receipt.json")
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			export, err := preflightSuitePassingExport(ctx, destination, root, filepath.Dir(prepared.Path))
			late := strings.Contains(refusal, "after preflight") || refusal == "incoherent" || refusal == "parent moved"
			if !late {
				want := errSuitePassingFile
				if refusal == "canceled" {
					want = context.Canceled
				}
				if !errors.Is(err, want) {
					if export != nil {
						export.Close()
					}
					t.Fatalf("wrong preflight refusal: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal("preflight prerequisite failed", err)
			}
			defer export.Close()
			r := *receipt
			switch refusal {
			case "collision after preflight":
				writeFile(t, destination, "original")
			case "cancel after preflight":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "incoherent":
				r.Subject.PayloadDigest = strings.Repeat("0", 64)
			case "parent moved":
				if err := os.Rename(parent, parent+"-moved"); err != nil {
					t.Fatal(err)
				}
				defer os.RemoveAll(parent + "-moved")
				if err := os.Mkdir(parent, 0700); err != nil {
					t.Fatal(err)
				}
			}
			want := errSuitePassingExport
			if refusal == "cancel after preflight" {
				want = context.Canceled
			} else if refusal == "incoherent" {
				want = errSuitePassingReceipt
			}
			if err := export.publish(ctx, &r, suite); !errors.Is(err, want) {
				t.Fatalf("wrong publication refusal: %v", err)
			}
			raw, err := os.ReadFile(destination)
			if refusal == "collision after preflight" {
				if err != nil || string(raw) != "original" {
					t.Fatal("overwrote collision", err)
				}
			} else if !os.IsNotExist(err) {
				t.Fatal("refusal published output", err)
			}
		})
	}
}

func TestSuitePassingExportFileSyncFailureBeforePublication(t *testing.T) {
	destination := filepath.Join(privateSuiteDir(t), "receipt.json")
	export, err := preflightSuitePassingExport(t.Context(), destination, t.TempDir(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer export.Close()
	raw := []byte("complete stage before file flush\n")
	called := false
	export.beforeFileSync = func(file *os.File) {
		called = true
		info, err := file.Stat()
		if err != nil || info.Size() != int64(len(raw)) {
			t.Fatalf("file flush reached before complete write: %v, %v", info, err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err := export.publishBytes(t.Context(), raw); !errors.Is(err, errSuitePassingExport) {
		t.Fatalf("file flush failure = %v, want publication refusal", err)
	}
	if !called || export.linked {
		t.Fatalf("file flush fault not enforced before link: called=%v linked=%v", called, export.linked)
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		t.Fatalf("file flush failure published an output: %v", err)
	}
	entries, err := os.ReadDir(filepath.Dir(destination))
	if err != nil || len(entries) != 0 {
		t.Fatalf("failed stage left residue: %v, %v", entries, err)
	}
}

// The production publisher orders a complete write, a successful file flush,
// the exclusive link and then the directory flush. The hooks observe the real
// publisher at its own boundaries; the output stays invisible until the link.
func TestSuitePassingExportRawPublicationOrder(t *testing.T) {
	destination := filepath.Join(privateSuiteDir(t), "receipt.json")
	export, err := preflightSuitePassingExport(t.Context(), destination, t.TempDir(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer export.Close()
	raw := []byte("complete private publication\n")
	var events []string
	invisible := func(stage string) {
		if _, err := os.Lstat(destination); !os.IsNotExist(err) {
			t.Errorf("output visible before %s: %v", stage, err)
		}
	}
	export.beforeFileSync = func(file *os.File) {
		info, err := file.Stat()
		if err != nil || info.Size() != int64(len(raw)) {
			t.Errorf("file flush reached before complete write: %v, %v", info, err)
		}
		invisible("file flush")
		events = append(events, "written")
	}
	export.beforeLink = func() error {
		invisible("link")
		events = append(events, "file-flushed")
		return nil
	}
	if err := export.publishBytes(t.Context(), raw); err != nil {
		t.Fatal(err)
	}
	if strings.Join(events, ",") != "written,file-flushed" || !export.linked {
		t.Fatalf("publication order = %v linked=%v", events, export.linked)
	}
	if got, err := os.ReadFile(destination); err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("published bytes = %q, %v", got, err)
	}
	entries, err := os.ReadDir(filepath.Dir(destination))
	if err != nil || len(entries) != 1 || entries[0].Name() != "receipt.json" {
		t.Fatalf("publication left stage residue: %v, %v", entries, err)
	}
}

// A directory flush failure after the exclusive link leaves the complete
// output visible but is never acknowledged as durable success.
func TestSuitePassingExportDirectorySyncFailureAfterLink(t *testing.T) {
	destination := filepath.Join(privateSuiteDir(t), "receipt.json")
	export, err := preflightSuitePassingExport(t.Context(), destination, t.TempDir(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer export.Close()
	raw := []byte("complete stage, directory flush fails\n")
	closed := false
	export.beforeLink = func() error {
		closed = true
		return export.directory.Close()
	}
	if err := export.publishBytes(t.Context(), raw); !errors.Is(err, errSuitePassingExport) {
		t.Fatalf("directory flush failure = %v, want publication uncertainty", err)
	}
	if !closed || !export.linked {
		t.Fatalf("directory flush fault not after link: closed=%v linked=%v", closed, export.linked)
	}
	info, err := os.Lstat(destination)
	if err != nil || info.Size() == 0 {
		t.Fatalf("linked output missing or empty: %v, %v", info, err)
	}
	if got, err := os.ReadFile(destination); err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("visible output incomplete = %q, %v", got, err)
	}
	entries, err := os.ReadDir(filepath.Dir(destination))
	if err != nil || len(entries) != 1 {
		t.Fatalf("publication left stage residue: %v, %v", entries, err)
	}
}

func TestSuitePassingExportReportsPublicationSyncFailureHonestly(t *testing.T) {
	root, prepared, suite, placement, observations := passingFixture(t)
	receipt, err := newSuitePassingReceipt(t.Context(), prepared, placement, observations)
	if err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(privateSuiteDir(t), "receipt.json")
	export, err := preflightSuitePassingExport(t.Context(), destination, root, filepath.Dir(prepared.Path))
	if err != nil {
		t.Fatal(err)
	}
	defer export.Close()
	if err := export.directory.Close(); err != nil {
		t.Fatal(err)
	}
	if err := export.publish(t.Context(), receipt, suite); err == nil || !strings.Contains(err.Error(), "output may exist") {
		t.Fatalf("dishonest sync failure: %v", err)
	}
	if _, err := readSuitePassingReceipt(t.Context(), destination); err != nil {
		t.Fatal("expected complete output after actual link", err)
	}
}

func TestSuitePassingReceiptPrivateReader(t *testing.T) {
	_, prepared, suite, placement, observations := passingFixture(t)
	receipt, err := newSuitePassingReceipt(t.Context(), prepared, placement, observations)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := canonicalSuitePassingReceipt(t.Context(), receipt, suite)
	if err != nil {
		t.Fatal(err)
	}
	for _, refusal := range []string{"public file", "public parent", "symlink", "directory", "oversize", "malformed", "canceled"} {
		t.Run(refusal, func(t *testing.T) {
			parent := privateSuiteDir(t)
			name := filepath.Join(parent, "receipt.json")
			ctx := t.Context()
			if err := os.WriteFile(name, raw, 0600); err != nil {
				t.Fatal(err)
			}
			var setupErr error
			switch refusal {
			case "public file":
				setupErr = os.Chmod(name, 0644)
			case "public parent":
				setupErr = os.Chmod(parent, 0750)
			case "symlink":
				if err := os.Remove(name); err != nil {
					t.Fatal(err)
				}
				setupErr = os.Symlink("missing", name)
			case "directory":
				if err := os.Remove(name); err != nil {
					t.Fatal(err)
				}
				setupErr = os.Mkdir(name, 0700)
			case "oversize":
				setupErr = os.WriteFile(name, []byte(strings.Repeat(" ", maxSuitePassingReceiptBytes+1)), 0600)
			case "malformed":
				if err := os.WriteFile(name, []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if setupErr != nil {
				t.Fatal(setupErr)
			}
			want := errSuitePassingFile
			if refusal == "malformed" {
				want = errSuitePassingReceipt
			} else if refusal == "canceled" {
				want = context.Canceled
			}
			if _, err := readSuitePassingReceipt(ctx, name); !errors.Is(err, want) || strings.Contains(err.Error(), name) {
				t.Fatalf("wrong private-reader refusal/error: %v", err)
			}
		})
	}
}
