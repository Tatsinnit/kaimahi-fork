package fileaccess

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestProductionSurfaceIsReadOnly(t *testing.T) {
	exportedFunctions := map[string]bool{}
	exportedTypes := map[string]bool{}
	banned := map[string]bool{
		"Create": true, "CreateFile": true, "FlushFileBuffers": true,
		"Flock": true, "Link": true, "LockFileEx": true, "Mkdir": true,
		"MoveFileEx": true, "NtSetInformationFile": true,
		"MkdirAll": true, "OpenFile": true, "Remove": true, "RemoveAll": true,
		"Rename": true, "ReplaceFile": true, "SetEndOfFile": true,
		"SetFileInformationByHandle": true, "SetFileSecurity": true,
		"SetFileTime": true, "SetNamedSecurityInfo": true, "SetSecurityInfo": true, "Sync": true,
		"Truncate": true, "Write": true, "WriteAt": true, "WriteFile": true,
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			switch value := decl.(type) {
			case *ast.FuncDecl:
				if value.Recv == nil && ast.IsExported(value.Name.Name) {
					exportedFunctions[value.Name.Name] = true
				}
			case *ast.GenDecl:
				if value.Tok == token.TYPE {
					for _, spec := range value.Specs {
						name := spec.(*ast.TypeSpec).Name.Name
						if ast.IsExported(name) {
							exportedTypes[name] = true
						}
					}
				}
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			switch value := node.(type) {
			case *ast.SelectorExpr:
				if banned[value.Sel.Name] {
					t.Errorf("%s calls phase-3 operation %s", name, value.Sel.Name)
				}
			case *ast.Ident:
				if strings.HasPrefix(value.Name, "FILE_CREATE") || strings.HasPrefix(value.Name, "FILE_OPEN_IF") || strings.HasPrefix(value.Name, "FILE_OVERWRITE") || value.Name == "GENERIC_WRITE" || value.Name == "FILE_GENERIC_WRITE" {
					t.Errorf("%s contains phase-3 Windows authority %s", name, value.Name)
				}
			}
			return true
		})
	}
	names := make([]string, 0, len(exportedFunctions))
	for name := range exportedFunctions {
		names = append(names, name)
	}
	slices.Sort(names)
	want := []string{"CheckPrivate", "CheckSafeDirectory", "OpenDirectory", "OpenDirectoryAt", "OpenRegularAt", "PhysicalIdentity"}
	if !slices.Equal(names, want) {
		t.Fatalf("exported functions = %v, want exactly %v", names, want)
	}
	types := make([]string, 0, len(exportedTypes))
	for name := range exportedTypes {
		types = append(types, name)
	}
	slices.Sort(types)
	wantTypes := []string{"AccessError", "Directory", "ErrorClass", "File", "Object"}
	if !slices.Equal(types, wantTypes) {
		t.Fatalf("exported types = %v, want exactly %v", types, wantTypes)
	}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") || name == "doc.go" {
			continue
		}
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"internal/kmx/app", "internal/kmx/config", "internal/kmx/agentsuite", "internal/kmx/toolchain"} {
			if strings.Contains(string(data), forbidden) {
				t.Errorf("%s imports or names operation package %s", name, forbidden)
			}
		}
	}
}

func TestFoundationHasNoProductionConsumers(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == ".git" || entry.Name() == "node_modules" || entry.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" || strings.Contains(path, string(filepath.Separator)+"internal"+string(filepath.Separator)+"kmx"+string(filepath.Separator)+"fileaccess"+string(filepath.Separator)) {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imported := range file.Imports {
			if imported.Path.Value == `"github.com/kaimahi-agents/kaimahi/internal/kmx/fileaccess"` {
				t.Errorf("production package imports unwired foundation: %s", path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
