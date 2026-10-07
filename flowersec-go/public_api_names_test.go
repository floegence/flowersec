package flowersec

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPublicPackagesUseUnversionedNames(t *testing.T) {
	for _, directory := range []string{".", "controlplane"} {
		directory := directory
		t.Run(directory, func(t *testing.T) {
			entries, err := os.ReadDir(directory)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if entry.IsDir() || filepath.Ext(entry.Name()) != ".go" || strings.HasSuffix(entry.Name(), "_test.go") {
					continue
				}
				path := filepath.Join(directory, entry.Name())
				file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.AllErrors)
				if err != nil {
					t.Fatalf("parse public package source %s: %v", path, err)
				}
				for _, declaration := range file.Decls {
					switch declaration := declaration.(type) {
					case *ast.FuncDecl:
						if declaration.Name.IsExported() && strings.Contains(declaration.Name.Name, "V4") {
							t.Errorf("%s exports versioned function or method %s", path, declaration.Name.Name)
						}
					case *ast.GenDecl:
						for _, specification := range declaration.Specs {
							switch specification := specification.(type) {
							case *ast.TypeSpec:
								if specification.Name.IsExported() && strings.Contains(specification.Name.Name, "V4") {
									t.Errorf("%s exports versioned type %s", path, specification.Name.Name)
								}
							case *ast.ValueSpec:
								for _, name := range specification.Names {
									if name.IsExported() && strings.Contains(name.Name, "V4") {
										t.Errorf("%s exports versioned value %s", path, name.Name)
									}
								}
							}
						}
					}
				}
			}
		})
	}
}
