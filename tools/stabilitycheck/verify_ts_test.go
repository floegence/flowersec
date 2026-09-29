package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyTSIsSourceOnly(t *testing.T) {
	data, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	start := strings.Index(text, "func verifyTS(")
	end := strings.Index(text[start:], "\nfunc countTSTypeExports(")
	if start < 0 || end < 0 {
		t.Fatal("verifyTS function boundaries not found")
	}
	verifySource := text[start : start+end]

	for _, forbidden := range []string{
		`exec.Command("npm", "run", "build"`,
		`exec.Command("node"`,
		`public runtime export probe`,
	} {
		if strings.Contains(verifySource, forbidden) {
			t.Fatalf("verifyTS must stay source-only; found %q", forbidden)
		}
	}
	for _, required := range []string{
		"tsSourceEntrypoint(",
		"TypeScript public source compile probe failed",
	} {
		if !strings.Contains(verifySource, required) {
			t.Fatalf("verifyTS must include %q", required)
		}
	}
}

func TestTypeScriptBuildDoesNotPostProcessDeclarations(t *testing.T) {
	packageRoot := "../../flowersec-ts"
	packageData, err := os.ReadFile(filepath.Join(packageRoot, "package.json"))
	if err != nil {
		t.Fatal(err)
	}
	var packageJSON tsPackageJSON
	if err := json.Unmarshal(packageData, &packageJSON); err != nil {
		t.Fatal(err)
	}
	build, ok := packageJSON.Scripts["build"]
	if !ok {
		t.Fatal("TypeScript package build script is missing")
	}
	if strings.Contains(build, "prune-dist") || strings.Contains(build, "sanitize-public-declarations") {
		t.Fatalf("TypeScript build must not post-process compiler declarations: %s", build)
	}
	for _, script := range []string{"scripts/prune-dist.mjs", "scripts/sanitize-public-declarations.mjs"} {
		if _, err := os.Stat(packageRoot + "/" + script); !os.IsNotExist(err) {
			t.Fatalf("obsolete TypeScript declaration postprocessor remains: %s", script)
		}
	}
}

// Compile against the real TypeScript compiler so arity, constraints, and
// missing exports remain checked, including types reached through aliases.
func TestVerifyTSGenericExports(t *testing.T) {
	dependencies, err := filepath.Abs("../../flowersec-ts/node_modules")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		args    []string
		symbol  string
		failure string
	}{
		{"valid", []string{`"transport"`}, "PublicGeneric", ""},
		{"missing arguments", nil, "PublicGeneric", "requires 1 type argument"},
		{"wrong constraint", []string{`"execution"`}, "PublicGeneric", "does not satisfy the constraint"},
		{"wrong arity", []string{`"transport"`, `"transport"`}, "PublicGeneric", "requires 1 type argument"},
		{"missing export", []string{`"transport"`}, "Missing", "has no exported member"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			pkg := filepath.Join(root, "flowersec-ts")
			if err := os.MkdirAll(filepath.Join(pkg, "src"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(dependencies, filepath.Join(pkg, "node_modules")); err != nil {
				t.Fatal(err)
			}
			files := map[string]string{
				"package.json":   `{"type":"module","exports":{".":{"types":"./dist/index.d.ts","default":"./dist/index.js"}}}`,
				"src/index.ts":   `export type { Generic as PublicGeneric } from "./generic.js"; export const value = 1;`,
				"src/generic.ts": `export interface Generic<T extends "transport"> { value: T }`,
			}
			for path, content := range files {
				if err := os.WriteFile(filepath.Join(pkg, path), []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			m := &manifest{TS: tsManifest{Subpaths: []tsSubpath{{Specifier: "test", PackageJSONExport: ".", RuntimeExports: []string{"value"}, TypeExports: []string{tc.symbol}, TypeArguments: map[string][]string{tc.symbol: tc.args}}}}}
			err := verifyTS(root, m)
			if tc.failure == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.failure) {
				t.Fatalf("wanted %q, got %v", tc.failure, err)
			}
		})
	}
}
