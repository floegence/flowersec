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
