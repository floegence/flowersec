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

func TestPruneDistRetainsEveryPublicEntrypoint(t *testing.T) {
	packageRoot := filepath.Join("..", "..", "flowersec-ts")
	packageData, err := os.ReadFile(filepath.Join(packageRoot, "package.json"))
	if err != nil {
		t.Fatal(err)
	}
	var packageJSON tsPackageJSON
	if err := json.Unmarshal(packageData, &packageJSON); err != nil {
		t.Fatal(err)
	}
	pruneData, err := os.ReadFile(filepath.Join(packageRoot, "scripts", "prune-dist.mjs"))
	if err != nil {
		t.Fatal(err)
	}
	pruneSource := string(pruneData)
	for packageExport, exported := range packageJSON.Exports {
		for _, entrypoint := range []string{exported.Default, exported.Types} {
			entrypoint = strings.TrimPrefix(entrypoint, "./dist/")
			if !strings.Contains(pruneSource, `"`+entrypoint+`"`) {
				t.Errorf("prune-dist does not retain %s entrypoint %s", packageExport, entrypoint)
			}
		}
	}
}
