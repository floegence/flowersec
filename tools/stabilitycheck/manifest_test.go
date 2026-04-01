package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateManifestRejectsDuplicateTSSubpaths(t *testing.T) {
	root := t.TempDir()
	for _, p := range []string{"docs/API_SURFACE.md", "docs/API_STABILITY_POLICY.md", "README.md", "docs/ERROR_MODEL.md"} {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("ok"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	m := &manifest{
		Version: 1,
		Docs: docsManifest{
			APISurface: "docs/API_SURFACE.md",
			Policy:     "docs/API_STABILITY_POLICY.md",
			Readme:     "README.md",
			ErrorModel: "docs/ERROR_MODEL.md",
			CLITokens:  []string{"`cli`"},
		},
		Go: goManifest{
			ModulePath: "github.com/floegence/flowersec/flowersec-go",
			CompileTargets: []goCompileTarget{
				{
					Package:         "github.com/floegence/flowersec/flowersec-go/client",
					Alias:           "client",
					DocPackageToken: "`client`",
					Entries: []goCompileExpr{
						{Kind: "func", Expr: "client.Connect", DocToken: "`client.Connect(...)`"},
					},
				},
			},
		},
		TS: tsManifest{
			Subpaths: []tsSubpath{
				{Specifier: "@pkg/core", PackageJSONExport: ".", DocTokens: []string{"`@pkg/core`"}, RuntimeExports: []string{"connect"}},
				{Specifier: "@pkg/core", PackageJSONExport: "./dup", DocTokens: []string{"`@pkg/core`"}, RuntimeExports: []string{"connectDup"}},
			},
		},
		Coverage: coverageManifest{
			Go: []goCoverageTarget{{Package: "github.com/floegence/flowersec/flowersec-go/client", MinStatementsPct: 1}},
			TS: tsCoverageTarget{Lines: 1, Functions: 1, Statements: 1, Branches: 1},
		},
	}

	err := validateManifest(root, m)
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate error, got %v", err)
	}
}

func TestRenderGoVerifierIncludesTypeChecks(t *testing.T) {
	m := &manifest{
		Go: goManifest{
			ModulePath: "github.com/floegence/flowersec/flowersec-go",
			CompileTargets: []goCompileTarget{
				{
					Package:         "github.com/floegence/flowersec/flowersec-go/endpoint",
					Alias:           "endpoint",
					DocPackageToken: "`endpoint`",
					Entries: []goCompileExpr{
						{Kind: "type", Expr: "endpoint.UpgraderOptions", DocToken: "`endpoint.UpgraderOptions`"},
						{Kind: "func", Expr: "endpoint.NewDirectHandler", DocToken: "`endpoint.NewDirectHandler(...)`"},
					},
				},
			},
		},
	}

	_, testFile := renderGoVerifier("/tmp/flowersec-go", m)
	if !strings.Contains(testFile, "var _ endpoint.UpgraderOptions") {
		t.Fatalf("expected type guard in generated verifier, got:\n%s", testFile)
	}
	if !strings.Contains(testFile, "var _ = endpoint.NewDirectHandler") {
		t.Fatalf("expected function guard in generated verifier, got:\n%s", testFile)
	}
}
