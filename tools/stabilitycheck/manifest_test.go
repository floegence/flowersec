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

func TestDiffSwiftSymbolsDetectsMissingAndExtra(t *testing.T) {
	diff := diffSwiftSymbols(
		[]swiftSymbol{{Kind: "swift.struct", Name: "Expected"}},
		[]swiftSymbol{{Kind: "swift.struct", Name: "Actual"}},
	)
	if !strings.Contains(diff, "missing public symbols from source") {
		t.Fatalf("expected missing section, got:\n%s", diff)
	}
	if !strings.Contains(diff, "extra public symbols not listed in manifest") {
		t.Fatalf("expected extra section, got:\n%s", diff)
	}
}

func TestSwiftSymbolGraphExtractCandidatesIncludeRuntimeToolchainBin(t *testing.T) {
	root := t.TempDir()
	swiftPath := filepath.Join(root, "usr", "bin", "swift")
	runtimePath := filepath.Join(root, "usr", "lib", "swift")
	candidates := swiftSymbolGraphExtractCandidates(swiftPath, runtimePath)
	expected := filepath.Join(root, "usr", "bin", "swift-symbolgraph-extract")
	found := false
	for _, candidate := range candidates {
		if candidate == expected {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected candidates to include %s, got %#v", expected, candidates)
	}
}

func TestSwiftMacOSTargetDetectionFallsBackToTriple(t *testing.T) {
	if !isSwiftMacOSTarget("", "arm64-apple-macosx15.0") {
		t.Fatal("expected macOS target detection from macosx triple")
	}
	if !isSwiftMacOSTarget("", "arm64-apple-darwin24.0") {
		t.Fatal("expected macOS target detection from darwin triple")
	}
	if isSwiftMacOSTarget("linux", "x86_64-unknown-linux-gnu") {
		t.Fatal("linux target must not require a macOS SDK")
	}
}

func TestMakefileStabilityCheckRunsSwiftVerifier(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	target := text[strings.Index(text, "stability-check:"):]
	if !strings.Contains(target, "verify-swift") {
		t.Fatalf("stability-check must run verify-swift, got:\n%s", target)
	}
}
