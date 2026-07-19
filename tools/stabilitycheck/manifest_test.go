package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestValidateManifestRejectsDuplicateTSSubpaths(t *testing.T) {
	root := t.TempDir()
	for _, p := range []string{"docs/API_CONTRACT.md", "docs/API_CHANGE_POLICY.md", "README.md", "docs/ERROR_MODEL.md"} {
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
			APIContract:  "docs/API_CONTRACT.md",
			ChangePolicy: "docs/API_CHANGE_POLICY.md",
			Readme:       "README.md",
			ErrorModel:   "docs/ERROR_MODEL.md",
			CLITokens:    []string{"`cli`"},
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

func TestValidateManifestRejectsRemovedLegacyPackageExport(t *testing.T) {
	for _, packageExport := range []string{"./internal", "./internal/*"} {
		t.Run(packageExport, func(t *testing.T) {
			m, root := validTestManifest(t)
			m.TS.Subpaths = append(m.TS.Subpaths, tsSubpath{
				Specifier:         "@floegence/flowersec-core/internal",
				PackageJSONExport: packageExport,
				DocTokens:         []string{"`@floegence/flowersec-core/internal`"},
				RuntimeExports:    []string{"connect"},
			})

			err := validateManifest(root, m)
			if err == nil || !strings.Contains(err.Error(), "removed legacy TypeScript package export") {
				t.Fatalf("expected removed package export error, got %v", err)
			}
		})
	}
}

func TestValidateManifestRejectsRemovedLegacyRuntimeExport(t *testing.T) {
	for _, symbol := range []string{"requestChannelGrant", "requestEntryChannelGrant"} {
		t.Run(symbol, func(t *testing.T) {
			m, root := validTestManifest(t)
			m.TS.Subpaths[0].RuntimeExports = append(m.TS.Subpaths[0].RuntimeExports, symbol)

			err := validateManifest(root, m)
			if err == nil || !strings.Contains(err.Error(), "removed legacy TypeScript runtime export") {
				t.Fatalf("expected removed runtime export error, got %v", err)
			}
		})
	}
}

func TestValidateManifestRejectsRemovedLegacyDocumentationToken(t *testing.T) {
	for _, token := range []string{"`requestChannelGrant(...)`", "`requestEntryChannelGrant(...)`"} {
		t.Run(token, func(t *testing.T) {
			m, root := validTestManifest(t)
			m.TS.Subpaths[0].DocTokens = append(m.TS.Subpaths[0].DocTokens, token)

			err := validateManifest(root, m)
			if err == nil || !strings.Contains(err.Error(), "removed legacy TypeScript documentation token") {
				t.Fatalf("expected removed documentation token error, got %v", err)
			}
		})
	}
}

func validTestManifest(t *testing.T) (*manifest, string) {
	t.Helper()
	root := t.TempDir()
	for _, p := range []string{"docs/API_CONTRACT.md", "docs/API_CHANGE_POLICY.md", "README.md", "docs/ERROR_MODEL.md", "flowersec-rust/Cargo.toml"} {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("ok"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	return &manifest{
		Version: 1,
		Docs: docsManifest{
			APIContract:  "docs/API_CONTRACT.md",
			ChangePolicy: "docs/API_CHANGE_POLICY.md",
			Readme:       "README.md",
			ErrorModel:   "docs/ERROR_MODEL.md",
			CLITokens:    []string{"`cli`"},
		},
		Go: goManifest{
			ModulePath: "github.com/floegence/flowersec/flowersec-go",
			CompileTargets: []goCompileTarget{{
				Package:         "github.com/floegence/flowersec/flowersec-go/client",
				Alias:           "client",
				DocPackageToken: "`client`",
				Entries: []goCompileExpr{{
					Kind: "func", Expr: "client.Connect", DocToken: "`client.Connect(...)`",
				}},
			}},
		},
		TS: tsManifest{Subpaths: []tsSubpath{{
			Specifier:         "@floegence/flowersec-core",
			PackageJSONExport: ".",
			DocTokens:         []string{"`@floegence/flowersec-core`"},
			RuntimeExports:    []string{"connect"},
		}}},
		Swift: swiftManifest{
			PackageName: "Flowersec",
			Product:     "Flowersec",
			Module:      "Flowersec",
			DocTokens:   []string{"`Flowersec`"},
			Symbols:     []swiftSymbol{{Kind: "swift.struct", Name: "FlowersecClient"}},
		},
		Rust: rustManifest{
			Package:        "flowersec",
			CratePath:      "flowersec-rust",
			DocTokens:      []string{"`flowersec`"},
			CompileEntries: []string{"let _ = flowersec::connect"},
		},
		Coverage: coverageManifest{
			Go: []goCoverageTarget{{Package: "github.com/floegence/flowersec/flowersec-go/client", MinStatementsPct: 1}},
			TS: tsCoverageTarget{Lines: 1, Functions: 1, Statements: 1, Branches: 1},
		},
	}, root
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

func TestSwiftBuildModulePathsIncludesDependencyModuleMaps(t *testing.T) {
	repoRoot := t.TempDir()
	binPath := filepath.Join(repoRoot, ".build", "arm64-apple-macosx", "debug")
	moduleDir := filepath.Join(binPath, "Modules")
	shimDir := filepath.Join(repoRoot, ".build", "checkouts", "dependency", "Sources", "Shim", "include")
	for _, dir := range []string{moduleDir, shimDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(shimDir, "module.modulemap"), []byte("module Shim {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	paths, err := swiftBuildModulePaths(repoRoot, binPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{binPath, moduleDir, shimDir} {
		if !slices.Contains(paths, expected) {
			t.Fatalf("expected module paths to include %s, got %#v", expected, paths)
		}
	}
}

func TestMakefileStabilityCheckRunsEveryContractVerifier(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	target := text[strings.Index(text, "stability-check:"):]
	for _, command := range []string{
		"tools/manifestgen",
		"verify-manifest",
		"verify-defaults",
		"verify-parity",
		"verify-docs",
		"verify-go",
		"verify-swift",
		"verify-rust",
		"report",
	} {
		if !strings.Contains(target, command) {
			t.Fatalf("stability-check must run %s, got:\n%s", command, target)
		}
	}
}
