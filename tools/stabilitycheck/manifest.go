package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const manifestPath = "stability/public_api_manifest.json"

type manifest struct {
	Version  int              `json:"version"`
	Docs     docsManifest     `json:"docs"`
	Go       goManifest       `json:"go"`
	TS       tsManifest       `json:"ts"`
	Coverage coverageManifest `json:"coverage"`
}

type docsManifest struct {
	APISurface string   `json:"api_surface"`
	Policy     string   `json:"policy"`
	Readme     string   `json:"readme"`
	ErrorModel string   `json:"error_model"`
	CLITokens  []string `json:"cli_tokens"`
}

type goManifest struct {
	ModulePath     string            `json:"module_path"`
	CompileTargets []goCompileTarget `json:"compile_targets"`
}

type goCompileTarget struct {
	Package         string          `json:"package"`
	Alias           string          `json:"alias"`
	DocPackageToken string          `json:"doc_package_token"`
	Entries         []goCompileExpr `json:"entries"`
}

type goCompileExpr struct {
	Kind     string `json:"kind"`
	Expr     string `json:"expr"`
	DocToken string `json:"doc_token"`
}

type tsManifest struct {
	Subpaths []tsSubpath `json:"subpaths"`
}

type tsSubpath struct {
	Specifier         string   `json:"specifier"`
	PackageJSONExport string   `json:"package_json_export"`
	DocTokens         []string `json:"doc_tokens"`
	RuntimeExports    []string `json:"runtime_exports"`
}

type coverageManifest struct {
	Go []goCoverageTarget `json:"go"`
	TS tsCoverageTarget   `json:"ts"`
}

type goCoverageTarget struct {
	Package          string  `json:"package"`
	MinStatementsPct float64 `json:"min_statements_pct"`
}

type tsCoverageTarget struct {
	Lines      int `json:"lines"`
	Functions  int `json:"functions"`
	Statements int `json:"statements"`
	Branches   int `json:"branches"`
}

func repoRootFromWD() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	root := filepath.Clean(filepath.Join(wd, "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "AGENTS.md")); err != nil {
		return "", fmt.Errorf("resolve repo root from %q: %w", wd, err)
	}
	return root, nil
}

func loadManifest(repoRoot string) (*manifest, error) {
	b, err := os.ReadFile(filepath.Join(repoRoot, manifestPath))
	if err != nil {
		return nil, err
	}
	var m manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("parse %s: %w", manifestPath, err)
	}
	if err := validateManifest(repoRoot, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func validateManifest(repoRoot string, m *manifest) error {
	if m.Version != 1 {
		return fmt.Errorf("unsupported manifest version %d", m.Version)
	}
	for _, p := range []string{m.Docs.APISurface, m.Docs.Policy, m.Docs.Readme, m.Docs.ErrorModel} {
		if strings.TrimSpace(p) == "" {
			return errors.New("docs paths must not be empty")
		}
		if _, err := os.Stat(filepath.Join(repoRoot, p)); err != nil {
			return fmt.Errorf("manifest doc path %q: %w", p, err)
		}
	}
	if err := requireUnique("docs.cli_tokens", m.Docs.CLITokens); err != nil {
		return err
	}
	if strings.TrimSpace(m.Go.ModulePath) == "" {
		return errors.New("go.module_path must not be empty")
	}
	if len(m.Go.CompileTargets) == 0 {
		return errors.New("go.compile_targets must not be empty")
	}

	packages := make([]string, 0, len(m.Go.CompileTargets))
	aliases := make([]string, 0, len(m.Go.CompileTargets))
	for _, target := range m.Go.CompileTargets {
		if strings.TrimSpace(target.Package) == "" {
			return errors.New("go.compile_targets.package must not be empty")
		}
		if strings.TrimSpace(target.Alias) == "" {
			return fmt.Errorf("go target %q alias must not be empty", target.Package)
		}
		if strings.TrimSpace(target.DocPackageToken) == "" {
			return fmt.Errorf("go target %q doc_package_token must not be empty", target.Package)
		}
		if len(target.Entries) == 0 {
			return fmt.Errorf("go target %q must have entries", target.Package)
		}
		packages = append(packages, target.Package)
		aliases = append(aliases, target.Alias)

		seenExpr := make([]string, 0, len(target.Entries))
		for _, entry := range target.Entries {
			switch entry.Kind {
			case "func", "method", "type", "const":
			default:
				return fmt.Errorf("go entry %q has unsupported kind %q", entry.Expr, entry.Kind)
			}
			if strings.TrimSpace(entry.Expr) == "" {
				return fmt.Errorf("go target %q entry expr must not be empty", target.Package)
			}
			if strings.TrimSpace(entry.DocToken) == "" {
				return fmt.Errorf("go entry %q doc_token must not be empty", entry.Expr)
			}
			seenExpr = append(seenExpr, entry.Expr)
		}
		if err := requireUnique("go.entries("+target.Package+")", seenExpr); err != nil {
			return err
		}
	}
	if err := requireUnique("go.compile_targets.package", packages); err != nil {
		return err
	}
	if err := requireUnique("go.compile_targets.alias", aliases); err != nil {
		return err
	}

	if len(m.TS.Subpaths) == 0 {
		return errors.New("ts.subpaths must not be empty")
	}
	specifiers := make([]string, 0, len(m.TS.Subpaths))
	exports := make([]string, 0, len(m.TS.Subpaths))
	for _, subpath := range m.TS.Subpaths {
		if strings.TrimSpace(subpath.Specifier) == "" {
			return errors.New("ts subpath specifier must not be empty")
		}
		if strings.TrimSpace(subpath.PackageJSONExport) == "" {
			return fmt.Errorf("ts subpath %q package_json_export must not be empty", subpath.Specifier)
		}
		if len(subpath.DocTokens) == 0 {
			return fmt.Errorf("ts subpath %q doc_tokens must not be empty", subpath.Specifier)
		}
		if len(subpath.RuntimeExports) == 0 {
			return fmt.Errorf("ts subpath %q runtime_exports must not be empty", subpath.Specifier)
		}
		specifiers = append(specifiers, subpath.Specifier)
		exports = append(exports, subpath.PackageJSONExport)
		if err := requireUnique("ts.doc_tokens("+subpath.Specifier+")", subpath.DocTokens); err != nil {
			return err
		}
		if err := requireUnique("ts.runtime_exports("+subpath.Specifier+")", subpath.RuntimeExports); err != nil {
			return err
		}
	}
	if err := requireUnique("ts.subpaths.specifier", specifiers); err != nil {
		return err
	}
	if err := requireUnique("ts.subpaths.package_json_export", exports); err != nil {
		return err
	}

	if len(m.Coverage.Go) == 0 {
		return errors.New("coverage.go must not be empty")
	}
	coveragePkgs := make([]string, 0, len(m.Coverage.Go))
	for _, item := range m.Coverage.Go {
		if strings.TrimSpace(item.Package) == "" {
			return errors.New("coverage.go.package must not be empty")
		}
		if item.MinStatementsPct < 0 || item.MinStatementsPct > 100 {
			return fmt.Errorf("coverage.go %q has invalid min_statements_pct %.2f", item.Package, item.MinStatementsPct)
		}
		coveragePkgs = append(coveragePkgs, item.Package)
	}
	if err := requireUnique("coverage.go.package", coveragePkgs); err != nil {
		return err
	}
	for _, value := range []int{m.Coverage.TS.Lines, m.Coverage.TS.Functions, m.Coverage.TS.Statements, m.Coverage.TS.Branches} {
		if value < 0 || value > 100 {
			return fmt.Errorf("ts coverage threshold %d out of range", value)
		}
	}

	return nil
}

func requireUnique(label string, values []string) error {
	copyValues := append([]string(nil), values...)
	slices.Sort(copyValues)
	for i := 1; i < len(copyValues); i += 1 {
		if copyValues[i] == copyValues[i-1] {
			return fmt.Errorf("%s contains duplicate value %q", label, copyValues[i])
		}
	}
	return nil
}
