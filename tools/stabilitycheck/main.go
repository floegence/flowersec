package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

const repoGoToolchain = "go1.25.9"

func main() {
	if err := run(os.Args[1:]); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: go run . <verify-manifest|verify-go|verify-docs|verify-go-coverage|report>")
	}
	repoRoot, err := repoRootFromWD()
	if err != nil {
		return err
	}
	m, err := loadManifest(repoRoot)
	if err != nil {
		return err
	}

	switch args[0] {
	case "verify-manifest":
		fmt.Printf("manifest OK: %d go targets, %d ts subpaths\n", len(m.Go.CompileTargets), len(m.TS.Subpaths))
		return nil
	case "verify-go":
		return verifyGo(repoRoot, m)
	case "verify-docs":
		return verifyDocs(repoRoot, m)
	case "verify-go-coverage":
		return verifyGoCoverage(repoRoot, m)
	case "report":
		fmt.Printf("manifest=%s\n", manifestPath)
		fmt.Printf("go_targets=%d\n", len(m.Go.CompileTargets))
		fmt.Printf("ts_subpaths=%d\n", len(m.TS.Subpaths))
		fmt.Printf("go_coverage_packages=%d\n", len(m.Coverage.Go))
		fmt.Printf("ts_coverage=%d/%d/%d/%d\n", m.Coverage.TS.Lines, m.Coverage.TS.Functions, m.Coverage.TS.Statements, m.Coverage.TS.Branches)
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func verifyDocs(repoRoot string, m *manifest) error {
	b, err := os.ReadFile(filepath.Join(repoRoot, m.Docs.APISurface))
	if err != nil {
		return err
	}
	doc := string(b)
	required := append([]string{}, m.Docs.CLITokens...)
	required = append(required, "`docs/API_STABILITY_POLICY.md`", "`stability/public_api_manifest.json`")
	for _, target := range m.Go.CompileTargets {
		required = append(required, target.DocPackageToken)
		for _, entry := range target.Entries {
			required = append(required, entry.DocToken)
		}
	}
	for _, subpath := range m.TS.Subpaths {
		required = append(required, subpath.DocTokens...)
	}
	for _, token := range required {
		if !strings.Contains(doc, token) {
			return fmt.Errorf("%s missing token %s", m.Docs.APISurface, token)
		}
	}
	fmt.Printf("docs OK: %d tokens verified in %s\n", len(required), m.Docs.APISurface)
	return nil
}

func verifyGo(repoRoot string, m *manifest) error {
	tmpDir, err := os.MkdirTemp("", "flowersec-stability-go-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	goMod, goTest := renderGoVerifier(filepath.Join(repoRoot, "flowersec-go"), m)
	if err := os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(goMod), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "api_surface_test.go"), []byte(goTest), 0o644); err != nil {
		return err
	}

	cmd := exec.Command("go", "test", "-mod=mod", "./...")
	cmd.Dir = tmpDir
	cmd.Env = withRepoGoToolchain()
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("verify-go failed:\n%s", out.String())
	}
	fmt.Printf("go symbols OK: %d targets verified\n", len(m.Go.CompileTargets))
	return nil
}

func renderGoVerifier(goModulePath string, m *manifest) (string, string) {
	var imports strings.Builder
	var checks strings.Builder
	for _, target := range m.Go.CompileTargets {
		fmt.Fprintf(&imports, "\t%s %q\n", target.Alias, target.Package)
		for _, entry := range target.Entries {
			switch entry.Kind {
			case "type":
				fmt.Fprintf(&checks, "\tvar _ %s\n", entry.Expr)
			case "func", "method", "const":
				fmt.Fprintf(&checks, "\tvar _ = %s\n", entry.Expr)
			}
		}
	}

	goMod := fmt.Sprintf("module flowersecstabilitychecktmp\n\ngo 1.25.9\n\nrequire %s v0.0.0\n\nreplace %s => %s\n", m.Go.ModulePath, m.Go.ModulePath, filepath.ToSlash(goModulePath))
	goTest := fmt.Sprintf("package flowersecstabilitychecktmp\n\nimport (\n%s)\n\nfunc TestStableSymbolsCompile(t *testing.T) {\n%s}\n", imports.String()+"\t\"testing\"\n", checks.String())
	return goMod, goTest
}

var coverageLine = regexp.MustCompile(`^(?:ok|\?)\s+(\S+)\s+.*coverage:\s+([0-9.]+)% of statements$`)

func verifyGoCoverage(repoRoot string, m *manifest) error {
	cmd := exec.Command("go", "test", "-count=1", "-cover", "./...")
	cmd.Dir = filepath.Join(repoRoot, "flowersec-go")
	cmd.Env = withRepoGoToolchain()
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("go test -cover failed:\n%s", out.String())
	}

	results := map[string]float64{}
	for _, line := range strings.Split(out.String(), "\n") {
		match := coverageLine.FindStringSubmatch(strings.TrimSpace(line))
		if len(match) != 3 {
			continue
		}
		results[match[1]] = mustParseFloat(match[2])
	}
	for _, target := range m.Coverage.Go {
		got, ok := results[target.Package]
		if !ok {
			return fmt.Errorf("missing coverage result for %s", target.Package)
		}
		if got+1e-9 < target.MinStatementsPct {
			return fmt.Errorf("coverage for %s = %.1f%%, want >= %.1f%%", target.Package, got, target.MinStatementsPct)
		}
	}
	fmt.Printf("go coverage OK: %d package thresholds verified\n", len(m.Coverage.Go))
	return nil
}

func mustParseFloat(s string) float64 {
	var whole, frac float64
	var fracDiv float64 = 1
	seenDot := false
	for _, r := range s {
		if r == '.' {
			seenDot = true
			continue
		}
		d := float64(r - '0')
		if !seenDot {
			whole = whole*10 + d
			continue
		}
		frac = frac*10 + d
		fracDiv *= 10
	}
	return whole + frac/fracDiv
}

func withRepoGoToolchain() []string {
	return append(os.Environ(), "GOTOOLCHAIN="+repoGoToolchain)
}
