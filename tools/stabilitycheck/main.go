package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

const repoGoToolchain = "go1.26.5"

func main() {
	if err := run(os.Args[1:]); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: go run . <verify-manifest|verify-go|verify-ts|verify-swift|verify-rust|verify-docs|verify-go-coverage|verify-parity|verify-defaults|report>")
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
		fmt.Printf("manifest OK: %d go targets, %d ts subpaths, %d swift symbols, %d rust entries\n", len(m.Go.CompileTargets), len(m.TS.Subpaths), len(m.Swift.Symbols), len(m.Rust.CompileEntries))
		return nil
	case "verify-go":
		return verifyGo(repoRoot, m)
	case "verify-ts":
		return verifyTS(repoRoot, m)
	case "verify-swift":
		return verifySwift(repoRoot, m)
	case "verify-rust":
		return verifyRust(repoRoot, m)
	case "verify-docs":
		return verifyDocs(repoRoot, m)
	case "verify-go-coverage":
		return verifyGoCoverage(repoRoot, m)
	case "verify-parity":
		return verifyParity(repoRoot)
	case "verify-defaults":
		return verifyDefaults(repoRoot)
	case "report":
		return report(repoRoot, m)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func report(repoRoot string, m *manifest) error {
	transport, err := loadTransportV2Contract(repoRoot)
	if err != nil {
		return err
	}
	fmt.Printf("manifest=%s\n", manifestPath)
	fmt.Printf("go_targets=%d\n", len(m.Go.CompileTargets))
	fmt.Printf("ts_subpaths=%d\n", len(m.TS.Subpaths))
	fmt.Printf("ts_type_exports=%d\n", countTSTypeExports(m))
	fmt.Printf("swift_symbols=%d\n", len(m.Swift.Symbols))
	fmt.Printf("rust_entries=%d\n", len(m.Rust.CompileEntries))
	fmt.Printf("go_coverage_packages=%d\n", len(m.Coverage.Go))
	fmt.Printf("ts_coverage=%d/%d/%d/%d\n", m.Coverage.TS.Lines, m.Coverage.TS.Functions, m.Coverage.TS.Statements, m.Coverage.TS.Branches)
	if capabilities, err := loadCapabilityManifest(repoRoot); err == nil {
		fmt.Printf("portable_capabilities=%d\n", len(capabilities.PortableCapabilities))
	}
	fmt.Printf("transport_v2_carriers=%d\n", len(transport.Carriers))
	fmt.Printf("transport_v2_runtimes=%d\n", len(transport.Runtimes))
	return nil
}

func verifyDocs(repoRoot string, m *manifest) error {
	b, err := os.ReadFile(filepath.Join(repoRoot, m.Docs.APIContract))
	if err != nil {
		return err
	}
	doc := string(b)
	required := append([]string{}, m.Docs.CLITokens...)
	required = append(required, "`docs/API_CHANGE_POLICY.md`", "`stability/api_contract_manifest.json`")
	for _, target := range m.Go.CompileTargets {
		if target.StabilityGroup == "transport_v2" {
			continue
		}
		required = append(required, target.DocPackageToken)
		for _, entry := range target.Entries {
			if entry.StabilityGroup == "transport_v2" {
				continue
			}
			required = append(required, entry.DocToken)
		}
	}
	for _, subpath := range m.TS.Subpaths {
		required = append(required, subpath.DocTokens...)
	}
	required = append(required, m.Swift.DocTokens...)
	required = append(required, m.Rust.DocTokens...)
	for _, token := range required {
		if !strings.Contains(doc, token) {
			return fmt.Errorf("%s missing token %s", m.Docs.APIContract, token)
		}
	}
	v2Data, err := os.ReadFile(filepath.Join(repoRoot, m.Docs.TransportV2API))
	if err != nil {
		return err
	}
	for _, token := range m.Docs.TransportV2Tokens {
		if !strings.Contains(string(v2Data), token) {
			return fmt.Errorf("%s missing token %s", m.Docs.TransportV2API, token)
		}
	}
	fmt.Printf(
		"docs OK: %d API tokens verified in %s and %d Transport v2 tokens verified in %s\n",
		len(required), m.Docs.APIContract, len(m.Docs.TransportV2Tokens), m.Docs.TransportV2API,
	)
	return nil
}

type tsPackageJSON struct {
	Exports map[string]struct {
		Types   string `json:"types"`
		Default string `json:"default"`
	} `json:"exports"`
}

func verifyTS(repoRoot string, m *manifest) error {
	packageRoot := filepath.Join(repoRoot, "flowersec-ts")
	build := exec.Command("npm", "run", "build", "--silent")
	build.Dir = packageRoot
	var buildOutput bytes.Buffer
	build.Stdout = &buildOutput
	build.Stderr = &buildOutput
	if err := build.Run(); err != nil {
		return fmt.Errorf("TypeScript package build failed: %w\n%s", err, buildOutput.String())
	}

	packageData, err := os.ReadFile(filepath.Join(packageRoot, "package.json"))
	if err != nil {
		return err
	}
	var packageJSON tsPackageJSON
	if err := json.Unmarshal(packageData, &packageJSON); err != nil {
		return fmt.Errorf("parse flowersec-ts/package.json: %w", err)
	}

	probeDir := filepath.Join(repoRoot, ".build", "stability-ts-probe")
	if err := os.RemoveAll(probeDir); err != nil {
		return err
	}
	if err := os.MkdirAll(probeDir, 0o755); err != nil {
		return err
	}

	var typeProbe strings.Builder
	runtimeChecks := make([]map[string]any, 0, len(m.TS.Subpaths))
	typeIndex := 0
	for _, subpath := range m.TS.Subpaths {
		exported, ok := packageJSON.Exports[subpath.PackageJSONExport]
		if !ok || exported.Types == "" || exported.Default == "" {
			return fmt.Errorf("TypeScript package export %s is missing types/default entries", subpath.PackageJSONExport)
		}
		typePath := filepath.Join(packageRoot, filepath.FromSlash(strings.TrimPrefix(exported.Types, "./")))
		typeImport, err := filepath.Rel(probeDir, typePath)
		if err != nil {
			return err
		}
		typeImport = filepath.ToSlash(typeImport)
		if !strings.HasPrefix(typeImport, ".") {
			typeImport = "./" + typeImport
		}
		for _, exportName := range subpath.TypeExports {
			alias := fmt.Sprintf("ManifestType%d", typeIndex)
			fmt.Fprintf(&typeProbe, "import type { %s as %s } from %q;\n", exportName, alias, typeImport)
			fmt.Fprintf(&typeProbe, "declare const manifestType%d: %s;\nvoid manifestType%d;\n", typeIndex, alias, typeIndex)
			typeIndex++
		}
		runtimeChecks = append(runtimeChecks, map[string]any{
			"specifier": subpath.Specifier,
			"module":    filepath.Join(packageRoot, filepath.FromSlash(strings.TrimPrefix(exported.Default, "./"))),
			"exports":   subpath.RuntimeExports,
		})
	}
	if err := os.WriteFile(filepath.Join(probeDir, "probe.ts"), []byte(typeProbe.String()), 0o644); err != nil {
		return err
	}
	tsconfig := `{"compilerOptions":{"module":"NodeNext","moduleResolution":"NodeNext","noEmit":true,"strict":true,"target":"ES2022"},"include":["probe.ts"]}`
	if err := os.WriteFile(filepath.Join(probeDir, "tsconfig.json"), []byte(tsconfig), 0o644); err != nil {
		return err
	}
	tsc := exec.Command(
		filepath.Join(packageRoot, "node_modules", "typescript", "bin", "tsc"),
		"-p", filepath.Join(probeDir, "tsconfig.json"),
	)
	tsc.Dir = probeDir
	var tscOutput bytes.Buffer
	tsc.Stdout = &tscOutput
	tsc.Stderr = &tscOutput
	if err := tsc.Run(); err != nil {
		return fmt.Errorf("TypeScript public type compile probe failed: %w\n%s", err, tscOutput.String())
	}

	encodedChecks, err := json.Marshal(runtimeChecks)
	if err != nil {
		return err
	}
	runtimeProbe := fmt.Sprintf(`import { pathToFileURL } from "node:url";
const checks = %s;
for (const check of checks) {
  const module = await import(pathToFileURL(check.module).href);
  for (const exportName of check.exports) {
    if (!Object.prototype.hasOwnProperty.call(module, exportName) || module[exportName] === undefined) {
      throw new Error(check.specifier + " missing runtime export " + exportName);
    }
  }
}
`, encodedChecks)
	node := exec.Command("node", "--input-type=module", "-")
	node.Dir = probeDir
	node.Stdin = strings.NewReader(runtimeProbe)
	var nodeOutput bytes.Buffer
	node.Stdout = &nodeOutput
	node.Stderr = &nodeOutput
	if err := node.Run(); err != nil {
		return fmt.Errorf("TypeScript public runtime export probe failed: %w\n%s", err, nodeOutput.String())
	}
	fmt.Printf("TypeScript symbols OK: %d runtime exports and %d type exports verified\n", countTSRuntimeExports(m), typeIndex)
	return nil
}

func countTSTypeExports(m *manifest) int {
	count := 0
	for _, subpath := range m.TS.Subpaths {
		count += len(subpath.TypeExports)
	}
	return count
}

func countTSRuntimeExports(m *manifest) int {
	count := 0
	for _, subpath := range m.TS.Subpaths {
		count += len(subpath.RuntimeExports)
	}
	return count
}

func verifyRust(repoRoot string, m *manifest) error {
	probeDir := filepath.Join(repoRoot, ".build", "stability-rust-probe")
	if err := os.RemoveAll(probeDir); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(probeDir, "src"), 0o755); err != nil {
		return err
	}
	cratePath := filepath.ToSlash(filepath.Join(repoRoot, m.Rust.CratePath))
	cargo := fmt.Sprintf("[package]\nname = \"flowersec-api-probe\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[dependencies]\n%s = { path = %q }\n", m.Rust.Package, cratePath)
	if err := os.WriteFile(filepath.Join(probeDir, "Cargo.toml"), []byte(cargo), 0o644); err != nil {
		return err
	}
	var source strings.Builder
	source.WriteString("fn main() {\n")
	for _, entry := range m.Rust.CompileEntries {
		source.WriteString("    ")
		source.WriteString(entry)
		if !strings.HasSuffix(strings.TrimSpace(entry), ";") {
			source.WriteString(";")
		}
		source.WriteString("\n")
	}
	source.WriteString("}\n")
	if err := os.WriteFile(filepath.Join(probeDir, "src", "main.rs"), []byte(source.String()), 0o644); err != nil {
		return err
	}
	cmd := exec.Command("cargo", "check", "--quiet")
	cmd.Dir = probeDir
	cmd.Env = append(os.Environ(), "CARGO_TERM_COLOR=never")
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("Rust public API compile probe failed: %w\n%s", err, output.String())
	}
	fmt.Printf("rust symbols OK: %d compile entries verified\n", len(m.Rust.CompileEntries))
	return nil
}

func verifySwift(repoRoot string, m *manifest) error {
	packageData, err := os.ReadFile(filepath.Join(repoRoot, "Package.swift"))
	if err != nil {
		return err
	}
	packageText := string(packageData)
	for _, token := range []string{
		`name: "` + m.Swift.PackageName + `"`,
		`.library(name: "` + m.Swift.Product + `"`,
		`name: "` + m.Swift.Module + `"`,
	} {
		if !strings.Contains(packageText, token) {
			return fmt.Errorf("Package.swift missing Swift package token %s", token)
		}
	}

	symbols, err := dumpSwiftPublicSymbols(repoRoot, m.Swift.Module)
	if err != nil {
		return err
	}
	actual := make([]swiftSymbol, 0, len(symbols))
	for _, symbol := range symbols {
		actual = append(actual, swiftSymbol{Kind: symbol.Kind, Name: symbol.Name})
	}
	if diff := diffSwiftSymbols(m.Swift.Symbols, actual); diff != "" {
		return errors.New(diff)
	}
	fmt.Printf("swift symbols OK: %d symbols verified\n", len(m.Swift.Symbols))
	return nil
}

type dumpedSwiftSymbol struct {
	Kind string
	Name string
}

type swiftSymbolGraph struct {
	Symbols []struct {
		Kind struct {
			Identifier string `json:"identifier"`
		} `json:"kind"`
		PathComponents []string `json:"pathComponents"`
		AccessLevel    string   `json:"accessLevel"`
		Identifier     struct {
			InterfaceLanguage string `json:"interfaceLanguage"`
		} `json:"identifier"`
	} `json:"symbols"`
}

type swiftTargetInfo struct {
	Target struct {
		Triple   string `json:"triple"`
		Platform string `json:"platform"`
	} `json:"target"`
	Paths struct {
		RuntimeResourcePath string `json:"runtimeResourcePath"`
	} `json:"paths"`
}

func dumpSwiftPublicSymbols(repoRoot, module string) ([]dumpedSwiftSymbol, error) {
	if err := buildSwiftTarget(repoRoot, module); err != nil {
		return nil, err
	}
	binPath, err := swiftBuildBinPath(repoRoot)
	if err != nil {
		return nil, err
	}
	modulePaths, err := swiftBuildModulePaths(repoRoot, binPath)
	if err != nil {
		return nil, err
	}
	target, err := swiftBuildTargetInfo(repoRoot)
	if err != nil {
		return nil, err
	}
	sdkPath, err := swiftSDKPath(target.Target.Platform, target.Target.Triple)
	if err != nil {
		return nil, err
	}
	graphDir := filepath.Join(repoRoot, ".build", "stability-symbolgraph")
	if err := os.RemoveAll(graphDir); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(graphDir, 0o755); err != nil {
		return nil, err
	}
	if err := extractSwiftSymbolGraph(
		repoRoot,
		module,
		target.Target.Triple,
		modulePaths,
		sdkPath,
		target.Paths.RuntimeResourcePath,
		graphDir,
	); err != nil {
		return nil, err
	}
	graphPath := filepath.Join(graphDir, module+".symbols.json")
	data, err := os.ReadFile(graphPath)
	if err != nil {
		return nil, err
	}
	var graph swiftSymbolGraph
	if err := json.Unmarshal(data, &graph); err != nil {
		return nil, fmt.Errorf("parse %s: %w", graphPath, err)
	}
	symbols := make([]dumpedSwiftSymbol, 0, len(graph.Symbols))
	for _, item := range graph.Symbols {
		if item.AccessLevel != "public" || item.Identifier.InterfaceLanguage != "swift" {
			continue
		}
		symbols = append(symbols, dumpedSwiftSymbol{
			Kind: item.Kind.Identifier,
			Name: strings.Join(item.PathComponents, "."),
		})
	}
	slices.SortFunc(symbols, func(a, b dumpedSwiftSymbol) int {
		return strings.Compare(a.Kind+"\x00"+a.Name, b.Kind+"\x00"+b.Name)
	})
	return symbols, nil
}

func buildSwiftTarget(repoRoot, module string) error {
	cmd := exec.Command("swift", "build", "--target", module)
	cmd.Dir = repoRoot
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("swift build --target %s failed:\n%s", module, out.String())
	}
	return nil
}

func swiftBuildBinPath(repoRoot string) (string, error) {
	cmd := exec.Command("swift", "build", "--show-bin-path")
	cmd.Dir = repoRoot
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("swift build --show-bin-path failed:\n%s", out.String())
	}
	path := strings.TrimSpace(out.String())
	if path == "" {
		return "", errors.New("swift build --show-bin-path returned an empty path")
	}
	return path, nil
}

func swiftBuildModulePaths(repoRoot, binPath string) ([]string, error) {
	candidates := []string{
		filepath.Join(binPath, "Modules"),
		binPath,
	}
	paths := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		info, err := os.Stat(candidate)
		if err == nil && info.IsDir() {
			paths = append(paths, candidate)
			continue
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	for _, root := range []string{binPath, filepath.Join(repoRoot, ".build", "checkouts")} {
		if _, err := os.Stat(root); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return nil, err
		}
		if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || entry.Name() != "module.modulemap" {
				return nil
			}
			dir := filepath.Dir(path)
			if !slices.Contains(paths, dir) {
				paths = append(paths, dir)
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("swift build output %s does not contain module search paths", binPath)
	}
	slices.Sort(paths)
	return paths, nil
}

func swiftBuildTargetInfo(repoRoot string) (*swiftTargetInfo, error) {
	cmd := exec.Command("swift", "-print-target-info")
	cmd.Dir = repoRoot
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("swift -print-target-info failed:\n%s", out.String())
	}
	var info swiftTargetInfo
	if err := json.Unmarshal(out.Bytes(), &info); err != nil {
		return nil, fmt.Errorf("parse swift target info: %w", err)
	}
	if strings.TrimSpace(info.Target.Triple) == "" {
		return nil, errors.New("swift target info missing target triple")
	}
	return &info, nil
}

func swiftSDKPath(platform, triple string) (string, error) {
	if !isSwiftMacOSTarget(platform, triple) {
		return "", nil
	}
	if _, err := exec.LookPath("xcrun"); err != nil {
		return "", nil
	}
	cmd := exec.Command("xcrun", "--sdk", "macosx", "--show-sdk-path")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("xcrun --sdk macosx --show-sdk-path failed:\n%s", out.String())
	}
	return strings.TrimSpace(out.String()), nil
}

func isSwiftMacOSTarget(platform, triple string) bool {
	platform = strings.ToLower(platform)
	triple = strings.ToLower(triple)
	return strings.Contains(platform, "macos") ||
		strings.Contains(triple, "apple-macos") ||
		strings.Contains(triple, "apple-darwin")
}

func extractSwiftSymbolGraph(
	repoRoot string,
	module string,
	targetTriple string,
	modulePaths []string,
	sdkPath string,
	runtimeResourcePath string,
	outputDir string,
) error {
	command, commandPrefix, err := swiftSymbolGraphExtractCommand(sdkPath, runtimeResourcePath)
	if err != nil {
		return err
	}
	args := []string{
		"-module-name", module,
		"-target", targetTriple,
		"-output-dir", outputDir,
		"-minimum-access-level", "public",
		"-skip-synthesized-members",
	}
	for _, modulePath := range modulePaths {
		args = append(args, "-I", modulePath)
	}
	if sdkPath != "" {
		args = append(args, "-sdk", sdkPath)
	}
	args = append(commandPrefix, args...)
	cmd := exec.Command(command, args...)
	cmd.Dir = repoRoot
	if sdkPath != "" {
		cmd.Env = append(os.Environ(), "SDKROOT="+sdkPath)
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("swift-symbolgraph-extract failed:\n%s", out.String())
	}
	return nil
}

func swiftSymbolGraphExtractCommand(sdkPath, runtimeResourcePath string) (string, []string, error) {
	const tool = "swift-symbolgraph-extract"
	if sdkPath != "" {
		if _, err := exec.LookPath("xcrun"); err != nil {
			return "", nil, fmt.Errorf("xcrun not found for macOS %s: %w", tool, err)
		}
		return "xcrun", []string{tool}, nil
	}
	if command, err := exec.LookPath(tool); err == nil {
		return command, nil, nil
	}
	swiftPath, _ := exec.LookPath("swift")
	for _, candidate := range swiftSymbolGraphExtractCandidates(swiftPath, runtimeResourcePath) {
		if isExecutableFile(candidate) {
			return candidate, nil, nil
		}
	}
	return "", nil, fmt.Errorf(
		"%s not found in PATH or Swift toolchain candidates: %s",
		tool,
		strings.Join(swiftSymbolGraphExtractCandidates(swiftPath, runtimeResourcePath), ", "),
	)
}

func swiftSymbolGraphExtractCandidates(swiftPath, runtimeResourcePath string) []string {
	const tool = "swift-symbolgraph-extract"
	candidates := make([]string, 0, 4)
	addCandidate := func(path string) {
		if path == "" {
			return
		}
		path = filepath.Clean(path)
		if !slices.Contains(candidates, path) {
			candidates = append(candidates, path)
		}
	}
	if swiftPath != "" {
		addCandidate(filepath.Join(filepath.Dir(swiftPath), tool))
		if resolved, err := filepath.EvalSymlinks(swiftPath); err == nil {
			addCandidate(filepath.Join(filepath.Dir(resolved), tool))
		}
	}
	if runtimeResourcePath != "" {
		for dir, depth := filepath.Clean(runtimeResourcePath), 0; depth < 5; depth++ {
			addCandidate(filepath.Join(dir, "bin", tool))
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	return candidates
}

func isExecutableFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir() && info.Mode()&0o111 != 0
}

func diffSwiftSymbols(expected, actual []swiftSymbol) string {
	expectedSet := make(map[string]struct{}, len(expected))
	actualSet := make(map[string]struct{}, len(actual))
	for _, symbol := range expected {
		expectedSet[symbol.Kind+"\x00"+symbol.Name] = struct{}{}
	}
	for _, symbol := range actual {
		actualSet[symbol.Kind+"\x00"+symbol.Name] = struct{}{}
	}

	missing := make([]string, 0)
	for key := range expectedSet {
		if _, ok := actualSet[key]; !ok {
			missing = append(missing, formatSwiftSymbolKey(key))
		}
	}
	extra := make([]string, 0)
	for key := range actualSet {
		if _, ok := expectedSet[key]; !ok {
			extra = append(extra, formatSwiftSymbolKey(key))
		}
	}
	slices.Sort(missing)
	slices.Sort(extra)
	if len(missing) == 0 && len(extra) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("Swift public symbol manifest is out of sync")
	if len(missing) > 0 {
		b.WriteString("\nmissing public symbols from source:")
		for _, item := range missing {
			b.WriteString("\n  - ")
			b.WriteString(item)
		}
	}
	if len(extra) > 0 {
		b.WriteString("\nextra public symbols not listed in manifest:")
		for _, item := range extra {
			b.WriteString("\n  - ")
			b.WriteString(item)
		}
	}
	return b.String()
}

func formatSwiftSymbolKey(key string) string {
	parts := strings.SplitN(key, "\x00", 2)
	if len(parts) != 2 {
		return key
	}
	return parts[0] + " " + parts[1]
}

func verifyGo(repoRoot string, m *manifest) error {
	tmpDir, err := os.MkdirTemp("", "flowersec-stability-go-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	goMod, goTest, err := renderGoVerifier(filepath.Join(repoRoot, "flowersec-go"), m)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(goMod), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "api_contract_test.go"), []byte(goTest), 0o644); err != nil {
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

func renderGoVerifier(goModulePath string, m *manifest) (string, string, error) {
	var imports strings.Builder
	var checks strings.Builder
	interfaceGroups := make([]goInterfaceGuard, 0)
	interfaceGroupIndexes := make(map[string]int)
	if goVerifierUsesQualifier(m, "context") {
		fmt.Fprintln(&imports, "\t\"context\"")
	}
	if goVerifierUsesQualifier(m, "time") {
		fmt.Fprintln(&imports, "\t\"time\"")
	}
	for _, target := range m.Go.CompileTargets {
		fmt.Fprintf(&imports, "\t%s %q\n", target.Alias, target.Package)
		for _, entry := range target.Entries {
			switch entry.Kind {
			case "type":
				fmt.Fprintf(&checks, "\tvar _ %s\n", entry.Expr)
			case "interface_method":
				declaration, receiver, err := renderGoInterfaceMethodDeclaration(entry)
				if err != nil {
					return "", "", err
				}
				index, ok := interfaceGroupIndexes[receiver]
				if !ok {
					index = len(interfaceGroups)
					interfaceGroupIndexes[receiver] = index
					interfaceGroups = append(interfaceGroups, goInterfaceGuard{receiver: receiver})
				}
				interfaceGroups[index].methods = append(interfaceGroups[index].methods, declaration)
				fmt.Fprintf(&checks, "\tvar _ %s = %s\n", entry.Signature, entry.Expr)
			case "field":
				fmt.Fprintf(&checks, "\tvar _ %s = %s\n", entry.Signature, entry.Expr)
			case "func", "method", "const", "var":
				fmt.Fprintf(&checks, "\tvar _ = %s\n", entry.Expr)
			}
		}
	}
	for index, group := range interfaceGroups {
		fmt.Fprintf(&checks, "\ttype manifestInterface%d interface {\n", index)
		for _, method := range group.methods {
			fmt.Fprintf(&checks, "\t\t%s\n", method)
		}
		fmt.Fprintln(&checks, "\t}")
		fmt.Fprintf(&checks, "\tvar _ manifestInterface%d = (%s)(nil)\n", index, group.receiver)
		fmt.Fprintf(&checks, "\tvar _ %s = (manifestInterface%d)(nil)\n", group.receiver, index)
	}

	requireVersion := "v0.0.0"
	if match := regexp.MustCompile(`/v([2-9][0-9]*)$`).FindStringSubmatch(m.Go.ModulePath); match != nil {
		requireVersion = "v" + match[1] + ".0.0"
	}
	goMod := fmt.Sprintf("module flowersecstabilitychecktmp\n\ngo 1.26.5\n\nrequire %s %s\n\nreplace %s => %s\n", m.Go.ModulePath, requireVersion, m.Go.ModulePath, filepath.ToSlash(goModulePath))
	goTest := fmt.Sprintf("package flowersecstabilitychecktmp\n\nimport (\n%s)\n\nfunc TestContractSymbolsCompile(t *testing.T) {\n%s}\n", imports.String()+"\t\"testing\"\n", checks.String())
	return goMod, goTest, nil
}

type goInterfaceGuard struct {
	receiver string
	methods  []string
}

func renderGoInterfaceMethodDeclaration(entry goCompileExpr) (string, string, error) {
	separator := strings.LastIndex(entry.Expr, ".")
	if separator <= 0 || separator == len(entry.Expr)-1 {
		return "", "", fmt.Errorf("go interface method %q must use Receiver.Method form", entry.Expr)
	}
	receiver := entry.Expr[:separator]
	methodName := entry.Expr[separator+1:]
	expression, err := parser.ParseExpr(entry.Signature)
	if err != nil {
		return "", "", fmt.Errorf("parse go interface method %q signature: %w", entry.Expr, err)
	}
	functionType, ok := expression.(*ast.FuncType)
	if !ok || functionType.Params == nil || len(functionType.Params.List) == 0 {
		return "", "", fmt.Errorf("go interface method %q signature must be a method expression function type", entry.Expr)
	}
	functionType.Params.List = functionType.Params.List[1:]
	var rendered bytes.Buffer
	if err := format.Node(&rendered, token.NewFileSet(), functionType); err != nil {
		return "", "", fmt.Errorf("render go interface method %q signature: %w", entry.Expr, err)
	}
	declaration := methodName + strings.TrimPrefix(rendered.String(), "func")
	return declaration, receiver, nil
}

func goVerifierUsesQualifier(m *manifest, qualifier string) bool {
	prefix := qualifier + "."
	for _, target := range m.Go.CompileTargets {
		for _, entry := range target.Entries {
			if (entry.Kind == "interface_method" || entry.Kind == "field") && strings.Contains(entry.Signature, prefix) {
				return true
			}
		}
	}
	return false
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
