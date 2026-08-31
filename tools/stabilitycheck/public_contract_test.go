package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestTransportV3PublicAPIIsExplicitlyRegistered(t *testing.T) {
	repoRoot, err := repoRootFromWD()
	if err != nil {
		t.Fatal(err)
	}
	m, err := loadManifest(repoRoot)
	if err != nil {
		t.Fatal(err)
	}

	const goRoot = "github.com/floegence/flowersec/flowersec-go/v4"
	for _, expression := range []string{
		"flowersec.Artifact", "flowersec.ArtifactLease", "flowersec.ParseArtifact",
		"flowersec.NewArtifactLease", "flowersec.ConnectorOptions", "flowersec.Connect",
		"flowersec.Session", "flowersec.ByteStream", "flowersec.RPCPeer", "flowersec.ConnectError",
		"flowersec.UnreliableMessageChannel", "flowersec.UnreliableSendOptions",
	} {
		requireGoManifestEntry(t, m, goRoot, expression)
	}

	type rawManifest struct {
		Docs struct {
			TransportV3API    string   `json:"transport_v3_api"`
			TransportV3Tokens []string `json:"transport_v3_tokens"`
		} `json:"docs"`
		TS struct {
			Subpaths []struct {
				Specifier   string   `json:"specifier"`
				TypeExports []string `json:"type_exports"`
			} `json:"subpaths"`
		} `json:"ts"`
	}
	data, err := os.ReadFile(filepath.Join(repoRoot, manifestPath))
	if err != nil {
		t.Fatal(err)
	}
	var raw rawManifest
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if raw.Docs.TransportV3API == "" || !slices.Contains(raw.Docs.TransportV3Tokens, "flowersec/3") {
		t.Fatalf("manifest docs must register the Transport v3 API document and flowersec/3 token")
	}
	requireTSTypeExport(t, raw.TS.Subpaths, "@floegence/flowersec-core", "Session")
	requireTSTypeExport(t, raw.TS.Subpaths, "@floegence/flowersec-core", "UnreliableMessageChannel")
	requireTSTypeExport(t, raw.TS.Subpaths, "@floegence/flowersec-core/browser", "SessionOptions")
	requireTSTypeExport(t, raw.TS.Subpaths, "@floegence/flowersec-core/node", "ByteStream")
	for _, specifier := range []string{"@floegence/flowersec-core/browser", "@floegence/flowersec-core/node"} {
		for _, exportName := range []string{
			"JsonPrimitive", "JsonValue", "OperationOptions", "RpcPeer",
			"RpcResult", "SessionErrorCode", "SessionTermination",
		} {
			requireTSTypeExport(t, raw.TS.Subpaths, specifier, exportName)
		}
	}
	for _, exportName := range []string{
		"ArtifactSource", "ConnectionController", "ConnectionSnapshot",
		"RetryDisposition",
	} {
		requireTSTypeExport(t, raw.TS.Subpaths, "@floegence/flowersec-core", exportName)
	}
	requireSwiftManifestSymbol(t, m, "swift.protocol", "Session")
	requireSwiftManifestSymbol(t, m, "swift.protocol", "ByteStream")
	requireSwiftManifestSymbol(t, m, "swift.enum", "SessionError")
	requireSwiftManifestSymbol(t, m, "swift.func", "connect(lease:options:)")

	for _, entry := range []string{
		"let _: Option<&dyn flowersec::Session> = None",
		"let _ = std::mem::size_of::<flowersec::Artifact>()",
		"let _ = std::mem::size_of::<flowersec::ConnectorOptions>()",
		"let _ = flowersec::connect",
	} {
		if !slices.Contains(m.Rust.CompileEntries, entry) {
			t.Errorf("rust compile entries missing %q", entry)
		}
	}
	assertDocumentContains(t, repoRoot, "docs/API_CONTRACT.md", []string{
		"`flowersec.Connect(...)`",
		"`connect(...)`",
		"`ConnectorOptions`",
		"`Session`",
	})
}

func TestTransportV3GoExportsAreFullyRegistered(t *testing.T) {
	repoRoot, err := repoRootFromWD()
	if err != nil {
		t.Fatal(err)
	}
	m, err := loadManifest(repoRoot)
	if err != nil {
		t.Fatal(err)
	}

	for _, target := range m.Go.CompileTargets {
		if target.StabilityGroup != "transport_v3" {
			continue
		}
		relativePackage := "."
		if target.Package != m.Go.ModulePath {
			relativePackage = strings.TrimPrefix(target.Package, m.Go.ModulePath+"/")
		}
		if relativePackage == target.Package {
			t.Fatalf("transport v3 package %q is outside module %q", target.Package, m.Go.ModulePath)
		}
		exported, err := exportedGoExpressions(filepath.Join(repoRoot, "flowersec-go", filepath.FromSlash(relativePackage)), target.Alias)
		if err != nil {
			t.Fatal(err)
		}
		registered := make(map[string]struct{}, len(target.Entries))
		for _, entry := range target.Entries {
			registered[entry.Expr] = struct{}{}
		}
		missing := make([]string, 0)
		for expression := range exported {
			if _, ok := registered[expression]; !ok {
				missing = append(missing, expression)
			}
		}
		slices.Sort(missing)
		if len(missing) != 0 {
			t.Errorf("Go transport v3 manifest target %s is missing exported symbols: %s", target.Package, strings.Join(missing, ", "))
		}
	}
}

func TestTransportV3PublicInterfaceMethodsAreFullyRegistered(t *testing.T) {
	repoRoot, err := repoRootFromWD()
	if err != nil {
		t.Fatal(err)
	}
	m, err := loadManifest(repoRoot)
	if err != nil {
		t.Fatal(err)
	}

	expected := map[string][]string{
		"github.com/floegence/flowersec/flowersec-go/v4": {
			"flowersec.ByteStream.Read", "flowersec.ByteStream.Write", "flowersec.ByteStream.Close",
			"flowersec.ByteStream.Kind", "flowersec.ByteStream.TerminalError",
			"flowersec.ByteStream.CloseWrite", "flowersec.ByteStream.Reset",
			"flowersec.RPCPeer.Call", "flowersec.RPCPeer.Notify",
			"flowersec.UnreliableMessageChannel.MaxMessageBytes", "flowersec.UnreliableMessageChannel.Send",
			"flowersec.UnreliableMessageChannel.Receive", "flowersec.Session.RPC", "flowersec.Session.UnreliableMessages",
			"flowersec.Session.OpenStream", "flowersec.Session.AcceptStream", "flowersec.Session.Rekey",
			"flowersec.Session.ProbeLiveness", "flowersec.Session.WaitTermination", "flowersec.Session.Close",
		},
	}

	for packagePath, expressions := range expected {
		for _, expression := range expressions {
			requireGoManifestInterfaceMethod(t, m, packagePath, expression)
		}
	}
}

func TestInternalConnectErrorRegistryCoversCancelableStages(t *testing.T) {
	repoRoot, err := repoRootFromWD()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(repoRoot, "stability", "connect_error_code_registry.json"))
	if err != nil {
		t.Fatal(err)
	}
	var registry struct {
		Visibility string `json:"visibility"`
		Codes      []struct {
			Code   string   `json:"code"`
			Stages []string `json:"stages"`
		} `json:"codes"`
	}
	if err := json.Unmarshal(data, &registry); err != nil {
		t.Fatal(err)
	}
	if registry.Visibility != "internal" {
		t.Fatalf("connect error registry visibility = %q, want internal", registry.Visibility)
	}

	requiredStages := []string{"validate", "connect", "attach", "handshake", "close"}
	for _, code := range []string{"timeout", "canceled"} {
		var stages []string
		for _, entry := range registry.Codes {
			if entry.Code == code {
				stages = entry.Stages
				break
			}
		}
		if stages == nil {
			t.Fatalf("connect error registry missing %s", code)
		}
		for _, stage := range requiredStages {
			if !slices.Contains(stages, stage) {
				t.Errorf("connect error registry %s is missing stage %s", code, stage)
			}
		}
	}
}

func requireGoManifestInterfaceMethod(t *testing.T, m *manifest, packagePath, expression string) {
	t.Helper()
	for _, target := range m.Go.CompileTargets {
		if target.Package != packagePath {
			continue
		}
		for _, entry := range target.Entries {
			if entry.Expr != expression {
				continue
			}
			if entry.Kind != "interface_method" || strings.TrimSpace(entry.Signature) == "" {
				t.Fatalf("go target %s entry %s must be a signed interface_method", packagePath, expression)
			}
			return
		}
		t.Fatalf("go target %s missing %s", packagePath, expression)
	}
	t.Fatalf("go manifest missing target %s", packagePath)
}

func requireGoManifestEntry(t *testing.T, m *manifest, packagePath, expression string) {
	t.Helper()
	for _, target := range m.Go.CompileTargets {
		if target.Package != packagePath {
			continue
		}
		for _, entry := range target.Entries {
			if entry.Expr == expression {
				return
			}
		}
		t.Fatalf("go target %s missing %s", packagePath, expression)
	}
	t.Fatalf("go manifest missing target %s", packagePath)
}

func forbidGoManifestEntry(t *testing.T, m *manifest, packagePath, expression string) {
	t.Helper()
	for _, target := range m.Go.CompileTargets {
		if target.Package != packagePath {
			continue
		}
		for _, entry := range target.Entries {
			if entry.Expr == expression {
				t.Fatalf("go target %s retains forbidden public API %s", packagePath, expression)
			}
		}
		return
	}
	t.Fatalf("go manifest missing target %s", packagePath)
}

func exportedGoExpressions(packageDir, alias string) (map[string]struct{}, error) {
	entries, err := os.ReadDir(packageDir)
	if err != nil {
		return nil, err
	}
	exported := make(map[string]struct{})
	files := token.NewFileSet()
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(packageDir, entry.Name())
		file, err := parser.ParseFile(files, path, nil, 0)
		if err != nil {
			return nil, err
		}
		for _, declaration := range file.Decls {
			switch declaration := declaration.(type) {
			case *ast.GenDecl:
				for _, spec := range declaration.Specs {
					switch spec := spec.(type) {
					case *ast.TypeSpec:
						if spec.Name.IsExported() {
							exported[alias+"."+spec.Name.Name] = struct{}{}
							if interfaceType, ok := spec.Type.(*ast.InterfaceType); ok {
								for _, method := range interfaceType.Methods.List {
									for _, name := range method.Names {
										if name.IsExported() {
											exported[alias+"."+spec.Name.Name+"."+name.Name] = struct{}{}
										}
									}
								}
							}
						}
					case *ast.ValueSpec:
						for _, name := range spec.Names {
							if name.IsExported() {
								exported[alias+"."+name.Name] = struct{}{}
							}
						}
					}
				}
			case *ast.FuncDecl:
				if !declaration.Name.IsExported() {
					continue
				}
				if declaration.Recv == nil {
					exported[alias+"."+declaration.Name.Name] = struct{}{}
					continue
				}
				receiver, pointer, ok := receiverTypeName(declaration.Recv.List[0].Type)
				if !ok {
					return nil, fmt.Errorf("unsupported receiver for %s in %s", declaration.Name.Name, path)
				}
				if !ast.IsExported(receiver) {
					continue
				}
				if pointer {
					exported["(*"+alias+"."+receiver+")."+declaration.Name.Name] = struct{}{}
				} else {
					exported[alias+"."+receiver+"."+declaration.Name.Name] = struct{}{}
				}
			}
		}
	}
	return exported, nil
}

func receiverTypeName(expression ast.Expr) (string, bool, bool) {
	switch expression := expression.(type) {
	case *ast.Ident:
		return expression.Name, false, true
	case *ast.StarExpr:
		name, _, ok := receiverTypeName(expression.X)
		return name, true, ok
	case *ast.IndexExpr:
		return receiverTypeName(expression.X)
	case *ast.IndexListExpr:
		return receiverTypeName(expression.X)
	default:
		return "", false, false
	}
}

func requireTSTypeExport(t *testing.T, subpaths []struct {
	Specifier   string   `json:"specifier"`
	TypeExports []string `json:"type_exports"`
}, specifier, exportName string) {
	t.Helper()
	for _, subpath := range subpaths {
		if subpath.Specifier == specifier {
			if !slices.Contains(subpath.TypeExports, exportName) {
				t.Fatalf("TypeScript subpath %s missing type export %s", specifier, exportName)
			}
			return
		}
	}
	t.Fatalf("TypeScript manifest missing subpath %s", specifier)
}

func requireSwiftManifestSymbol(t *testing.T, m *manifest, kind, name string) {
	t.Helper()
	for _, symbol := range m.Swift.Symbols {
		if symbol.Kind == kind && symbol.Name == name {
			return
		}
	}
	t.Fatalf("Swift manifest missing %s %s", kind, name)
}

func assertDocumentContains(t *testing.T, repoRoot, path string, tokens []string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot, path))
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range tokens {
		if !strings.Contains(string(data), token) {
			t.Errorf("%s missing %q", path, token)
		}
	}
}
