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

func TestTransportV2ContractDeclaresSignedSliceZeroRegistry(t *testing.T) {
	repoRoot, err := repoRootFromWD()
	if err != nil {
		t.Fatal(err)
	}
	contract, err := loadTransportV2Contract(repoRoot)
	if err != nil {
		t.Fatal(err)
	}

	if contract.Version != 2 || contract.SessionProfile != "flowersec/2" {
		t.Fatalf("unexpected transport contract identity: version=%d profile=%q", contract.Version, contract.SessionProfile)
	}
	wantCarriers := []string{"raw_quic", "websocket", "webtransport"}
	gotCarriers := make([]string, 0, len(contract.Carriers))
	for _, carrier := range contract.Carriers {
		gotCarriers = append(gotCarriers, carrier.ID)
	}
	slices.Sort(gotCarriers)
	if !slices.Equal(gotCarriers, wantCarriers) {
		t.Fatalf("carrier registry = %#v, want %#v", gotCarriers, wantCarriers)
	}

	wantRuntimeCarriers := map[string][]string{
		"go_native":          {"raw_quic", "websocket", "webtransport"},
		"typescript_browser": {"websocket", "webtransport"},
		"typescript_node":    {"websocket"},
		"rust_native":        {"raw_quic"},
		"swift_apple":        {},
	}
	for _, runtime := range contract.Runtimes {
		want, ok := wantRuntimeCarriers[runtime.ID]
		if !ok {
			t.Fatalf("unexpected runtime %q", runtime.ID)
		}
		got := runtimeSupportedCarriers(runtime)
		if !slices.Equal(got, want) {
			t.Fatalf("runtime %s carriers = %#v, want %#v", runtime.ID, got, want)
		}
		delete(wantRuntimeCarriers, runtime.ID)
	}
	if len(wantRuntimeCarriers) != 0 {
		t.Fatalf("missing runtime registries: %#v", wantRuntimeCarriers)
	}
	wantDynamicReasons := []string{
		"browser_websocket_api_unavailable",
		"browser_webtransport_api_unavailable",
	}
	gotReasons := make([]string, 0, len(contract.UnsupportedReasons))
	for _, reason := range contract.UnsupportedReasons {
		gotReasons = append(gotReasons, reason.ID)
	}
	for _, reason := range wantDynamicReasons {
		if !slices.Contains(gotReasons, reason) {
			t.Errorf("unsupported reason registry missing %q", reason)
		}
	}

	deps := map[string]string{}
	for _, dependency := range contract.GoSlice0.Dependencies {
		deps[dependency.Module] = dependency.Version
	}
	if deps["github.com/quic-go/quic-go"] != "v0.60.0" || deps["github.com/quic-go/webtransport-go"] != "v0.11.1" {
		t.Fatalf("unexpected signed Go dependency set: %#v", deps)
	}
	if contract.GoSlice0.Toolchain != "1.26.5" || contract.GoSlice0.WebTransportDialer != "quic.DialAddr" {
		t.Fatalf("unexpected Go Slice 0 contract: %+v", contract.GoSlice0)
	}
	if contract.RustSlice0.Status != "signed" || contract.RustSlice0.QuinnVersion != "=0.11.11" || contract.RustSlice0.RCGen != "forbidden" {
		t.Fatalf("unexpected Rust Slice 0 contract: %+v", contract.RustSlice0)
	}
	if contract.RustSlice0.QuinnDefaultFeatures != "disabled" || !slices.Equal(contract.RustSlice0.QuinnFeatures, []string{"runtime-tokio", "rustls-ring"}) {
		t.Fatalf("unexpected signed quinn feature set: %+v", contract.RustSlice0)
	}

	assertDocumentContains(t, repoRoot, contract.Docs.Architecture, []string{
		"CarrierSession",
		"native bidirectional stream",
		"Yamux",
		"0-RTT",
		"DATAGRAM",
		"business logic",
		"stability/transport_v2_contract.json",
	})
}

func TestTransportV2PublicAPIIsExplicitlyRegistered(t *testing.T) {
	repoRoot, err := repoRootFromWD()
	if err != nil {
		t.Fatal(err)
	}
	m, err := loadManifest(repoRoot)
	if err != nil {
		t.Fatal(err)
	}

	const goRoot = "github.com/floegence/flowersec/flowersec-go/v2"
	for _, expression := range []string{
		"flowersec.Artifact", "flowersec.ArtifactLease", "flowersec.ParseArtifact",
		"flowersec.NewArtifactLease", "flowersec.Connector", "flowersec.NewConnector",
		"flowersec.Session", "flowersec.ByteStream", "flowersec.RPCPeer", "flowersec.ConnectError",
	} {
		requireGoManifestEntry(t, m, goRoot, expression)
	}

	type rawManifest struct {
		Docs struct {
			TransportV2API    string   `json:"transport_v2_api"`
			TransportV2Tokens []string `json:"transport_v2_tokens"`
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
	if raw.Docs.TransportV2API == "" || !slices.Contains(raw.Docs.TransportV2Tokens, "`CarrierSession`") {
		t.Fatalf("manifest docs must register the Transport v2 API document and CarrierSession token")
	}
	requireTSTypeExport(t, raw.TS.Subpaths, "@floegence/flowersec-core", "SessionV2")
	requireTSTypeExport(t, raw.TS.Subpaths, "@floegence/flowersec-core/browser", "BrowserSessionConnectorV2Options")
	requireTSTypeExport(t, raw.TS.Subpaths, "@floegence/flowersec-core/node", "ByteStreamV2")
	for _, specifier := range []string{"@floegence/flowersec-core/browser", "@floegence/flowersec-core/node"} {
		for _, exportName := range []string{
			"JsonPrimitiveV2", "JsonValueV2", "OperationOptionsV2", "RpcPeerV2",
			"RpcResultV2", "SessionErrorCode", "SessionTerminationV2",
			"SessionReconnectConfigV2", "SessionReconnectManagerV2", "SessionReconnectStateV2",
		} {
			requireTSTypeExport(t, raw.TS.Subpaths, specifier, exportName)
		}
	}
	requireSwiftManifestSymbol(t, m, "swift.protocol", "SessionV2")
	requireSwiftManifestSymbol(t, m, "swift.protocol", "ByteStreamV2")
	requireSwiftManifestSymbol(t, m, "swift.enum", "SessionErrorV2")

	for _, entry := range []string{
		"let _: Option<&dyn flowersec::Session> = None",
		"let _ = std::mem::size_of::<flowersec::Artifact>()",
		"let _ = std::mem::size_of::<flowersec::Connector>()",
	} {
		if !slices.Contains(m.Rust.CompileEntries, entry) {
			t.Errorf("rust compile entries missing %q", entry)
		}
	}
	assertDocumentContains(t, repoRoot, "docs/API_CONTRACT.md", []string{
		"`Connector`",
		"`ConnectorOptions`",
		"`Session`",
	})
}

func TestTransportV2GoExportsAreFullyRegistered(t *testing.T) {
	repoRoot, err := repoRootFromWD()
	if err != nil {
		t.Fatal(err)
	}
	m, err := loadManifest(repoRoot)
	if err != nil {
		t.Fatal(err)
	}

	for _, target := range m.Go.CompileTargets {
		if target.StabilityGroup != "transport_v2" {
			continue
		}
		relativePackage := "."
		if target.Package != m.Go.ModulePath {
			relativePackage = strings.TrimPrefix(target.Package, m.Go.ModulePath+"/")
		}
		if relativePackage == target.Package {
			t.Fatalf("transport v2 package %q is outside module %q", target.Package, m.Go.ModulePath)
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
			t.Errorf("Go transport v2 manifest target %s is missing exported symbols: %s", target.Package, strings.Join(missing, ", "))
		}
	}
}

func TestTransportV2PublicInterfaceMethodsAreFullyRegistered(t *testing.T) {
	repoRoot, err := repoRootFromWD()
	if err != nil {
		t.Fatal(err)
	}
	m, err := loadManifest(repoRoot)
	if err != nil {
		t.Fatal(err)
	}

	expected := map[string][]string{
		"github.com/floegence/flowersec/flowersec-go/v2": {
			"flowersec.ByteStream.Read", "flowersec.ByteStream.Write", "flowersec.ByteStream.Close",
			"flowersec.ByteStream.Kind", "flowersec.ByteStream.TerminalError",
			"flowersec.ByteStream.CloseWrite", "flowersec.ByteStream.Reset",
			"flowersec.RPCPeer.Call", "flowersec.RPCPeer.Notify",
			"flowersec.Session.RPC",
			"flowersec.Session.OpenStream", "flowersec.Session.AcceptStream", "flowersec.Session.Rekey",
			"flowersec.Session.ProbeLiveness", "flowersec.Session.Termination",
			"flowersec.Session.WaitClosed", "flowersec.Session.Close",
		},
	}

	for packagePath, expressions := range expected {
		for _, expression := range expressions {
			requireGoManifestInterfaceMethod(t, m, packagePath, expression)
		}
	}
}

func TestTransportV2InternalConnectErrorRegistryCoversCancelableStages(t *testing.T) {
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

	requiredStages := []string{"validate", "connect", "attach", "handshake", "reconnect", "close"}
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
				t.Errorf("connect error registry %s is missing v2 stage %s", code, stage)
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

func TestTransportV2ContractRejectsInvalidRegistryStates(t *testing.T) {
	repoRoot, err := repoRootFromWD()
	if err != nil {
		t.Fatal(err)
	}
	contract, err := loadTransportV2Contract(repoRoot)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		mutate  func(*transportV2Contract)
		wantErr string
	}{
		{
			name: "invalid cross product",
			mutate: func(copy *transportV2Contract) {
				copy.Runtimes[0].Tuples[0].NetworkMode = "listen"
				copy.Runtimes[0].Tuples[0].SessionRole = "client"
			},
			wantErr: "invalid runtime tuple",
		},
		{
			name: "missing exact tuple",
			mutate: func(copy *transportV2Contract) {
				copy.Runtimes[0].Tuples = copy.Runtimes[0].Tuples[1:]
			},
			wantErr: "exact capability tuples",
		},
		{
			name: "runtime metadata drift",
			mutate: func(copy *transportV2Contract) {
				copy.Runtimes[0].Language = "rust"
			},
			wantErr: "runtime metadata",
		},
		{
			name: "capability digest label drift",
			mutate: func(copy *transportV2Contract) {
				copy.CapabilityCodec.DigestLabel = "unbound"
			},
			wantErr: "frozen v2 flat schema",
		},
		{
			name: "duplicate tuple",
			mutate: func(copy *transportV2Contract) {
				copy.Runtimes[0].Tuples = append(copy.Runtimes[0].Tuples, copy.Runtimes[0].Tuples[0])
			},
			wantErr: "duplicate runtime tuple",
		},
		{
			name: "noncanonical tuple order",
			mutate: func(copy *transportV2Contract) {
				copy.Runtimes[0].Tuples[0], copy.Runtimes[0].Tuples[1] = copy.Runtimes[0].Tuples[1], copy.Runtimes[0].Tuples[0]
			},
			wantErr: "canonically sorted",
		},
		{
			name: "wrong ALPN",
			mutate: func(copy *transportV2Contract) {
				copy.Paths[0].RawQUIC.ALPN = "flowersec-tunnel/2"
			},
			wantErr: "raw QUIC ALPN",
		},
		{
			name: "duplicate path",
			mutate: func(copy *transportV2Contract) {
				copy.Paths = append(copy.Paths, copy.Paths[0])
			},
			wantErr: "duplicate transport path ids",
		},
		{
			name: "unknown capability reason",
			mutate: func(copy *transportV2Contract) {
				copy.Runtimes[1].Unsupported[0].Reason = "invented_reason"
			},
			wantErr: "unknown unsupported reason",
		},
		{
			name: "empty capability reason description",
			mutate: func(copy *transportV2Contract) {
				copy.UnsupportedReasons[0].Description = ""
			},
			wantErr: "reason description",
		},
		{
			name: "quic yamux",
			mutate: func(copy *transportV2Contract) {
				for i := range copy.Carriers {
					if copy.Carriers[i].ID == "raw_quic" {
						copy.Carriers[i].Multiplexing = "hop_yamux"
						copy.Carriers[i].Yamux = "allowed"
					}
				}
			},
			wantErr: "must forbid Yamux",
		},
		{
			name: "application 0-RTT enabled",
			mutate: func(copy *transportV2Contract) {
				copy.Policies.Application0RTT = "allowed"
			},
			wantErr: "0-RTT must be forbidden",
		},
		{
			name: "public datagram API exposed",
			mutate: func(copy *transportV2Contract) {
				copy.Policies.PublicDatagramAPI = "exposed"
			},
			wantErr: "public API unexposed",
		},
		{
			name: "unsupported carrier missing",
			mutate: func(copy *transportV2Contract) {
				copy.Runtimes[2].Unsupported = copy.Runtimes[2].Unsupported[1:]
			},
			wantErr: "must classify every carrier",
		},
		{
			name: "dependency drift",
			mutate: func(copy *transportV2Contract) {
				copy.GoSlice0.Dependencies[0].Version = "v0.59.1"
			},
			wantErr: "must pin",
		},
		{
			name: "swapped document ownership",
			mutate: func(copy *transportV2Contract) {
				copy.Docs.Architecture, copy.Docs.Wire = copy.Docs.Wire, copy.Docs.Architecture
			},
			wantErr: "architecture document path",
		},
		{
			name: "Rust dependency drift",
			mutate: func(copy *transportV2Contract) {
				copy.RustSlice0.QuinnVersion = "0.11"
			},
			wantErr: "quinn =0.11.11",
		},
		{
			name: "Rust rcgen enabled",
			mutate: func(copy *transportV2Contract) {
				copy.RustSlice0.RCGen = "allowed"
			},
			wantErr: "rcgen",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			copy := cloneTransportV2Contract(t, contract)
			tt.mutate(&copy)
			err := validateTransportV2Contract(repoRoot, &copy)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestReportRejectsInvalidTransportV2Contract(t *testing.T) {
	repoRoot := t.TempDir()
	path := filepath.Join(repoRoot, transportV2ContractPath)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("not-json"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := report(repoRoot, &manifest{})
	if err == nil || !strings.Contains(err.Error(), "parse "+transportV2ContractPath) {
		t.Fatalf("error = %v, want transport v2 parse failure", err)
	}
}

func cloneTransportV2Contract(t *testing.T, contract *transportV2Contract) transportV2Contract {
	t.Helper()
	data, err := json.Marshal(contract)
	if err != nil {
		t.Fatal(err)
	}
	var copy transportV2Contract
	if err := json.Unmarshal(data, &copy); err != nil {
		t.Fatal(err)
	}
	return copy
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
