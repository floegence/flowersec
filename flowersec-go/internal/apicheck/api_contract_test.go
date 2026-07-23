package apicheck

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v2/client"
	"github.com/floegence/flowersec/flowersec-go/v2/controlplane/channelinit"
	cpclient "github.com/floegence/flowersec/flowersec-go/v2/controlplane/client"
	cphttp "github.com/floegence/flowersec/flowersec-go/v2/controlplane/http"
	"github.com/floegence/flowersec/flowersec-go/v2/controlplane/issuer"
	"github.com/floegence/flowersec/flowersec-go/v2/controlplane/token"
	"github.com/floegence/flowersec/flowersec-go/v2/endpoint"
	"github.com/floegence/flowersec/flowersec-go/v2/endpoint/serve"
	"github.com/floegence/flowersec/flowersec-go/v2/framing/jsonframe"
	"github.com/floegence/flowersec/flowersec-go/v2/fserrors"
	"github.com/floegence/flowersec/flowersec-go/v2/observability"
	"github.com/floegence/flowersec/flowersec-go/v2/origin"
	"github.com/floegence/flowersec/flowersec-go/v2/protocolio"
	"github.com/floegence/flowersec/flowersec-go/v2/proxy"
	proxypreset "github.com/floegence/flowersec/flowersec-go/v2/proxy/preset"
	"github.com/floegence/flowersec/flowersec-go/v2/rpc"
	"github.com/floegence/flowersec/flowersec-go/v2/transportsecurity"
)

// Compile-time checks for the public Go API contract. If an entrypoint is renamed or removed,
// this file should fail to compile and the contract must be updated in the same change.
var _ func(context.Context, *protocolio.ConnectArtifact, ...client.ConnectOption) (client.Client, error) = client.Connect

var (
	// client
	_ = client.ConnectTunnel
	_ = client.ConnectDirect
	_ = client.WithTransportSecurityPolicy
	_ = client.RequireTLS

	// endpoint
	_                = endpoint.ConnectTunnel
	_                = endpoint.NewDirectHandler
	_                = endpoint.AcceptDirectWS
	_                = endpoint.NewDirectHandlerResolved
	_                = endpoint.AcceptDirectWSResolved
	_ endpoint.Suite = endpoint.SuiteX25519HKDFAES256GCM
	_                = endpoint.SuiteP256HKDFAES256GCM
	_ endpoint.UpgraderOptions
	_ endpoint.HandshakeCache
	_ endpoint.AcceptDirectOptions
	_ endpoint.AcceptDirectResolverOptions
	_ endpoint.DirectHandshakeCredential
	_ = endpoint.WithTransportSecurityPolicy

	// endpoint/serve
	_ = serve.New
	_ = (*serve.Server).Handle
	_ = (*serve.Server).HandleStream
	_ = (*serve.Server).ServeSession
	_ = serve.ServeTunnel
	_ = serve.NewDirectHandler
	_ = serve.NewDirectHandlerResolved

	// protocolio
	_ = protocolio.DecodeGrantClientJSON
	_ = protocolio.DecodeGrantServerJSON
	_ = protocolio.DecodeGrantJSON
	_ = protocolio.DecodeDirectConnectInfoJSON
	_ = protocolio.DecodeConnectArtifactJSON
	_ protocolio.ConnectArtifact
	_ protocolio.TunnelClientConnectArtifact
	_ protocolio.DirectClientConnectArtifact
	_ protocolio.CorrelationContext
	_ protocolio.CorrelationKV
	_ protocolio.ScopeMetadataEntry

	// controlplane/client
	_ = cpclient.RequestConnectArtifact
	_ = cpclient.RequestEntryConnectArtifact
	_ cpclient.RequestError

	// controlplane/http
	_ int64 = cphttp.DefaultMaxBodyBytes
	_ cphttp.ArtifactRequest
	_ cphttp.ArtifactEnvelope
	_ cphttp.ErrorEnvelope
	_ cphttp.ArtifactRequestMetadata
	_ cphttp.ArtifactIssueInput
	_ cphttp.ArtifactHandlerOptions
	_ cphttp.RequestError
	_ = cphttp.NewRequestError
	_ = cphttp.DecodeArtifactRequest
	_ = cphttp.WriteArtifactEnvelope
	_ = cphttp.WriteErrorEnvelope
	_ = cphttp.NewArtifactHandler
	_ = cphttp.NewEntryArtifactHandler
	_ = cphttp.DefaultRequestMetadata
	_ = cphttp.IssueArtifact

	// observability
	_ observability.DiagnosticEvent
	_ observability.ClientObserver = nil
	_                              = observability.NormalizeClientObserver
	_                              = observability.WithClientObserverContext

	// origin
	_ = origin.FromWSURL
	_ = origin.ForTunnel

	// transportsecurity
	_ transportsecurity.Policy
	_ transportsecurity.Input
	_ = transportsecurity.RequireTLS

	// proxy
	_ = proxy.Register

	// proxy/preset
	_ proxypreset.Manifest
	_ = proxypreset.DecodeJSON
	_ = proxypreset.LoadFile
	_ = proxypreset.ApplyBridgeOptions

	// rpc
	_ = rpc.NewRouter
	_ = rpc.NewServer
	_ = rpc.NewClient

	// framing/jsonframe
	_ = jsonframe.ReadJSONFrame
	_ = jsonframe.WriteJSONFrame
	_ = jsonframe.ReadJSONFrameDefaultMax

	// fserrors
	_ fserrors.Path
	_ fserrors.Stage
	_ fserrors.Code

	// Controlplane helpers
	_ = issuer.NewRandom
	_ = channelinit.Service{}
	_ = token.Verify
)

func TestAPIContractDocCoversGoEntrypoints(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(thisFile)

	repoRoot := filepath.Join(dir, "..", "..", "..")
	docPath := filepath.Join(repoRoot, "docs", "API_CONTRACT.md")
	doc, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("read docs/API_CONTRACT.md: %v", err)
	}

	manifestPath := filepath.Join(repoRoot, "stability", "api_contract_manifest.json")
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read stability/api_contract_manifest.json: %v", err)
	}
	var manifest apiContractManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("parse stability/api_contract_manifest.json: %v", err)
	}

	wantTokens := append([]string{}, manifest.Docs.CLITokens...)
	wantTokens = append(wantTokens, "`docs/API_CHANGE_POLICY.md`", "`stability/api_contract_manifest.json`")
	for _, target := range manifest.Go.CompileTargets {
		wantTokens = append(wantTokens, target.DocPackageToken)
		for _, entry := range target.Entries {
			wantTokens = append(wantTokens, entry.DocToken)
		}
	}

	docText := string(doc)
	for _, token := range wantTokens {
		if !strings.Contains(docText, token) {
			t.Fatalf("docs/API_CONTRACT.md missing manifest token: %q", token)
		}
	}
}

func TestGoModuleUsesV2SemanticImportPath(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	moduleRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")
	goMod, err := os.ReadFile(filepath.Join(moduleRoot, "go.mod"))
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	const moduleLine = "module github.com/floegence/flowersec/flowersec-go/v2\n"
	if !strings.HasPrefix(string(goMod), moduleLine) {
		t.Fatalf("go.mod must start with %q", strings.TrimSpace(moduleLine))
	}
}

type apiContractManifest struct {
	Docs struct {
		CLITokens []string `json:"cli_tokens"`
	} `json:"docs"`
	Go struct {
		CompileTargets []struct {
			DocPackageToken string `json:"doc_package_token"`
			Entries         []struct {
				DocToken string `json:"doc_token"`
			} `json:"entries"`
		} `json:"compile_targets"`
	} `json:"go"`
}
