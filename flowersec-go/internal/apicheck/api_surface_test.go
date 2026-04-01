package apicheck

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/client"
	"github.com/floegence/flowersec/flowersec-go/controlplane/channelinit"
	"github.com/floegence/flowersec/flowersec-go/controlplane/issuer"
	"github.com/floegence/flowersec/flowersec-go/controlplane/token"
	"github.com/floegence/flowersec/flowersec-go/endpoint"
	"github.com/floegence/flowersec/flowersec-go/endpoint/serve"
	"github.com/floegence/flowersec/flowersec-go/framing/jsonframe"
	"github.com/floegence/flowersec/flowersec-go/fserrors"
	"github.com/floegence/flowersec/flowersec-go/origin"
	"github.com/floegence/flowersec/flowersec-go/protocolio"
	"github.com/floegence/flowersec/flowersec-go/proxy"
	"github.com/floegence/flowersec/flowersec-go/rpc"
)

// Compile-time checks for the intended stable Go API surface. If an entrypoint is renamed or
// removed, this file should fail to compile (and the docs must be updated in the same change).
var (
	// client
	_ = client.Connect
	_ = client.ConnectTunnel
	_ = client.ConnectDirect

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

	// origin
	_ = origin.FromWSURL
	_ = origin.ForTunnel

	// proxy
	_ = proxy.Register

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

func TestAPISurfaceDoc_CoversStableGoEntrypoints(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(thisFile)

	repoRoot := filepath.Join(dir, "..", "..", "..")
	docPath := filepath.Join(repoRoot, "docs", "API_SURFACE.md")
	doc, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("read docs/API_SURFACE.md: %v", err)
	}

	manifestPath := filepath.Join(repoRoot, "stability", "public_api_manifest.json")
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read stability/public_api_manifest.json: %v", err)
	}
	var manifest apiSurfaceManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("parse stability/public_api_manifest.json: %v", err)
	}

	wantTokens := append([]string{}, manifest.Docs.CLITokens...)
	wantTokens = append(wantTokens, "`docs/API_STABILITY_POLICY.md`", "`stability/public_api_manifest.json`")
	for _, target := range manifest.Go.CompileTargets {
		wantTokens = append(wantTokens, target.DocPackageToken)
		for _, entry := range target.Entries {
			wantTokens = append(wantTokens, entry.DocToken)
		}
	}

	docText := string(doc)
	for _, token := range wantTokens {
		if !strings.Contains(docText, token) {
			t.Fatalf("docs/API_SURFACE.md missing manifest token: %q", token)
		}
	}
}

type apiSurfaceManifest struct {
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
