package apicheck

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/client"
	"github.com/floegence/flowersec/flowersec-go/controlplane/channelinit"
	"github.com/floegence/flowersec/flowersec-go/controlplane/issuer"
	"github.com/floegence/flowersec/flowersec-go/controlplane/token"
	"github.com/floegence/flowersec/flowersec-go/endpoint"
	"github.com/floegence/flowersec/flowersec-go/endpoint/serve"
	"github.com/floegence/flowersec/flowersec-go/framing/jsonframe"
	"github.com/floegence/flowersec/flowersec-go/fserrors"
	"github.com/floegence/flowersec/flowersec-go/protocolio"
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

	docPath := filepath.Join(dir, "..", "..", "..", "docs", "API_SURFACE.md")
	doc, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("read docs/API_SURFACE.md: %v", err)
	}

	// Stable CLIs.
	wantCLI := []string{
		"flowersec-tunnel",
		"flowersec-issuer-keygen",
		"flowersec-channelinit",
		"flowersec-directinit",
		"idlgen",
	}
	for _, v := range wantCLI {
		if !bytes.Contains(doc, []byte("`"+v+"`")) {
			t.Fatalf("docs/API_SURFACE.md missing stable CLI: %q", v)
		}
	}

	// Stable Go packages.
	wantPackages := []string{
		"github.com/floegence/flowersec/flowersec-go/client",
		"github.com/floegence/flowersec/flowersec-go/endpoint",
		"github.com/floegence/flowersec/flowersec-go/endpoint/serve",
		"github.com/floegence/flowersec/flowersec-go/rpc",
		"github.com/floegence/flowersec/flowersec-go/framing/jsonframe",
		"github.com/floegence/flowersec/flowersec-go/protocolio",
		"github.com/floegence/flowersec/flowersec-go/fserrors",
		"github.com/floegence/flowersec/flowersec-go/controlplane/issuer",
		"github.com/floegence/flowersec/flowersec-go/controlplane/channelinit",
		"github.com/floegence/flowersec/flowersec-go/controlplane/token",
	}
	for _, v := range wantPackages {
		if !bytes.Contains(doc, []byte("`"+v+"`")) {
			t.Fatalf("docs/API_SURFACE.md missing stable Go package: %q", v)
		}
	}

	// Stable Go entrypoints.
	wantEntrypoints := []string{
		"client.Connect(...)",
		"client.ConnectTunnel(...)",
		"client.ConnectDirect(...)",

		"endpoint.ConnectTunnel(...)",
		"endpoint.NewDirectHandler(...)",
		"endpoint.AcceptDirectWS(...)",
		"endpoint.NewDirectHandlerResolved(...)",
		"endpoint.AcceptDirectWSResolved(...)",

		"endpoint.Suite",
		"SuiteX25519HKDFAES256GCM",
		"SuiteP256HKDFAES256GCM",
		"endpoint.UpgraderOptions",
		"endpoint.HandshakeCache",

		"serve.New(...)",
		"srv.Handle(...)",
		"srv.HandleStream(...)",
		"srv.ServeSession(...)",
		"serve.ServeTunnel(...)",
		"serve.NewDirectHandler(...)",
		"serve.NewDirectHandlerResolved(...)",

		"protocolio.DecodeGrantClientJSON(...)",
		"protocolio.DecodeGrantServerJSON(...)",
		"protocolio.DecodeGrantJSON(...)",
		"protocolio.DecodeDirectConnectInfoJSON(...)",

		"rpc.NewRouter(...)",
		"rpc.NewServer(...)",
		"rpc.NewClient(...)",

		"jsonframe.ReadJSONFrame(...)",
		"jsonframe.WriteJSONFrame(...)",
		"jsonframe.ReadJSONFrameDefaultMax(...)",
	}
	for _, v := range wantEntrypoints {
		if !bytes.Contains(doc, []byte("`"+v+"`")) {
			t.Fatalf("docs/API_SURFACE.md missing stable entrypoint: %q", v)
		}
	}
}
