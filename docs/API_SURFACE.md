# Flowersec API Surface

This document defines the intended stable ("public") API surface of this repository.
It is meant to remove guesswork for integrators: which packages and entrypoints you can depend on without importing internal building blocks directly.

Status: experimental; not audited.

See also:

- Error model: `docs/ERROR_MODEL.md`

## CLI surface

Supported binaries (user-facing):

- `flowersec-tunnel` (deployable tunnel server)
- `flowersec-proxy-gateway` (deployable L7 HTTP/WS gateway; forwards to a server endpoint via `flowersec-proxy/*` streams)
- `flowersec-issuer-keygen` (helper: generate issuer keypair and tunnel public keyset)
- `flowersec-channelinit` (helper: mint a `ChannelInitGrant` pair)
- `flowersec-directinit` (helper: generate a `DirectConnectInfo` JSON object for direct (no tunnel) demos)
- `idlgen` (code generator for `*.fidl.json` IDL; install via `go install github.com/floegence/flowersec/tools/idlgen@latest`)

Internal tooling (not supported as a public CLI surface):

- `flowersec-go/internal/cmd/*` (interop harnesses, load generators)

## Go: stable packages

These packages are the recommended integration entrypoints:

- `github.com/floegence/flowersec/flowersec-go/client`
  - Role: `client`
  - APIs: `client.Connect(...)`, `client.ConnectTunnel(...)`, `client.ConnectDirect(...)`
- `github.com/floegence/flowersec/flowersec-go/endpoint`
  - Role: `server`
  - APIs: `endpoint.ConnectTunnel(...)`, `endpoint.NewDirectHandler(...)`, `endpoint.AcceptDirectWS(...)`, `endpoint.NewDirectHandlerResolved(...)`, `endpoint.AcceptDirectWSResolved(...)` (direct server building blocks; most apps should use `endpoint/serve`)
  - Types: `endpoint.Suite` (`SuiteX25519HKDFAES256GCM`, `SuiteP256HKDFAES256GCM`), `endpoint.UpgraderOptions`, `endpoint.HandshakeCache`, `endpoint.AcceptDirectOptions`, `endpoint.AcceptDirectResolverOptions`
- `github.com/floegence/flowersec/flowersec-go/endpoint/serve`
  - Role: server runtime
  - APIs: `serve.New(...)`, `srv.Handle(...)`, `srv.HandleStream(...)`, `srv.ServeSession(...)`, `serve.ServeTunnel(...)`, `serve.NewDirectHandler(...)`, `serve.NewDirectHandlerResolved(...)`
- `github.com/floegence/flowersec/flowersec-go/proxy`
  - Role: server endpoint add-on
  - APIs: `proxy.Register(...)` (registers `flowersec-proxy/http1` and `flowersec-proxy/ws` stream handlers)
- `github.com/floegence/flowersec/flowersec-go/rpc`
  - Role: stable RPC client/server/router APIs (used by `Client.RPC()` and `endpoint/serve`)
  - APIs: `rpc.NewRouter(...)`, `rpc.NewServer(...)`, `rpc.NewClient(...)`
- `github.com/floegence/flowersec/flowersec-go/framing/jsonframe`
  - Role: stable JSON framing helpers (length-prefixed JSON frames)
  - APIs: `jsonframe.ReadJSONFrame(...)`, `jsonframe.WriteJSONFrame(...)`, `jsonframe.ReadJSONFrameDefaultMax(...)`
- `github.com/floegence/flowersec/flowersec-go/protocolio`
  - Role: JSON decoding helpers for `ChannelInitGrant` and `DirectConnectInfo`
  - APIs: `protocolio.DecodeGrantClientJSON(...)`, `protocolio.DecodeGrantServerJSON(...)`, `protocolio.DecodeGrantJSON(...)`, `protocolio.DecodeDirectConnectInfoJSON(...)`
- `github.com/floegence/flowersec/flowersec-go/fserrors`
  - Role: stable error codes (`Path`, `Stage`, `Code`)

Controlplane helpers (supported for integration and used by the helper CLIs):

- `github.com/floegence/flowersec/flowersec-go/controlplane/issuer`
- `github.com/floegence/flowersec/flowersec-go/controlplane/channelinit`
- `github.com/floegence/flowersec/flowersec-go/controlplane/token`

## Go: stable protocol types (generated)

The stable APIs above use generated protocol types. These packages are safe to depend on:

- `github.com/floegence/flowersec/flowersec-go/gen/flowersec/controlplane/v1`
- `github.com/floegence/flowersec/flowersec-go/gen/flowersec/direct/v1`
- `github.com/floegence/flowersec/flowersec-go/gen/flowersec/tunnel/v1`
- `github.com/floegence/flowersec/flowersec-go/gen/flowersec/rpc/v1`
- `github.com/floegence/flowersec/flowersec-go/gen/flowersec/e2ee/v1`

## Go: building blocks (not a stable surface)

The repository also contains lower-level components (crypto, yamux, ws, tunnel internals, and additional framing utilities beyond the stable packages listed above).
They are useful for contributors and advanced integrations, but are not intended as a stable API surface.

If you rely on these directly, expect breaking changes without deprecation cycles.

## TypeScript: stable exports

Stable entrypoints:

- `@floegence/flowersec-core`:
  - `connect(...)`, `connectTunnel(...)`, `connectDirect(...)`
  - `Client`, `FlowersecError`, protocol types and asserts
- `@floegence/flowersec-core/node`:
  - `connectNode(...)`, `connectTunnelNode(...)`, `connectDirectNode(...)`, `createNodeWsFactory()`
- `@floegence/flowersec-core/browser`:
  - `connectBrowser(...)`, `connectTunnelBrowser(...)`, `connectDirectBrowser(...)`

Stable building blocks (advanced, but supported):

- `@floegence/flowersec-core/framing` (length-prefixed JSON framing helpers)
- `@floegence/flowersec-core/streamio` (stream IO helpers for custom yamux streams)
- `@floegence/flowersec-core/proxy` (browser runtime helpers for `flowersec-proxy/http1` + `flowersec-proxy/ws`)
  - `createProxyRuntime(...)`
  - `createProxyServiceWorkerScript(...)`
  - `registerServiceWorkerAndEnsureControl(...)`
  - `installWebSocketPatch(...)`
  - `disableUpstreamServiceWorkerRegister()`
- `@floegence/flowersec-core/reconnect` (framework-agnostic reconnect state machine)
  - `createReconnectManager()`
- `@floegence/flowersec-core/rpc` (RPC client/server over length-prefixed JSON frames)
- `@floegence/flowersec-core/yamux` (yamux framing and session)
- `@floegence/flowersec-core/e2ee` (record layer and handshake helpers)
- `@floegence/flowersec-core/ws` (WebSocket binary transport)
- `@floegence/flowersec-core/observability` (observer types)
- `@floegence/flowersec-core/streamhello` (stream hello helpers)

Unstable entrypoint:

- `@floegence/flowersec-core/internal` (internal glue; not recommended as a stable dependency)
