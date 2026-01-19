# Flowersec API Surface

This document defines the intended stable ("public") API surface of this repository.
It is meant to remove guesswork for integrators: which packages and entrypoints you can depend on without importing internal building blocks directly.

Status: experimental; not audited.

## CLI surface

Supported binaries (user-facing):

- `flowersec-tunnel` (deployable tunnel server)
- `flowersec-issuer-keygen` (helper: generate issuer keypair and tunnel public keyset)
- `flowersec-channelinit` (helper: mint a `ChannelInitGrant` pair)

Internal tooling (not supported as a public CLI surface):

- `flowersec-go/internal/cmd/*` (interop harnesses, load generators)

## Go: stable packages

These packages are the recommended integration entrypoints:

- `github.com/floegence/flowersec/flowersec-go/client`
  - Role: `client`
  - APIs: `client.ConnectTunnel(...)`, `client.ConnectDirect(...)`
- `github.com/floegence/flowersec/flowersec-go/endpoint`
  - Role: `server`
  - APIs: `endpoint.ConnectTunnel(...)`, `endpoint.NewDirectHandler(...)`, `endpoint.AcceptDirectWS(...)`, `endpoint.NewDirectHandlerResolved(...)`, `endpoint.AcceptDirectWSResolved(...)`
- `github.com/floegence/flowersec/flowersec-go/endpoint/serve`
  - Role: server runtime
  - APIs: `serve.New(...)`, `srv.Handle(...)`, `srv.ServeSession(...)`, `serve.ServeTunnel(...)`
- `github.com/floegence/flowersec/flowersec-go/protocolio`
  - Role: JSON decoding helpers for `ChannelInitGrant` and `DirectConnectInfo`
- `github.com/floegence/flowersec/flowersec-go/fserrors`
  - Role: stable error codes (`Path`, `Stage`, `Code`)

Controlplane helpers (supported for integration and used by the helper CLIs):

- `github.com/floegence/flowersec/flowersec-go/controlplane/issuer`
- `github.com/floegence/flowersec/flowersec-go/controlplane/channelinit`
- `github.com/floegence/flowersec/flowersec-go/controlplane/token`

## Go: building blocks (not a stable surface)

The repository also contains lower-level components (crypto, framing, yamux, rpc, ws, tunnel internals).
They are useful for contributors and advanced integrations, but are not intended as a stable API surface.

If you rely on these directly, expect breaking changes without deprecation cycles.

## TypeScript: stable exports

Stable entrypoints:

- `@flowersec/core`:
  - `connect(...)`, `connectTunnel(...)`, `connectDirect(...)`
  - `Client`, `FlowersecError`, protocol types and asserts
- `@flowersec/core/node`:
  - `connectNode(...)`, `connectTunnelNode(...)`, `connectDirectNode(...)`, `createNodeWsFactory()`
- `@flowersec/core/browser`:
  - `connectBrowser(...)`, `connectTunnelBrowser(...)`, `connectDirectBrowser(...)`

Unstable entrypoint:

- `@flowersec/core/internal` (internal glue; not recommended as a stable dependency)
