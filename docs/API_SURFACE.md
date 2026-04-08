# Flowersec API Surface

This document defines the stable integration surface for Flowersec v0.18.x.

Canonical source of truth for the stable surface: `stability/public_api_manifest.json`

See also:

- Error model: `docs/ERROR_MODEL.md`
- API stability policy: `docs/API_STABILITY_POLICY.md`

## CLI surface

Supported user-facing binaries:

- `flowersec-tunnel`
- `flowersec-proxy-gateway`
- `flowersec-issuer-keygen`
- `flowersec-channelinit`
- `flowersec-directinit`
- `idlgen`

Internal tooling under `flowersec-go/internal/cmd/*` is not a stable CLI surface.

## Go: stable packages

Recommended integration entrypoints:

- `github.com/floegence/flowersec/flowersec-go/client`
  - `client.Connect(...)`
  - `client.ConnectTunnel(...)`
  - `client.ConnectDirect(...)`
  - `client.WithObserver(...)`
- `github.com/floegence/flowersec/flowersec-go/endpoint`
  - `endpoint.ConnectTunnel(...)`
  - `endpoint.NewDirectHandler(...)`
  - `endpoint.AcceptDirectWS(...)`
  - `endpoint.NewDirectHandlerResolved(...)`
  - `endpoint.AcceptDirectWSResolved(...)`
  - `endpoint.Suite`
  - `SuiteX25519HKDFAES256GCM`
  - `SuiteP256HKDFAES256GCM`
  - `endpoint.UpgraderOptions`
  - `endpoint.HandshakeCache`
  - `endpoint.AcceptDirectOptions`
  - `endpoint.AcceptDirectResolverOptions`
- `github.com/floegence/flowersec/flowersec-go/endpoint/serve`
  - `serve.New(...)`
  - `srv.Handle(...)`
  - `srv.HandleStream(...)`
  - `srv.ServeSession(...)`
  - `serve.ServeTunnel(...)`
  - `serve.NewDirectHandler(...)`
  - `serve.NewDirectHandlerResolved(...)`
- `github.com/floegence/flowersec/flowersec-go/protocolio`
  - `protocolio.DecodeGrantClientJSON(...)`
  - `protocolio.DecodeGrantServerJSON(...)`
  - `protocolio.DecodeGrantJSON(...)`
  - `protocolio.DecodeDirectConnectInfoJSON(...)`
  - `protocolio.DecodeConnectArtifactJSON(...)`
  - `protocolio.ConnectArtifact`
  - `protocolio.TunnelClientConnectArtifact`
  - `protocolio.DirectClientConnectArtifact`
  - `protocolio.CorrelationContext`
  - `protocolio.CorrelationKV`
  - `protocolio.ScopeMetadataEntry`
- `github.com/floegence/flowersec/flowersec-go/controlplane/client`
  - `client.RequestConnectArtifact(...)`
  - `client.RequestEntryConnectArtifact(...)`
  - `client.RequestError`
- `github.com/floegence/flowersec/flowersec-go/observability`
  - `observability.DiagnosticEvent`
  - `observability.ClientObserver`
  - `observability.NormalizeClientObserver(...)`
  - `observability.WithClientObserverContext(...)`
- `github.com/floegence/flowersec/flowersec-go/origin`
  - `origin.FromWSURL(...)`
  - `origin.ForTunnel(...)`
- `github.com/floegence/flowersec/flowersec-go/proxy`
  - `proxy.Register(...)`
- `github.com/floegence/flowersec/flowersec-go/proxy/preset`
  - `preset.Manifest`
  - `preset.DecodeJSON(...)`
  - `preset.LoadFile(...)`
  - `preset.ApplyBridgeOptions(...)`
- `github.com/floegence/flowersec/flowersec-go/rpc`
  - `rpc.NewRouter(...)`
  - `rpc.NewServer(...)`
  - `rpc.NewClient(...)`
- `github.com/floegence/flowersec/flowersec-go/framing/jsonframe`
  - `jsonframe.ReadJSONFrame(...)`
  - `jsonframe.WriteJSONFrame(...)`
  - `jsonframe.ReadJSONFrameDefaultMax(...)`
- `github.com/floegence/flowersec/flowersec-go/fserrors`
  - stable machine-readable `{path, stage, code}` types
- `github.com/floegence/flowersec/flowersec-go/controlplane/issuer`
- `github.com/floegence/flowersec/flowersec-go/controlplane/channelinit`
- `github.com/floegence/flowersec/flowersec-go/controlplane/token`

Stable generated protocol packages:

- `github.com/floegence/flowersec/flowersec-go/gen/flowersec/controlplane/v1`
- `github.com/floegence/flowersec/flowersec-go/gen/flowersec/direct/v1`
- `github.com/floegence/flowersec/flowersec-go/gen/flowersec/tunnel/v1`
- `github.com/floegence/flowersec/flowersec-go/gen/flowersec/rpc/v1`
- `github.com/floegence/flowersec/flowersec-go/gen/flowersec/e2ee/v1`

Compatibility-only Go surface:

- legacy raw grant / wrapper / direct JSON inputs continue to work through `client.Connect(...)`
- deprecated named profile helpers such as `preset.ResolveBuiltin(...)` and gateway `proxy.profile` remain compatibility-only; they are not part of the stable core surface

## TypeScript: stable exports

Stable entrypoints:

- `@floegence/flowersec-core`
  - `connect(...)`
  - `connectTunnel(...)`
  - `connectDirect(...)`
  - `ConnectArtifact`
  - `CorrelationContext`
  - `CorrelationKV`
  - `TunnelClientConnectArtifact`
  - `DirectClientConnectArtifact`
  - `ScopeMetadataEntry`
  - `assertConnectArtifact(...)`
- `@floegence/flowersec-core/node`
  - `connectNode(...)`
  - `connectTunnelNode(...)`
  - `connectDirectNode(...)`
  - `createNodeWsFactory()`
  - `ConnectArtifact`
  - `CorrelationContext`
  - `CorrelationKV`
  - `TunnelClientConnectArtifact`
  - `DirectClientConnectArtifact`
  - `ScopeMetadataEntry`
  - `assertConnectArtifact(...)`
- `@floegence/flowersec-core/browser`
  - `connectBrowser(...)`
  - `connectTunnelBrowser(...)`
  - `connectDirectBrowser(...)`
  - `ConnectArtifact`
  - `CorrelationContext`
  - `CorrelationKV`
  - `TunnelClientConnectArtifact`
  - `DirectClientConnectArtifact`
  - `ScopeMetadataEntry`
  - `assertConnectArtifact(...)`
  - `requestChannelGrant(...)`
  - `requestEntryChannelGrant(...)`
  - `requestConnectArtifact(...)`
  - `requestEntryConnectArtifact(...)`
  - `ControlplaneRequestError`
  - `createBrowserReconnectConfig(...)`
  - `createTunnelBrowserReconnectConfig(...)`
  - `createDirectBrowserReconnectConfig(...)`

Stable building blocks:

- `@floegence/flowersec-core/framing`
- `@floegence/flowersec-core/streamio`
  - `createJsonFrameChannel(...)`
  - `openJsonFrameChannel(...)`
- `@floegence/flowersec-core/proxy`
  - `createProxyRuntime(...)`
  - `createProxyServiceWorkerScript(...)`
  - `createProxyIntegrationServiceWorkerScript(...)`
  - `registerProxyIntegration(...)`
  - `registerServiceWorkerAndEnsureControl(...)`
  - `connectTunnelProxyBrowser(...)`
  - `connectTunnelProxyControllerBrowser(...)`
  - `createServiceWorkerControllerGuard(...)`
  - `registerProxyControllerWindow(...)`
  - `registerProxyAppWindow(...)`
  - `registerProxyAppWindowWithServiceWorkerControl(...)`
  - `installWebSocketPatch(...)`
  - `disableUpstreamServiceWorkerRegister()`
  - `assertProxyPresetManifest(...)`
  - `resolveProxyPreset(...)`
  - `DEFAULT_PROXY_PRESET_MANIFEST`
- `@floegence/flowersec-core/reconnect`
  - `createReconnectManager()`
  - `ReconnectManager.connectIfNeeded(...)`
- `@floegence/flowersec-core/rpc`
  - `RpcProxy`
- `@floegence/flowersec-core/yamux`
- `@floegence/flowersec-core/e2ee`
- `@floegence/flowersec-core/ws`
- `@floegence/flowersec-core/observability`
  - `DiagnosticEvent`
  - `normalizeObserver(...)`
  - `withObserverContext(...)`
- `@floegence/flowersec-core/streamhello`

Compatibility-only TypeScript surface:

- legacy raw grant / wrapper / direct connect inputs remain accepted by `connect(...)`, `connectBrowser(...)`, and `connectNode(...)`
- hybrid ambiguous inputs and legacy inputs mixed with artifact-only fields now fail fast
- named proxy profiles are no longer stable core APIs; use preset manifests instead

## Stable vs experimental notes

Stable in v0.18.x:

- client-facing canonical `ConnectArtifact`
- strict canonical parse / validate rules
- artifact-aware client connect entrypoints
- correlation metadata carrier
- runtime `DiagnosticEvent`
- artifact fetch helpers
- proxy preset manifest contract

Still experimental in v0.18.x:

- public normalize helper shapes
- public scope resolver registration API
- scoped manifest toolchain/codegen factory
- concrete scoped payload schemas such as `proxy.runtime`
- bilateral contract negotiation semantics

## Not part of the stable surface

- `@floegence/flowersec-core/internal`
- lower-level tunnel / yamux / crypto internals not listed above
- repository reference assets under `reference/`
- deprecated named proxy profiles
