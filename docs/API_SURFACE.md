# Flowersec API Surface

This document defines the stable integration surface for Flowersec v0.19.x.

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
- `github.com/floegence/flowersec/flowersec-go/controlplane/http`
  - `controlplanehttp.DefaultMaxBodyBytes`
  - `controlplanehttp.ArtifactRequest`
  - `controlplanehttp.ArtifactEnvelope`
  - `controlplanehttp.ErrorEnvelope`
  - `controlplanehttp.ArtifactRequestMetadata`
  - `controlplanehttp.ArtifactIssueInput`
  - `controlplanehttp.ArtifactHandlerOptions`
  - `controlplanehttp.RequestError`
  - `controlplanehttp.NewRequestError(...)`
  - `controlplanehttp.DecodeArtifactRequest(...)`
  - `controlplanehttp.WriteArtifactEnvelope(...)`
  - `controlplanehttp.WriteErrorEnvelope(...)`
  - `controlplanehttp.NewArtifactHandler(...)`
  - `controlplanehttp.NewEntryArtifactHandler(...)`
  - `controlplanehttp.DefaultRequestMetadata(...)`
  - `controlplanehttp.IssueArtifact(...)`
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
- `controlplane/client` stays the recommended Go client-side artifact fetch entry; `controlplane/http` is the recommended server-side helper-first reference layer
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
  - `createNodeReconnectConfig(...)`
  - `createTunnelNodeReconnectConfig(...)`
  - `createDirectNodeReconnectConfig(...)`
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
- `@floegence/flowersec-core/controlplane`
  - `requestConnectArtifact(...)`
  - `requestEntryConnectArtifact(...)`
  - `ControlplaneRequestError`
  - `DEFAULT_CONNECT_ARTIFACT_PATH`
  - `DEFAULT_ENTRY_CONNECT_ARTIFACT_PATH`

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
  - `connectArtifactProxyBrowser(...)`
  - `connectArtifactProxyControllerBrowser(...)`
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

Compatibility and alias TypeScript notes:

- legacy raw grant / wrapper / direct connect inputs remain accepted by `connect(...)`, `connectBrowser(...)`, and `connectNode(...)`
- browser `requestConnectArtifact(...)`, `requestEntryConnectArtifact(...)`, and `ControlplaneRequestError` remain stable aliases of `@floegence/flowersec-core/controlplane`; new code should prefer the canonical `@floegence/flowersec-core/controlplane` import
- `requestChannelGrant(...)` / `requestEntryChannelGrant(...)` remain supported for compatibility and bootstrap fallback flows, but they are no longer the preferred controlplane contract
- `connectTunnelProxyBrowser(...)` and `connectTunnelProxyControllerBrowser(...)` remain stable deprecated aliases over the artifact-first proxy bootstrap cores
- hybrid ambiguous inputs and legacy inputs mixed with artifact-only fields fail fast
- named proxy profiles are no longer stable core APIs; use preset manifests instead

## Stable vs experimental notes

Stable in v0.19.x:

- client-facing canonical `ConnectArtifact`
- strict canonical parse / validate rules
- artifact-aware browser, node, and Go client connect entrypoints
- `@floegence/flowersec-core/controlplane` helper contract
- Node/browser artifact-aware reconnect adapters
- `controlplane/http` helper-first Go reference layer
- correlation metadata carrier
- runtime `DiagnosticEvent`
- proxy preset manifest contract
- `proxy.runtime@1` when consumed through stable proxy helper entrypoints

Still experimental in v0.19.x:

- public normalize helper shapes
- public scope resolver registration API
- scoped manifest toolchain/codegen factory outside the frozen `proxy.runtime@1` contract
- bilateral scope negotiation semantics
- direct-transport proxy helper support beyond the documented tunnel-first browser flows
