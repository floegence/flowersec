# Flowersec API Contract

This document records the current public Flowersec integration contract.

Canonical source of truth: `stability/api_contract_manifest.json`

See also:

- Error model: `docs/ERROR_MODEL.md`
- API change policy: `docs/API_CHANGE_POLICY.md`

## CLI surface

Supported user-facing binaries:

- `flowersec-tunnel`
- `flowersec-proxy-gateway`
- `flowersec-issuer-keygen`
- `flowersec-channelinit`
- `flowersec-directinit`
- `idlgen`

Internal tooling under `flowersec-go/internal/cmd/*` is not part of the public CLI contract.

## Go packages

Recommended integration entrypoints:

- `github.com/floegence/flowersec/flowersec-go/client`
  - `client.Connect(...)`
  - `client.ConnectTunnel(...)`
  - `client.ConnectDirect(...)`
  - `client.WithObserver(...)`
  - `client.WithTransportSecurityPolicy(...)`
  - `client.WithOutboundRecordChunkBytes(...)`
  - `client.WithMaxBufferedBytes(...)`
  - `client.WithMaxOutboundBufferedBytes(...)`
  - `client.WithYamuxLimits(...)`
  - `client.WithLiveness(...)`
  - `client.WithLivenessDisabled()`
  - `client.LivenessOptions`
  - `client.YamuxLimits`
  - `client.Client.ProbeLiveness(...)`
  - `client.Client.Rekey()`
  - `client.Client.OpenStream(...)`
  - `client.RequireTLS`
  - `client.AllowPlaintextForLoopback`
  - `client.NewNetworkPlaintextPolicy(...)`
  - `client.NetworkPlaintextPolicyOptions`
  - `client.PlaintextRiskAcceptance`
  - `client.PlaintextRiskAcceptPreE2ECredentialExposure`
  - `client.AllowPlaintext`
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
  - `endpoint.DirectHandshakeCredential`
  - `endpoint.WithTransportSecurityPolicy(...)`
  - `endpoint.WithOutboundRecordChunkBytes(...)`
  - `endpoint.WithMaxBufferedBytes(...)`
  - `endpoint.WithMaxOutboundBufferedBytes(...)`
  - `endpoint.WithYamuxLimits(...)`
  - `endpoint.WithLiveness(...)`
  - `endpoint.WithLivenessDisabled()`
  - `endpoint.LivenessOptions`
  - `endpoint.YamuxLimits`
  - `endpoint.Session.ProbeLiveness(...)`
  - `endpoint.NewNetworkPlaintextPolicy(...)`
  - `endpoint.NetworkPlaintextPolicyOptions`
  - `endpoint.PlaintextRiskAcceptance`
  - `endpoint.PlaintextRiskAcceptPreE2ECredentialExposure`
  - `endpoint.Session.Rekey()`
  - `endpoint.Session.OpenStream(...)`
- `github.com/floegence/flowersec/flowersec-go/stream`
  - `stream.Stream`
  - `stream.Stream.Reset()`
- `github.com/floegence/flowersec/flowersec-go/transportsecurity`
  - `transportsecurity.Policy`
  - `transportsecurity.Input`
  - `transportsecurity.RequireTLS(...)`
  - `transportsecurity.AllowPlaintextForLoopback(...)`
  - `transportsecurity.NewNetworkPlaintextPolicy(...)`
  - `transportsecurity.NetworkPlaintextPolicyOptions`
  - `transportsecurity.PlaintextRiskAcceptance`
  - `transportsecurity.PlaintextRiskAcceptPreE2ECredentialExposure`
  - `transportsecurity.AllowPlaintext(...)`
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
  - `proxy.NewClient(...)`
  - `proxy.ClientHTTPRequest`
  - `proxy.ClientHTTPResponse`
  - `proxy.ClientWebSocket`
- `github.com/floegence/flowersec/flowersec-go/reconnect`
  - `reconnect.NewManager(...)`
  - `reconnect.OnceSource(...)`
  - `reconnect.RefreshableSource(...)`
  - `reconnect.ControlplaneSource(...)`
  - `reconnect.Config`
  - `reconnect.Settings`
  - `(*reconnect.Manager).Disconnect()`
- `github.com/floegence/flowersec/flowersec-go/proxy/preset`
  - `preset.Manifest`
  - `preset.DecodeJSON(...)`
  - `preset.LoadFile(...)`
  - `preset.ApplyBridgeOptions(...)`
- `github.com/floegence/flowersec/flowersec-go/rpc`
  - `rpc.NewRouter(...)`
  - `rpc.NewServer(...)`
  - `rpc.NewServerWithOptions(...)`
  - `rpc.ServerOptions`
  - `rpc.NewClient(...)`
- `github.com/floegence/flowersec/flowersec-go/framing/jsonframe`
  - `jsonframe.ReadJSONFrame(...)`
  - `jsonframe.WriteJSONFrame(...)`
  - `jsonframe.ReadJSONFrameDefaultMax(...)`
- `github.com/floegence/flowersec/flowersec-go/fserrors`
  - shared machine-readable `{path, stage, code}` types
  - `fserrors.CodeResourceExhausted`
- `github.com/floegence/flowersec/flowersec-go/controlplane/issuer`
  - `issuer.Keyset`
  - `issuer.New(...)`
  - `issuer.NewRandom(...)`
  - `issuer.Keyset.AddVerificationKey(...)`
  - `issuer.Keyset.Rotate(...)`
  - `issuer.Keyset.RetireVerificationKey(...)`
- `github.com/floegence/flowersec/flowersec-go/controlplane/channelinit`
- `github.com/floegence/flowersec/flowersec-go/controlplane/token`
- `github.com/floegence/flowersec/flowersec-go/tunnel/server`
  - `server.Config`
    - `MaxTenantQueuedBytes`
    - `MaxTotalQueuedBytes`
  - `server.ReplayCache`
  - `server.TokenUseCache`
  - `server.NewTokenUseCache(...)`
  - `server.HTTPAuthorizerConfig.MaxResponseBytes`
- `github.com/floegence/flowersec/flowersec-go/mux/yamux`
  - `yamux.Session.OpenStreamContext(...)`

Generated protocol packages:

- `github.com/floegence/flowersec/flowersec-go/gen/flowersec/controlplane/v1`
- `github.com/floegence/flowersec/flowersec-go/gen/flowersec/direct/v1`
- `github.com/floegence/flowersec/flowersec-go/gen/flowersec/tunnel/v1`
- `github.com/floegence/flowersec/flowersec-go/gen/flowersec/rpc/v1`
- `github.com/floegence/flowersec/flowersec-go/gen/flowersec/e2ee/v1`

Compatibility-only Go surface:

- legacy raw grant / wrapper / direct JSON inputs continue to work through `client.Connect(...)`
- `controlplane/client` stays the recommended Go client-side artifact fetch entry; `controlplane/http` is the recommended server-side helper-first reference layer
- deprecated named profile helpers such as `preset.ResolveBuiltin(...)` and gateway `proxy.profile` remain compatibility-only for `default`; the removed `codeserver` name is represented only by the static migration manifest

## TypeScript exports

Package entrypoints:

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
  - `RequireTLS`
  - `AllowPlaintextForLoopback`
  - `createNetworkPlaintextPolicy(...)`
  - `NetworkPlaintextPolicyOptions`
  - `PlaintextRiskAcceptance`
  - `AllowPlaintext`
  - `TransportSecurityPolicy`
  - `LivenessOptions`
  - `WebSocketLimits`
  - `YamuxLimits`
  - connect option `maxOutboundBufferedBytes`
  - connected client method `rekey()`
  - connected stream method `reset()`
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
  - `RequireTLS`
  - `AllowPlaintextForLoopback`
  - `createNetworkPlaintextPolicy(...)`
  - `NetworkPlaintextPolicyOptions`
  - `PlaintextRiskAcceptance`
  - `AllowPlaintext`
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
  - `RequireTLS`
  - `AllowPlaintextForLoopback`
  - `createNetworkPlaintextPolicy(...)`
  - `NetworkPlaintextPolicyOptions`
  - `PlaintextRiskAcceptance`
  - `AllowPlaintext`
- `@floegence/flowersec-core/controlplane`
  - `requestConnectArtifact(...)`
  - `requestEntryConnectArtifact(...)`
  - `ControlplaneRequestError`
  - `DEFAULT_CONNECT_ARTIFACT_PATH`
  - `DEFAULT_ENTRY_CONNECT_ARTIFACT_PATH`
  - `IssuerKeyset`
  - `signToken(...)`
  - `verifyToken(...)`
  - `ChannelInitService`

`IssuerKeyset` has one active signing key and a set of published verification keys. A new key must be added with `addVerificationKey(...)` before `rotate(...)` can activate its matching signing seed. `retireVerificationKey(...)` rejects the active key and unknown key IDs. `dispose()` is idempotent and terminal: signing, rotation, key publication, retirement, key inspection, and export all fail after disposal.
- `@floegence/flowersec-core/endpoint`
  - `Session`
  - `Session.rekey()`
  - `acceptDirect(...)`
  - `acceptDirectResolved(...)`
  - `connectTunnel(...)`

Public building blocks:

- `@floegence/flowersec-core/framing`
- `@floegence/flowersec-core/streamio`
  - `createJsonFrameChannel(...)`
  - `openJsonFrameChannel(...)`
- `@floegence/flowersec-core/proxy`
  - `createProxyRuntime(...)`
  - `ProxyRuntimeOptions` field `maxConcurrentHttpStreams`
  - `ProxyRuntimeOptions` field `maxQueuedHttpRequests`
  - `ProxyRuntimeOptions` field `maxQueuedHttpBodyBytes`
  - `ProxyRuntimeOptions` field `maxWsBufferedAmountBytes`
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
  - `serveProxySession(...)`
  - `serveProxyStream(...)`
  - `ProxyServerOptions`
- `@floegence/flowersec-core/reconnect`
  - `createReconnectManager()`
  - `ReconnectManager.connectIfNeeded(...)`
  - `ArtifactSource`
  - `createArtifactResolver(...)`
  - `createControlplaneArtifactSource(...)`
- `@floegence/flowersec-core/rpc`
  - `RpcProxy`
  - `RpcServer`
  - `RpcServerOptions`
  - `RpcServerTransport`
- `@floegence/flowersec-core/yamux`
  - `YamuxLimits`
  - `DEFAULT_YAMUX_LIMITS`
- `@floegence/flowersec-core/e2ee`
- `@floegence/flowersec-core/ws`
  - `WebSocketLimits`
  - `DEFAULT_WEB_SOCKET_LIMITS`
- `@floegence/flowersec-core/observability`
  - `DiagnosticEvent`
  - `normalizeObserver(...)`
  - `withObserverContext(...)`
- `@floegence/flowersec-core/streamhello`

Compatibility and alias TypeScript notes:

- legacy raw grant / wrapper / direct connect inputs remain accepted by `connect(...)`, `connectBrowser(...)`, and `connectNode(...)`
- browser `requestConnectArtifact(...)`, `requestEntryConnectArtifact(...)`, and `ControlplaneRequestError` remain compatibility aliases of `@floegence/flowersec-core/controlplane`; new code should prefer the canonical `@floegence/flowersec-core/controlplane` import
- `requestChannelGrant(...)` / `requestEntryChannelGrant(...)` remain supported for compatibility and bootstrap fallback flows, but they are no longer the preferred controlplane contract
- `connectTunnelProxyBrowser(...)` and `connectTunnelProxyControllerBrowser(...)` remain deprecated compatibility aliases over the artifact-first proxy bootstrap cores
- hybrid ambiguous inputs and legacy inputs mixed with artifact-only fields fail fast
- named proxy profiles are compatibility-only; use preset manifests instead

## SwiftPM module

Package:

- `Flowersec`
  - SwiftPM product: `Flowersec`
  - module import: `import Flowersec`

Connection and session entrypoints:

- `Flowersec.connect(...)`
- `Flowersec.connectTunnel(...)`
- `Flowersec.connectDirect(...)`
- `FlowersecClient`
- `FlowersecClient.rpc`
- `FlowersecClient.openStream(...)`
- `FlowersecClient.probeLiveness(...)`
- `FlowersecClient.rekey()`
- `FlowersecClient.close()`
- `ConnectOptions`
  - `ConnectOptions.connectTimeout`
  - `ConnectOptions.handshakeTimeout`
  - `ConnectOptions.maxOutboundBufferedBytes`
  - `ConnectOptions.scopeResolvers`
  - `ConnectOptions.relaxedOptionalScopeValidation`
- `ConnectScopeResolver`
- `ConnectScopeResolverMap`
- `DirectConnectOptions`
- `TunnelConnectOptions`
- `TransportSecurityPolicy`
- `TransportSecurityPolicyInput`
- `TransportSecurityPolicy.networkPlaintext(options:)`
- `NetworkPlaintextPolicyOptions`
- `PlaintextRiskAcceptance`
- `TransportSecurityDiagnostic`
- `TransportRuntime`
- `DiagnosticEvent`
- `DiagnosticCodeDomain`
- `DiagnosticResult`
- `LivenessOptions`
- `YamuxLimits`

Rust exposes the matching `TransportSecurityPolicy::network_plaintext(...)`,
`NetworkPlaintextPolicyOptions`, and `PlaintextRiskAcceptance` APIs.

RPC and stream building blocks:

- `RPCClient`
- `RPCClient.start()`
- `RPCClient.call(...)`
- `RPCClient.notify(...)`
- `RPCClient.onNotify(...)`
- `RPCClient.close()`
- `FlowersecRPCStream`
- `FlowersecByteStream`
- `FlowersecByteStream.reset()`
- `RPCSubscription`
- `RPCEnvelope`
- `RPCErrorPayload`
- `FlowersecRPCError`
- `FlowersecJSONFrame`
- `RPCServerOptions`
- `RPCRouter`
- `RPCServer`

Endpoint, controlplane, reconnect, and proxy building blocks:

- `Endpoint`
- `EndpointSession`
- `EndpointSession.rekey()`
- `EndpointSession.terminationError()`
- `EndpointOptions`
- `DirectEndpointCredential`
- `DirectCredentialResolver`
- `Controlplane`
- `FST2Token`
- `TokenIssuer`
  - `TokenIssuer.addVerificationKey(kid:publicKey:)`
  - `TokenIssuer.rotate(kid:seed:)`
  - `TokenIssuer.retireVerificationKey(kid:)`
- `ChannelInitService`
- `ArtifactSource`
- `ReconnectManager`
- `ReconnectConfig`
- `ReconnectSettings`
- `ProxyClient`
- `ProxyServer`
- `ProxyContractOptions`
- `ProxyServerOptions`
- `ProxyCookieJar`

Artifact and wire value types:

- `ConnectArtifact`
- `ConnectArtifactMetadata`
- `DirectConnectInfo`
- `ChannelInitGrant`
- `ScopeMetadataEntry`
- `ScopePayload`
- `ScopePayloadValue`
- `CorrelationContext`
- `CorrelationKV`
- `Suite`
- `FlowersecError`
- `FlowersecPath`
- `FlowersecStage`
- `FlowersecCode`

## Rust crate

The native Rust package is `flowersec` and targets Rust 1.85 or newer.

Entrypoints and modules:

- `flowersec::connect(...)`
- `flowersec::connect_direct(...)`
- `flowersec::connect_tunnel(...)`
- `flowersec::Client`
- `flowersec::endpoint`
- `flowersec::rpc`
- `flowersec::controlplane`
- `flowersec::reconnect`
- `flowersec::proxy`
- `flowersec::observability`
- `flowersec::generated`
- `flowersec::transport::WebSocketTransport`
- `flowersec::transport::TungsteniteTransport`
- `flowersec::endpoint::accept_direct(...)`
- `flowersec::endpoint::accept_direct_resolved(...)`
- `flowersec::endpoint::connect_tunnel(...)`
- `flowersec::endpoint::Session`
- `flowersec::Client::rekey()`
- `flowersec::endpoint::Session::rekey()`
- `flowersec::endpoint::Session::termination_error()`
- `flowersec::yamux::YamuxStream::reset()`
- `flowersec::rpc::RpcClient`
- `flowersec::rpc::Router`
- `flowersec::rpc::Server`
- `flowersec::controlplane::client`
- `flowersec::controlplane::token`
- `flowersec::controlplane::issuer`
- `flowersec::controlplane::issuer::Keyset`
- `Keyset::add_verification_key(...)`
- `Keyset::rotate(...)`
- `Keyset::retire_verification_key(...)`
- `flowersec::controlplane::channelinit`
- `flowersec::reconnect::ReconnectManager`
- `flowersec::reconnect::ReconnectManager::disconnect(...)`
- `flowersec::proxy::ProxyClient`
- `flowersec::proxy::ProxyServer`

## Shared issuer and runtime contracts

Issuer rotation uses one path in all four SDKs:

1. Publish the next verification key.
2. Deploy or reload the complete overlap keyset on every verifier.
3. Activate the matching private key in the issuer.
4. Retire the previous verification key only after the overlap window has elapsed.

Rotation never inserts a missing verification key implicitly. Reusing a key ID with different key material fails without changing issuer state. Public key snapshots are isolated from caller mutation, and serialized tunnel keysets are ordered by key ID.

The canonical resource defaults are recorded in `stability/sdk_defaults.json`:

- `max_inbound_buffered_bytes` bounds retained decrypted plaintext where a secure-channel implementation maintains an inbound buffer.
- `max_outbound_buffered_bytes` bounds the total bytes of accepted logical application writes that have not completed. It is not a per-record or per-frame limit.
- `max_stream_write_queue_bytes` is the independent Yamux per-stream write queue budget. It must not reuse the secure-channel outbound budget merely because the numeric defaults currently match.

RPC request and response IDs use the portable JSON integer range `0...9007199254740991`. Generated request IDs use `1...9007199254740991`; `0` remains the unset value. An exhausted generator fails before writing and never wraps.

The cross-language executable evidence is `testdata/issuer_rotation_vectors.json` and `testdata/runtime_contract_vectors.json`.

## Contract enforcement

All public exports are governed by `docs/API_CHANGE_POLICY.md`; there is no separate public API tier. The contract manifest and local quality gate verify:

- Go public-symbol compilation
- TypeScript packed-package exports and runtime imports
- Swift public symbol-graph equality
- Rust public-entrypoint compilation and release SemVer comparison
- shared defaults, schemas, registries, generated artifacts, and language capability evidence
- Go-reference interoperability for direct/tunnel sessions, RPC, streams, liveness, rekey, reset, reconnect, and proxy traffic

Internal, unexported implementation details may evolve without manifest entries as long as these public and behavioral checks remain green.
