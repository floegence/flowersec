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
  - `client.ConnectArtifactRequestConfig.AllowLoopbackHTTP`
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
  - `proxy.Options`
  - `proxy.DefaultMaxConcurrentStreams`
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
- preset manifests are accepted only through manifest files or decoded manifest objects; named profile helpers and gateway `proxy.profile` have been removed

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
  - `serveProxySession(...)`
  - `serveProxyStream(...)`
  - `ProxyServerOptions`
  - `ProxyServerOptions.maxConcurrentStreams`
  - `ProxyServerOptions.maxWsQueuedBytes`
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
  - `createBrowserReconnectConfig(...)`
  - `createTunnelBrowserReconnectConfig(...)`
  - `createDirectBrowserReconnectConfig(...)`
  - `RequireTLS`
  - `AllowPlaintextForLoopback`
  - `createNetworkPlaintextPolicy(...)`
  - `NetworkPlaintextPolicyOptions`
  - `PlaintextRiskAcceptance`
- `@floegence/flowersec-core/controlplane`
  - `requestConnectArtifact(...)`
  - `requestEntryConnectArtifact(...)`
  - `ControlplaneRequestError`
  - `ConnectArtifactRequestConfig.allowLoopbackHTTP`
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
- `requestChannelGrant(...)` / `requestEntryChannelGrant(...)` remain supported for compatibility and bootstrap fallback flows, but they are no longer the preferred controlplane contract
- artifact helpers and `ControlplaneRequestError` are exported only by `@floegence/flowersec-core/controlplane`
- proxy browser bootstrap is artifact-first through `connectArtifactProxyBrowser(...)` and `connectArtifactProxyControllerBrowser(...)`
- controller/app Window bridges use the `stream_bidirectional_ack_v2` contract and require both sides to run the same Flowersec minor version; mixed versions fail during bridge open and do not fall back to the earlier unbounded one-direction acknowledgement behavior
- hybrid ambiguous inputs and legacy inputs mixed with artifact-only fields fail fast
- named proxy profiles have been removed; use preset manifests instead

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

Artifact acquisition requires an absolute HTTPS URL by default. Go
`client.ConnectArtifactRequestConfig.AllowLoopbackHTTP`, TypeScript
`ConnectArtifactRequestConfig.allowLoopbackHTTP`, Swift
`ArtifactRequestOptions.allowLoopbackHTTP`, and Rust
`ConnectArtifactRequestConfig.allow_loopback_http` opt in to HTTP only for literal
`localhost`, canonical `127.0.0.0/8`, or `::1` targets. Artifact clients reject
userinfo, unsupported schemes, non-canonical loopback addresses, and redirects.
Rust custom HTTP configuration is accepted only through
`flowersec::controlplane::client::ArtifactHttpClient`, which always disables
redirects. Its explicit option is
`flowersec::controlplane::client::ConnectArtifactRequestConfig.allow_loopback_http`.

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
- `ProxyServerOptions.maxConcurrentStreams`
- `FlowersecSDKDefaults.Proxy.maxConcurrentStreams`
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
- `flowersec::client::ConnectOptions`
- `flowersec::client::ConnectOptions.liveness`
- `flowersec::endpoint`
- `flowersec::rpc`
- `flowersec::controlplane`
- `flowersec::reconnect`
- `flowersec::proxy`
- `flowersec::proxy::ServerOptions`
- `flowersec::proxy::ServerOptions.max_concurrent_streams`
- `flowersec::observability`
- `flowersec::generated`
- `flowersec::transport::WebSocketTransport`
- `flowersec::transport::TungsteniteTransport`
- `flowersec::transport::TungsteniteTransport::new(...)`
- `flowersec::transport::TungsteniteTransport::accept(...)`
- `flowersec::transport::TungsteniteTransport::accept_with_timeout(...)`
- `flowersec::endpoint::accept_direct(...)`
- `flowersec::endpoint::accept_direct_resolved(...)`
- `flowersec::endpoint::connect_tunnel(...)`
- `flowersec::endpoint::Session`
- `flowersec::endpoint::EndpointOptions`
- `flowersec::endpoint::EndpointOptions.liveness`
- `flowersec::endpoint::DirectAcceptOptions`
- `flowersec::endpoint::DirectAcceptOptions.liveness`
- `flowersec::Client::rekey()`
- `flowersec::endpoint::Session::rekey()`
- `flowersec::endpoint::Session::termination_error()`
- `flowersec::yamux::YamuxStream::reset()`
- `flowersec::yamux::LivenessOptions`
- `flowersec::yamux::YamuxLimits`
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

Rust liveness configuration uses `flowersec::yamux::LivenessOptions` without an
additional root-module alias. `PathDefault` disables automatic probes for direct
sessions and derives tunnel probes from the grant idle timeout; `Disabled` and
`Enabled { interval, timeout }` provide explicit control. Adding the public
`liveness` fields is an intentional pre-1.0 source change: consumers using
exhaustive struct literals must set the field or use `..Default::default()`, and
the introducing release must call this out in its release notes.

Rust raw-stream endpoint accepts apply the encrypted-record message and frame
limits before returning a transport. `TungsteniteTransport::accept(...)` also
bounds the HTTP WebSocket upgrade with the default handshake timeout, while
`accept_with_timeout(...)` accepts an explicit duration. Injecting an existing
`WebSocketStream` through `new(...)` returns `io::Result` and fails unless that
stream already uses equivalent or stricter message and frame limits. The
fallible `new(...)` signature is an intentional pre-1.0 source change that
removes the previous unbounded compatibility path.

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

Portable client artifact handling trims `channel_id`, rejects empty values and values longer than 256 UTF-8 bytes, and then uses that one normalized value for attach and handshake. Resolved direct endpoints receive a structurally validated but unauthenticated identifier from the peer's INIT frame, so they reject non-canonical leading or trailing whitespace before invoking the credential resolver. The resolver must treat every INIT field as untrusted until the peer completes PSK authentication. These checks run before transport-policy callbacks, scope resolvers, attach-token transmission, or other network activity where the applicable input is already available.

Resolved direct INIT validation uses the same stable tuples in all four SDKs before the resolver runs: an empty `channel_id` is `direct/validate/missing_channel_id`; leading or trailing whitespace and identifiers longer than 256 UTF-8 bytes are `direct/validate/invalid_input`; unsupported protocol versions, roles, or cipher suites are `direct/handshake/handshake_failed`. These structural checks protect the resolver boundary but do not authenticate the peer. When one INIT contains multiple invalid fields, which validation error is reported first is not a portable contract.

Credential resolvers must be non-consuming. `commitAuthenticated` runs only after PSK authentication and before Yamux, and the backing credential-store transaction must be idempotent, cancellation-safe, and bounded by its own deadline. The SDK handshake deadline bounds connection establishment and the caller-visible result, but it cannot roll back an external side effect that a callback already started. A callback may therefore finish after the SDK has returned timeout or cancellation; that late completion must never authorize or create the failed Flowersec connection. At worst, a correctly isolated credential transaction may consume a credential whose connection has already failed. Swift custom `FlowersecBinaryTransport` implementations must make `close()` idempotent and cancellation-cooperative because timeout and cancellation initiate cleanup without waiting indefinitely for custom transport code.

Tunnel attach cancellation has an explicit submission boundary. SDKs must reject observable cancellation before transport policy, connection start, and attach submission, and must close the transport immediately when cancellation is observed during a pending attach. Once an attach frame has been handed to the system WebSocket send operation, cancellation cannot retract it or prove that the peer did not receive the one-time token. The call still returns cancellation and closes the transport, but callers must not assume that the artifact remains reusable after that boundary.

Portable configuration must use a positive handshake timeout. Existing language-specific zero-value behavior remains unchanged in this release to avoid an unrelated API break: Go and TypeScript treat zero as disabling the timeout, Swift rejects zero as `invalid_option`, and Rust treats zero as an immediately elapsed timeout. Cross-language configuration generators must not emit zero; disabling deadlines is not a portable behavior.

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
