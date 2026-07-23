# Flowersec API Contract

This document records the current public Flowersec integration contract.

Canonical source of truth: `stability/api_contract_manifest.json`

See also:

- Error model: `docs/ERROR_MODEL.md`
- API change policy: `docs/API_CHANGE_POLICY.md`
- Flowersec 0.27 migration: `docs/MIGRATION_0.27.md`
- Transport v2 breaking migration: `docs/MIGRATION_TRANSPORT_V2.md`
- Transport v2 architecture and exact runtime matrix: `docs/TRANSPORT_V2_ARCHITECTURE.md`

## CLI surface

Supported user-facing binaries:

- `flowersec-tunnel`
- `flowersec-proxy-gateway`
- `flowersec-issuer-keygen`
- `flowersec-channelinit`
- `flowersec-directinit`
- `idlgen`

Internal tooling under `flowersec-go/internal/cmd/*` is not part of the public CLI contract.

`flowersec-tunnel` is a Transport v1 WebSocket CLI in this release. Go Transport v2 WebSocket, raw QUIC, WebTransport, session, endpoint-set, and tunnel coordination are public library packages; the CLI does not silently enable v2 listeners or UDP/HTTP3 exposure.

## Go packages

Recommended integration entrypoints:

- `github.com/floegence/flowersec/flowersec-go/v2/client`
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
- `github.com/floegence/flowersec/flowersec-go/v2/endpoint`
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
- `github.com/floegence/flowersec/flowersec-go/v2/stream`
  - `stream.Stream`
  - `stream.Stream.Reset()`
- `github.com/floegence/flowersec/flowersec-go/v2/transportsecurity`
  - `transportsecurity.Policy`
  - `transportsecurity.Input`
  - `transportsecurity.RequireTLS(...)`
  - `transportsecurity.AllowPlaintextForLoopback(...)`
  - `transportsecurity.NewNetworkPlaintextPolicy(...)`
  - `transportsecurity.NetworkPlaintextPolicyOptions`
  - `transportsecurity.PlaintextRiskAcceptance`
  - `transportsecurity.PlaintextRiskAcceptPreE2ECredentialExposure`
- `github.com/floegence/flowersec/flowersec-go/v2/endpoint/serve`
  - `serve.New(...)`
  - `srv.Handle(...)`
  - `srv.HandleStream(...)`
  - `srv.ServeSession(...)`
  - `serve.ServeTunnel(...)`
  - `serve.NewDirectHandler(...)`
  - `serve.NewDirectHandlerResolved(...)`
- `github.com/floegence/flowersec/flowersec-go/v2/protocolio`
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
- `github.com/floegence/flowersec/flowersec-go/v2/controlplane/client`
  - `client.RequestConnectArtifact(...)`
  - `client.RequestEntryConnectArtifact(...)`
  - `client.ConnectArtifactRequestConfig.AllowLoopbackHTTP`
  - `client.RequestError`
- `github.com/floegence/flowersec/flowersec-go/v2/controlplane/http`
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
- `github.com/floegence/flowersec/flowersec-go/v2/observability`
  - `observability.DiagnosticEvent`
  - `observability.ClientObserver`
  - `observability.NormalizeClientObserver(...)`
  - `observability.WithClientObserverContext(...)`
- `github.com/floegence/flowersec/flowersec-go/v2/origin`
  - `origin.FromWSURL(...)`
  - `origin.ForTunnel(...)`
- `github.com/floegence/flowersec/flowersec-go/v2/proxy`
  - `proxy.Register(...)`
  - `proxy.NewClient(...)`
  - `proxy.Options`
  - `proxy.DefaultMaxConcurrentStreams`
  - `proxy.ClientHTTPRequest`
  - `proxy.ClientHTTPResponse`
  - `proxy.ClientWebSocket`
- `github.com/floegence/flowersec/flowersec-go/v2/reconnect`
  - `reconnect.NewManager(...)`
  - `reconnect.OnceSource(...)`
  - `reconnect.RefreshableSource(...)`
  - `reconnect.ControlplaneSource(...)`
  - `reconnect.Config`
  - `reconnect.Settings`
  - `(*reconnect.Manager).Disconnect()`
- `github.com/floegence/flowersec/flowersec-go/v2/proxy/preset`
  - `preset.Manifest`
  - `preset.DecodeJSON(...)`
  - `preset.LoadFile(...)`
  - `preset.ApplyBridgeOptions(...)`
- `github.com/floegence/flowersec/flowersec-go/v2/rpc`
  - `rpc.NewRouter(...)`
  - `rpc.NewServer(...)`
  - `rpc.NewServerWithOptions(...)`
  - `rpc.ServerOptions`
  - `rpc.NewClient(...)`
- `github.com/floegence/flowersec/flowersec-go/v2/framing/jsonframe`
  - `jsonframe.ReadJSONFrame(...)`
  - `jsonframe.WriteJSONFrame(...)`
  - `jsonframe.ReadJSONFrameDefaultMax(...)`
- `github.com/floegence/flowersec/flowersec-go/v2/fserrors`
  - shared machine-readable `{path, stage, code}` types
  - `fserrors.Error` and `fserrors.CandidateDiagnostic`
  - `fserrors.Error.Diagnostics`
  - `fserrors.CodeResourceExhausted`
- `github.com/floegence/flowersec/flowersec-go/v2/controlplane/issuer`
  - `issuer.Keyset`
  - `issuer.New(...)`
  - `issuer.NewRandom(...)`
  - `issuer.Keyset.AddVerificationKey(...)`
  - `issuer.Keyset.Rotate(...)`
  - `issuer.Keyset.RetireVerificationKey(...)`
- `github.com/floegence/flowersec/flowersec-go/v2/controlplane/channelinit`
- `github.com/floegence/flowersec/flowersec-go/v2/controlplane/token`
- `github.com/floegence/flowersec/flowersec-go/v2/tunnel/server`
  - `server.Config`
    - `MaxTenantQueuedBytes`
    - `MaxTotalQueuedBytes`
    - `MaxTokenLifetime`
    - `MaxInitHorizon`
    - `MaxReplayEntries`
  - `server.ReplayCache`
  - `server.TokenUseCache`
  - `server.NewTokenUseCache(...)`
  - `server.HTTPAuthorizerConfig.MaxResponseBytes`
- `github.com/floegence/flowersec/flowersec-go/v2/mux/yamux`
  - `yamux.Session.OpenStreamContext(...)`

Transport v2 is a separate breaking contract built around `CarrierSession`:

- `admissionv2` and `artifactv2` own bounded FSB2/FSA2 admission, canonical
  artifacts, candidate binding, the session contract hash, and one-shot
  credential semantics.
- `github.com/floegence/flowersec/flowersec-go/v2/endpointsetv2` exposes the
  business-neutral custom tunnel registry contract: `endpointsetv2.EndpointSet`,
  `endpointsetv2.ListenerTuple`, `endpointsetv2.CertificateReadiness`,
  `endpointsetv2.AudienceReadiness`, and `endpointsetv2.Freshness`.
  `endpointsetv2.Validate(...)`, `endpointsetv2.CompatibleListeners(...)`,
  `endpointsetv2.MarshalJSON(...)`, and
  `endpointsetv2.DecodeJSON(...)` reject stale, unready, unknown, duplicate,
  unsorted, non-canonical, and cross-path registrations. The frozen constants
  include `endpointsetv2.Profile`, `endpointsetv2.TunnelWireProfile`, and
  `endpointsetv2.MaxFreshnessAgeSeconds`; validation failures wrap
  `endpointsetv2.ErrInvalidEndpointSet`; an empty requester intersection
  returns `endpointsetv2.ErrNoCompatibleListener`. Raw QUIC and WebTransport listen
  tuples use UDP bind endpoints, while WebSocket listen tuples use TCP. A listen
  tuple's `SessionRole` is the accepted dialing peer's Flowersec session role,
  not the listener's transport acceptor role; listeners accepting both tunnel
  roles publish one canonical tuple for each role.
- `carrier`, `carrier/websocket`, `carrier/rawquic`, and
  `carrier/webtransport` expose one carrier-neutral session and stream shape.
  WebSocket uses hop-local Yamux. Raw QUIC and WebTransport map every Flowersec
  logical stream to one native bidirectional stream and never construct Yamux.
  `CarrierSession.Path()` is the immutable negotiated routing profile: exact
  WebSocket subprotocol, raw QUIC ALPN, or WebTransport CONNECT path determines
  `direct` versus `tunnel`; callers cannot relabel a live carrier session.
  The Go v2 WebSocket surface accepts Flowersec-owned `ResourcePolicy` and
  `LivenessPolicy` values; no v2 signature exposes a concrete Yamux type.
- `connectv2` races compatible WebSocket, raw QUIC, and WebTransport candidates
  without registry-order preference, closes all losers before durable spend,
  commits FSB2 only on the winner, and returns `session.SessionV2` after the
  authenticated READY boundary. It enforces `init_expire_at_unix_s` before
  starting the race, before durable spend, and again after spend; expiry before
  spend writes neither durable spend nor FSB2, while expiry observed after a
  successful spend keeps the artifact spent but still writes no FSB2.
- Every high-level v2 connection result uses the shared error contract: Go
  returns `*fserrors.Error`; TypeScript returns `FlowersecError`. Their primary
  public fields are `path`, `stage`, and `code`, and every pair belongs to
  `stability/connect_error_code_registry.json`. The Go error's
  `Diagnostics` and TypeScript's `FlowersecCandidateDiagnostic` preserve
  bounded per-candidate `{candidateId, carrier, stage, code}` observations for
  logs and debugging. Go diagnostics retain the underlying error; TypeScript
  diagnostics expose a bounded message while the top-level `FlowersecError`
  retains its cause. Applications must branch on the stable fields, not error
  text, carrier ordering, or a concrete transport exception. `reconnect` is an
  allowed cross-language error-registry stage for reconnect lifecycle failures;
  it does not require a connector to relabel its validate, connect, attach,
  handshake, or close failure as `reconnect`.
- `connectv2.Factory.NewAttempt(...)` and `connectv2.CarrierDial` receive the
  artifact `SessionContract`. Implementations must bind
  `max_inbound_streams` to exactly `N + 2` physical bidirectional streams: one
  lifetime control stream, one persistent reserved RPC stream, and `N` logical
  data streams. This is Yamux `MaxInboundStreams` for WebSocket and native QUIC
  `MaxIncomingStreams` for raw QUIC. WebTransport exposes the same `N + 2`
  carrier capacity but its HTTP/3 server config reserves the CONNECT stream and
  therefore sets the underlying QUIC `MaxIncomingStreams` to `N + 3`. Carrier
  sessions report `N + 2` through `MaxIncomingStreams()` in Go,
  `inboundBidirectionalStreamCapacity` in TypeScript and Swift, and
  `inbound_bidirectional_stream_capacity()` in Rust. SessionV2 rejects a
  mismatch before opening the lifetime control stream or writing FSC2/FSH2.
- `protocolv2` owns exact FSC2, FSH2, FSS2, FSR2, OPEN metadata, key schedule,
  rekey, counter, ledger, and control-record primitives.
- `session.SessionV2` owns carrier-independent RPC, logical stream open and
  accept, FIN/reset, liveness, GOAWAY, and rekey behavior. Go exposes
  `Termination()` and `WaitClosed(ctx)` so downstream reconnect code can
  observe the authoritative terminal cause without polling transport state.
  `CapabilityDescriptor`, `EncodeCapabilityDescriptor(...)`,
  `DecodeCapabilityDescriptor(...)`, and `CapabilityDescriptorDigest(...)`
  implement the shared flat capability codec and vectors.
- The Go v2 root package `github.com/floegence/flowersec/flowersec-go/v2`
  exposes the carrier-neutral artifact and session boundary:
  `flowersec.Artifact`, `flowersec.ArtifactLease`,
  `flowersec.ParseArtifact(...)`, `flowersec.NewArtifactLease(...)`, and
  `flowersec.ErrInvalidArtifact`. The handle and lease serialize as empty JSON
  objects and do not expose candidates, routes, credentials, or session wire
  fields. `flowersec.NewConnector(...)` constructs a `flowersec.Connector`
  from carrier-neutral `flowersec.ConnectorOptions`,
  `flowersec.AdmissionReason`, and `flowersec.AdmissionReasonRegistry`.
  `flowersec.Connector.Connect(...)` returns only `flowersec.Session`, whose
  application contracts are `flowersec.Path`, `flowersec.PathDirect`,
  `flowersec.PathTunnel`, `flowersec.Metadata`, `flowersec.ByteStream`,
  `flowersec.IncomingStream`, and `flowersec.RPCPeer`. Failures project to
  `flowersec.ConnectError`; `flowersec.ConnectError.Error()` and
  `flowersec.ConnectError.Unwrap()` expose only stable path/stage/code and the
  `flowersec.ErrConnectionFailed` sentinel. Invalid construction returns
  `flowersec.ErrInvalidConnectorOptions`.
- The TypeScript root, browser, and Node entries expose `ArtifactV2`,
  `decodeArtifactV2JSON(...)`, `encodeArtifactV2JSON(...)`,
  `validateArtifactV2(...)`, `ArtifactLeaseV2`, `ArtifactSourceV2`,
  `createArtifactLeaseV2(...)`, `createArtifactV2Resolver(...)`, and
  `createSessionReconnectManagerV2(...)`. `ArtifactAcquireContextV2` contains
  `ArtifactVersionPolicyV2`, `RuntimeCapabilityDescriptorV2`, and the verified
  canonical digest produced by `runtimeCapabilityDigestV2(...)`;
  `createArtifactAcquireContextV2(...)` constructs it. TypeScript sessions expose
  `termination` and `waitClosed()`; automatic reconnect accepts only a
  refreshable artifact source and reacquires a new lease for every attempt.
  Durable spend remains a downstream callback and no product acquisition
  policy is embedded in Flowersec.
- TypeScript exports the Flowersec-owned `CarrierSessionV2`, `CarrierStreamV2`,
  `NativeCarrierSessionV2`, `NativeCarrierStreamV2`,
  `WebSocketBinaryTransportV2`, and `WebSocketResourcePolicyV2` contracts from
  the applicable root and runtime entries. Its v2 signatures never expose
  `YamuxSession`, `YamuxStream`, or `YamuxLimits`.
- TypeScript `SessionConfigV2.idleTimeoutMs` starts an authenticated-activity
  watchdog only after READY. `SessionConfigV2.closeTimeoutMs` bounds graceful
  GOAWAY, SESSION_CLOSE, and carrier shutdown even when the carrier close
  promise stalls.
- `tunnelv2` pairs authenticated endpoint legs and bridges opaque per-stream
  ciphertext across WebSocket, raw QUIC, WebTransport, and mixed topologies.

Transport v2 does not define a primary carrier or an implicit fallback policy.
Explicit caller policy may require WebSocket or the QUIC family, but adaptive
selection treats all issued and runtime-supported candidates equally.

The Swift package exposes the carrier-neutral `TransportV2Session`, configured
by `TransportV2SessionConfig` and driven through an injected
`TransportV2CarrierSession`. `ConnectorV2`, constructed with
`ConnectorOptionsV2`, consumes an opaque artifact lease and returns only the
carrier-neutral session; `ConnectorV2.connect()` reports redacted
`ConnectErrorV2` values. `RuntimeCapabilitiesV2.macOS` advertises the verified
WebSocket dial tuples, while `RuntimeCapabilitiesV2.apple` remains conservative
and advertises no carrier tuples until physical iOS evidence exists.
`IDNAHostV2.lookupASCII(_:)` provides the frozen portable IDNA profile.
`RuntimeCapabilityDescriptorV2.canonicalJSON()`,
`RuntimeCapabilityDescriptorV2.decodeCanonicalJSON(_:)`, and
`RuntimeCapabilityDescriptorV2.digest()` implement the shared codec.
Every Swift carrier implementation must report
`inboundBidirectionalStreamCapacity`; establishment requires exactly
`TransportV2SessionConfig.maxInboundStreams + 2` before opening or accepting
the lifetime control stream.

The signed `TransportV2SessionConfig.idleTimeoutSeconds` value starts an
authenticated-activity watchdog after READY; zero disables that watchdog.
`TransportV2Session.acceptStream()` responds to caller cancellation without
canceling or consuming another accept waiter. `TransportV2Session.close()`
enters the closing state before flushing GOAWAY and SESSION_CLOSE, rejects new
open and accept operations immediately, and bounds the control flush before
the authoritative carrier shutdown.
`TransportV2Session.waitClosed()` returns the stable terminal cause and is safe
to await repeatedly.

Generated protocol packages:

- `github.com/floegence/flowersec/flowersec-go/v2/gen/flowersec/controlplane/v1`
- `github.com/floegence/flowersec/flowersec-go/v2/gen/flowersec/direct/v1`
- `github.com/floegence/flowersec/flowersec-go/v2/gen/flowersec/tunnel/v1`
- `github.com/floegence/flowersec/flowersec-go/v2/gen/flowersec/rpc/v1`
- `github.com/floegence/flowersec/flowersec-go/v2/gen/flowersec/e2ee/v1`

Go connection contract:

- `client.Connect(...)` accepts only `*protocolio.ConnectArtifact`
- callers that already have a raw tunnel grant or direct connection info use the explicit `client.ConnectTunnel(...)` or `client.ConnectDirect(...)` entrypoint
- `client.Connect(...)` does not decode JSON, inspect wrappers, or infer a transport from raw fields
- `controlplane/client` stays the recommended Go client-side artifact fetch entry; `controlplane/http` is the recommended server-side helper-first reference layer
- preset manifests are accepted only through manifest files or decoded manifest objects; named profile helpers and gateway `proxy.profile` have been removed

Tunnel token verification is bounded even after a signature and `(audience, issuer)` scope match. `server.Config.MaxTokenLifetime` limits `exp - iat`, `MaxInitHorizon` limits how far `init_exp` may extend beyond current time plus clock skew, and `MaxReplayEntries` bounds the built-in replay cache. `server.NewTokenUseCache(maxEntries)` requires a positive capacity; when full, it removes expired entries and otherwise rejects new replay keys without evicting valid entries.

Multi-tenant tunnel isolation is keyed only by `(audience, issuer)`. Tenant IDs are optional operator metadata, must be unique when non-empty, and never merge queue accounting or channel state. Runtime observe decisions require `audience`, `issuer`, and `channel_id`; duplicate decisions, missing scope, or tenant ID mismatch invalidates the complete response batch. Replay keys are recorded atomically after an external attach authorizer allows the request and before endpoint insertion, so denied authorization does not consume the token and concurrent reuse admits at most one endpoint.

## TypeScript exports

Package entrypoints:

- `@floegence/flowersec-core`
  - opaque Transport v2 acquisition: `Artifact`, `parseArtifact(...)`,
    `ArtifactLeaseV2`, `ArtifactSourceV2`, `createArtifactLeaseV2(...)`, and
    `createArtifactV2Resolver(...)`
  - carrier-neutral Transport v2 session contracts: `SessionV2`,
    `ByteStreamV2`, `IncomingStreamV2`, and reconnect manager types
  - runtime capability descriptors and strict codecs
  - `RequireTLS`
  - `AllowPlaintextForLoopback`
  - `createNetworkPlaintextPolicy(...)`
  - `NetworkPlaintextPolicyOptions`
  - `PlaintextRiskAcceptance`
  - `TransportSecurityPolicy`
- `@floegence/flowersec-core/node`
  - `connectNodeSessionV2(...)` and `NodeSessionConnectorV2Options`
  - opaque acquisition and carrier-neutral session contracts
  - `RequireTLS`
  - `AllowPlaintextForLoopback`
  - `createNetworkPlaintextPolicy(...)`
  - `NetworkPlaintextPolicyOptions`
  - `PlaintextRiskAcceptance`
  - `NODE_RUNTIME_CAPABILITY_V2`
  - Node advertises WebSocket dial tuples for direct clients and both tunnel
    roles; raw QUIC and WebTransport remain typed unavailable
- `@floegence/flowersec-core/browser`
  - `connectBrowserSessionV2(...)` and `BrowserSessionConnectorV2Options`
  - opaque acquisition and carrier-neutral session contracts
  - `RequireTLS`
  - `AllowPlaintextForLoopback`
  - `createNetworkPlaintextPolicy(...)`
  - `NetworkPlaintextPolicyOptions`
  - `PlaintextRiskAcceptance`
  - `BROWSER_RUNTIME_CAPABILITY_V2`
  - `detectBrowserRuntimeCapabilityV2(...)` and `BrowserRuntimeFeaturesV2` for
    removing WebSocket or WebTransport tuples when the actual browser API is
    unavailable
  - carrier construction, selected candidates, raw artifacts, wire contracts,
    and Yamux remain package-internal
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

TypeScript connection contract notes:

- `connect(...)`, `connectBrowser(...)`, and `connectNode(...)` accept only `ConnectArtifact`
- callers that already have a raw tunnel grant or direct connection info use the explicit tunnel or direct entrypoint for their runtime
- automatic connection entrypoints do not parse serialized JSON, inspect wrappers, or infer a transport from raw fields
- browser control-plane code requests artifacts through `requestConnectArtifact(...)` or `requestEntryConnectArtifact(...)`; the browser entrypoint re-exports those functions and their input types directly from the control-plane implementation
- `@floegence/flowersec-core/controlplane` remains the canonical control-plane subpath and the sole owner of `ControlplaneRequestError`, token helpers, and server-side control-plane primitives
- proxy browser bootstrap is artifact-first through `connectArtifactProxyBrowser(...)` and `connectArtifactProxyControllerBrowser(...)`
- controller/app Window bridges use the `stream_bidirectional_ack_v2` contract and require both sides to run the same Flowersec minor version; mixed versions fail during bridge open and do not fall back to the earlier unbounded one-direction acknowledgement behavior
- named proxy profiles have been removed; use preset manifests instead

## SwiftPM module

The SwiftPM product and module are both `Flowersec` (`import Flowersec`). The maintained public surface is Transport v2-only:

- Opaque artifacts: `parseArtifactV2(...)`, `ArtifactV2`, and `ArtifactLeaseV2`
- Connection: `ConnectorV2`, `ConnectorOptionsV2`, and redacted `ConnectErrorV2`
- Carrier-neutral sessions: `SessionV2`, `RPCPeerV2`, `ByteStreamV2`, and `IncomingStreamV2`
- Portable stream metadata: `StreamMetadataV2` and `JSONValueV2`
- Capability negotiation: `RuntimeCapabilitiesV2` and its descriptor/tuple value types
- Host normalization: `IDNAHostV2`

Carrier candidates, credentials, wire frames, cryptographic material, Yamux, raw artifacts, spend ledgers, and concrete transport adapters are SDK-internal. On macOS, `ConnectorV2` supports direct and tunnel WSS dialing with TLS 1.3 and exact subprotocol validation. The cross-Apple descriptor does not advertise macOS evidence as iOS capability.

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

Transport v2 modules and entrypoints:

- `flowersec::transport_v2`
- `flowersec::protocol_v2`
- `flowersec::raw_quic_v2`
- `flowersec::session_v2`
- `flowersec::idna_v2`
- `SessionV2::wait_closed()`
- `native_rust_capability_descriptor_v2()`
- `encode_runtime_capability_descriptor_v2(...)`
- `decode_runtime_capability_descriptor_v2(...)`
- `runtime_capability_digest_v2(...)`
- `runtime_capability_digest_hex_v2(...)`

The native Rust runtime advertises raw QUIC client dialing for direct and tunnel
paths. The public `Connector`, configured with `ConnectorOptions`, consumes an
opaque `artifact_v2::ArtifactLease`, races compatible candidates, commits the
durable spend before writing FSB2, and returns a carrier-neutral `Session`.
The Quinn adapter maps directional close, FIN, `RESET_STREAM`, and
`STOP_SENDING` directly without inserting Yamux. Raw QUIC server/listen roles,
WebSocket, and WebTransport remain unavailable.

`flowersec::session_v2::EncryptedSessionV2` implements the transport-neutral
`flowersec::transport_v2::SessionV2` contract. `SessionV2::wait_closed()` waits
for terminal session shutdown and preserves the first terminal cause. Runtime
capabilities use the shared flat canonical JSON codec: callers obtain the local
descriptor with `native_rust_capability_descriptor_v2()`, encode or decode it
with the codec functions above, and bind it with the SHA-256 digest helpers.

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

Credential resolvers must be non-consuming. `commitAuthenticated` runs only after PSK authentication and before Yamux, and the backing credential-store transaction must be idempotent, cancellation-safe, and bounded by its own deadline. The SDK handshake deadline bounds connection establishment and the caller-visible result, but it cannot roll back an external side effect that a callback already started. A callback may therefore finish after the SDK has returned timeout or cancellation; that late completion must never authorize or create the failed Flowersec connection. At worst, a correctly isolated credential transaction may consume a credential whose connection has already failed. Swift carrier transports are SDK-internal and cleanup remains cancellation-cooperative and idempotent.

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
