# Flowersec v3 Public API Contract

Flowersec exposes opaque artifacts, carrier-neutral one-shot connection functions, sessions, RPC, byte streams, and an optional `ConnectionController` for long-lived connections. Applications cannot inspect candidates, selected carriers, Yamux, QUIC handles, wire frames, credentials, keys, endpoint identities, logical stream IDs, or spend ledgers.

The source tree defines the Flowersec 3.0.0 contract. v3 is strict and
fail-closed: artifacts, candidates, TLS policy, FSB3/FSA3, and the v3 frame
family are versioned. Production artifacts use WSS, QUIC, or HTTPS carriers;
there is no version negotiation, v2 fallback, or CA/pin downgrade. TLS policy
is part of candidate identity, canonicalization, candidate-set hashing, and
admission binding.

Across all four SDKs, an omitted public connection timeout uses the shared ten-second default from `stability/sdk_defaults.json`. The portable core is artifact/lease lifecycle, one-shot connection, authenticated sessions and reliable streams with construction-validated metadata, outbound RPC call/notify, redacted connection/session errors, and the optional single-owner `ConnectionController`. SDK profiles add runtime and carrier capabilities; language conveniences improve syntax and typing without changing wire semantics.

The v3 runtime registry has 17 portable capability declarations and explicit
unsupported reasons. Interoperability is measured separately by the v3 vector
sets for artifact, candidate, TLS policy, FSB3/FSA3, capability, and Controller
state. These counts describe distinct contracts and are derived from the
machine-readable registry.

| Capability layer | Contract | Go | TypeScript | Swift | Rust |
| --- | --- | :---: | :---: | :---: | :---: |
| `portable_core` | Artifact/lease, one-shot connect, session, reliable streams with validated metadata, RPC call/notify, redacted errors, optional connection controller | Yes | Yes | Yes | Yes |
| `sdk_profile` | Carrier/profile capabilities, unreliable messages, or runtime-owned acceptance | WSS, raw QUIC, WebTransport, direct Acceptor, opaque TunnelRuntime | Browser WSS/WebTransport; Node WSS/raw QUIC, direct Acceptor, opaque TunnelRuntime | Apple WSS client | WSS, raw QUIC, direct Acceptor, opaque TunnelRuntime |
| `language_convenience` | Language-native additions | Inbound handlers | Generic RPC results and subscriptions | `Codable` RPC | `RpcPeerExt::call_typed` |

Portable core, accepted-session lifecycle, control-plane issuance/authorization, connection control, RPC/stream lifecycle, and published consumer workflows require same-semantic public entries in every applicable SDK. An unsupported tuple records a stable reason and no executable test ID; supported tuples name their production entrypoint and focused test ID. The protocol carrier set is not a promise that every SDK exposes every carrier; each listener and connector profile declares only exact production-backed tuples.

The named deployment profiles are `native-server-core` for Go, Rust, and
Node.js; `browser-client` for TypeScript browser clients; `apple-client` for
Swift clients on Apple platforms; and `webtransport-server`, claimed by Go.
The native server profile records WebSocket and raw
QUIC endpoint-client, direct-server, and opaque-tunnel runtime capabilities in
all three languages. Its 18 tuples are aggregate capabilities, six per native
runtime, rather than pairwise interoperability results. Go's H4 profile binds
its WebTransport direct server and tunnel runtime, including encrypted
DATAGRAM forwarding, to production-adapter tests. Profiles select carrier adapters; they never select a different
Flowersec application wire. The separate interoperability matrix declares 18
direct and 18 tunnel coordinates; every current cell is explicitly unsupported
until one release-gating v3 test exercises its complete executable case set.

Trust-root sourcing is policy-specific. CA candidates use platform roots or
deployment-provided private roots. Pin candidates use only the complete leaf
DER SHA-256 pin set and never fall back to CA. Browser WebTransport passes only
active pins through the production `serverCertificateHashes` API; Browser
WebSocket is CA-only. Native adapters enforce the v3 TLS profile and declare
unsupported tuples when they cannot do so. None of these choices changes the
shared ten-second default connection timeout.

Every production CA-mode TLS connector validates both the certificate chain and the requested target identity; an untrusted root or hostname/IP mismatch fails closed. Pin mode instead uses only the complete leaf DER hashes authorized by the artifact, while still enforcing the certificate profile and the TLS private-key proof; it never adds or falls back to CA chain or hostname authorization. Test-only roots are supplied explicitly by acceptance fixtures or the browser test runner. No production connector has an insecure verification fallback.

The public contract is split into four layers. The portable core is the shared artifact, lease, one-shot connector, session, RPC, and stream model implemented by every SDK. An optional `ConnectionController` is the sole Flowersec long-lived connection owner above a refreshable artifact source. Each SDK profile records runtime-owned carrier support, listener support, and platform trust constraints. A language convenience is an ecosystem-specific API shape layered on top of the portable core, not a promise that every SDK exposes the same syntax. Retry decisions are structured as `terminal`, `retryable`, or an absolute `retry_after` deadline; raw public error code taxonomies remain SDK-local.

## Go

The only supported application import is `github.com/floegence/flowersec/flowersec-go/v3`, conventionally named `flowersec`. The package's default artifact and connector surface is v3; v2 symbols, where retained for source migration, are explicitly versioned and never accepted by v3 APIs.

- Artifact lifecycle: `flowersec.Artifact`, `flowersec.ArtifactLease`, `flowersec.ParseArtifact(...)`, `flowersec.NewArtifactLease(...)`, `flowersec.NewArtifactLeaseWithRetirement(...)`, and `flowersec.ErrInvalidArtifact`. The retirement-aware constructor gives an artifact source an explicit cleanup boundary when cancellation wins before spend.
- Connection: `flowersec.ConnectorOptions`, `flowersec.Connect(...)`, `flowersec.ConnectError`, and `flowersec.ConnectErrorCode`. Optional `ConnectorOptions.RPCHandlers` freezes a reusable `flowersec.RPCHandlers` request/notification definition before session establishment; each one-shot connection and Controller generation creates a fresh RPC router from that definition. Invalid artifacts and options are returned as redacted `flowersec.ConnectError` values. `ConnectorOptions.Origin` may be omitted for artifacts that use non-WebTransport carriers; a non-empty value must be an absolute HTTP(S) origin.
- Session values: `flowersec.Session`, `flowersec.SessionTermination`, `flowersec.StreamMetadata`, `flowersec.NewStreamMetadata(...)`, `flowersec.EmptyStreamMetadata()`, `flowersec.StreamMetadata.Values()`, `flowersec.ErrInvalidMetadata`, `flowersec.ByteStream`, `flowersec.IncomingStream`, and `flowersec.RPCPeer`. `SessionTermination.Error` is a required `flowersec.SessionError` value; cancellation of the wait is returned separately.
- Streams: `flowersec.ByteStream.Read(...)`, `flowersec.ByteStream.Write(...)`, `flowersec.ByteStream.Close()`, `flowersec.ByteStream.Kind()`, `flowersec.ByteStream.TerminalError()`, `flowersec.ByteStream.CloseWrite()`, and `flowersec.ByteStream.Reset()`. `CloseWrite` is the only graceful stream FIN operation and preserves the receive direction. `Reset` aborts both directions, and `Close` is its cleanup-oriented alias. A failed write makes that stream terminal because its wire commit boundary is no longer reusable; unrelated streams remain live.
- RPC: `flowersec.RPCPeer.Call(...)`, `flowersec.RPCPeer.Notify(...)`, `flowersec.RPCPeer.OnNotify(...)`, and sanitized application `flowersec.RPCError` values.
- Inbound serving: endpoint clients use `flowersec.RPCHandlers` from `flowersec.NewRPCHandlers()`, with `flowersec.RPCHandler` registrations through `flowersec.RPCHandlers.HandleRPC(...)` and `flowersec.RPCNotificationHandler` registrations through `flowersec.RPCHandlers.HandleNotification(...)`; it has no stream or serve API. Any established Session can use carrier-neutral `flowersec.StreamHandlers` from `flowersec.NewStreamHandlers(...)`, with bounded `flowersec.StreamHandlerOptions`, immutable `flowersec.StreamHandler` registrations through `flowersec.StreamHandlers.HandleStream(...)`, and lifecycle ownership through `flowersec.StreamHandlers.Serve(...)`. Accepted server Sessions use `flowersec.SessionHandlers` from `flowersec.NewSessionHandlers(...)` with `flowersec.SessionHandlerOptions`; that accepted-session configuration composes the same stream dispatcher with request and notification registration. Application stream kinds contain 1 through 128 canonical UTF-8 bytes, have no leading or trailing Unicode whitespace or control or unassigned scalars, and exclude the package-owned `flowersec.rpc.v2` and `flowersec.rpc.v3` names. RPC and notification registrations share one nonzero uint32 namespace. Consumption freezes a reusable definition; later registrations return `flowersec.ErrHandlerRegistryFrozen`, while repeated snapshot reads remain valid. A successful handler closes its write direction; a handler error or failed write close resets and closes only that stream, and unrelated dispatch continues. Notification failures remain isolated. Unhandled or excess streams are reset and closed. Invalid or duplicate registrations return `flowersec.ErrInvalidHandlerRegistration` or `flowersec.ErrHandlerAlreadyExists`. `flowersec.StreamHandlerRegistrar` is sealed to Flowersec registries. Registry string, debug, and JSON representations reveal no registration state.
- The accepted-session compatibility surface also provides `flowersec.SessionHandlers.HandleStream(...)`, `flowersec.SessionHandlers.HandleRPC(...)`, `flowersec.SessionHandlers.HandleNotification(...)`, and `flowersec.SessionHandlers.Serve(...)`; `flowersec.RPCHandlers.String()`, `flowersec.RPCHandlers.GoString()`, `flowersec.RPCHandlers.MarshalJSON()`, `flowersec.StreamHandlers.String()`, `flowersec.StreamHandlers.GoString()`, `flowersec.StreamHandlers.MarshalJSON()`, `flowersec.SessionHandlers.String()`, `flowersec.SessionHandlers.GoString()`, and `flowersec.SessionHandlers.MarshalJSON()` are redacted and reveal no registration state.
- Server acceptance: `flowersec.AcceptorOptions`, `flowersec.Acceptor`, `flowersec.NewAcceptor(...)`, `flowersec.Acceptor.Handler()`, and `flowersec.Acceptor.Serve(...)` own direct application Sessions. `flowersec.DirectListener`, `flowersec.RawQUICListenerOptions`, `flowersec.WebTransportListenerOptions`, `flowersec.NewWebSocketDirectListener()`, `flowersec.NewRawQUICDirectListener(...)`, and `flowersec.NewWebTransportDirectListener(...)` are the direct-only listener surface. `AcceptorOptions.ResolveHandlers` freezes one `flowersec.SessionHandlers` registry before Session establishment. `flowersec.TunnelListener`, `flowersec.TunnelRuntimeOptions`, `flowersec.TunnelRuntime`, `flowersec.NewTunnelRuntime(...)`, `flowersec.TunnelRuntime.Handler()`, `flowersec.TunnelRuntime.Serve(...)`, `flowersec.NewWebSocketTunnelListener()`, `flowersec.NewRawQUICTunnelListener(...)`, and `flowersec.NewWebTransportTunnelListener(...)` form the supported opaque relay boundary. `flowersec.WebSocketHTTPServerOptions`, `flowersec.WebSocketHTTPServer`, and `flowersec.NewWebSocketHTTPServer(...)` are required for direct or tunnel WebSocket handlers; its `flowersec.WebSocketHTTPServer.Serve(...)`, `flowersec.WebSocketHTTPServer.ListenAndServe(...)`, `flowersec.WebSocketHTTPServer.Shutdown(...)`, and `flowersec.WebSocketHTTPServer.Close()` methods own lifecycle. The wrapper owns a private TLS clone, forces TLS 1.3 only, and disables session tickets before handshakes. Direct `Handler()` installation on a caller-owned `http.Server` fails closed. `flowersec.ErrInvalidAcceptor`, `flowersec.ErrInvalidTunnelRuntime`, and `flowersec.ErrInvalidWebSocketServer` are the construction failures. `flowersec.WebSocketDirectPath` and `flowersec.WebSocketTunnelPath` remain fixed wire paths.
- Server proxy application: `flowersec.ProxyServerOptions`, `flowersec.ProxyServer`, `flowersec.NewProxyServer(...)`, `flowersec.ProxyServer.Register(...)`, `flowersec.ProxyServer.RegisterStreamHandlers(...)`, `flowersec.ProxyServer.Close()`, and `flowersec.ErrInvalidProxyServer` provide the fixed-upstream HTTP and WebSocket counterpart to `@floegence/flowersec-core/proxy`. Registration is atomic on either the legacy accepted-session `SessionHandlers` entrypoint or the sealed carrier-neutral `StreamHandlerRegistrar`; upstream selection, proxy wire framing, header filtering, body/frame limits, cancellation, and reset cleanup remain Flowersec-owned. `ProxyServer.Close()` cancels active upstream work, waits for handler cleanup, and makes previously registered handlers reject future dispatch.
- Optional unreliable messages: `flowersec.Session.UnreliableMessages()` returns the carrier-neutral `flowersec.UnreliableMessageChannel`; `flowersec.UnreliableMessageChannel.MaxMessageBytes()`, `flowersec.UnreliableMessageChannel.Send(...)`, and `flowersec.UnreliableMessageChannel.Receive(...)` use `flowersec.UnreliableSendOptions` and `flowersec.UnreliableSendStatus` without exposing DATAGRAM or carrier objects. Accepted sends and dropped sends are public outcomes; unavailable, invalid, oversized, canceled, closed, or failed channels remain public operation errors.
- Session lifecycle: `flowersec.Session.RPC()`, `flowersec.Session.OpenStream(...)`, `flowersec.Session.AcceptStream(...)`, `flowersec.Session.Rekey(...)`, `flowersec.Session.ProbeLiveness(...)`, `flowersec.Session.WaitTermination(...)`, and `flowersec.Session.Close()`.
- Long-lived connection: `flowersec.NewConnectionController(...)`, `flowersec.ConnectionController`, `flowersec.ConnectionControllerOptions`, `flowersec.ArtifactSource`, `flowersec.ArtifactSourceError`, `flowersec.RetryDisposition`, `flowersec.ConnectionState`, `flowersec.ConnectionFailure`, and `flowersec.ConnectionSnapshot`. `Start` is idempotent, `RetryNow` returns whether the current wait was woken, `Snapshot` exposes only the established one-shot session and core lifecycle fields, and `Close` cancels all controller-owned work.
- Redacted failures: `flowersec.ConnectError.Error()`, `flowersec.ConnectError.Unwrap()`, `flowersec.ConnectError.Is(...)`, `flowersec.ConnectError.Code()`, `flowersec.ConnectErrorCode.String()`, `flowersec.SessionError`, `flowersec.SessionErrorCode`, `flowersec.SessionError.Error()`, `flowersec.SessionError.Unwrap()`, `flowersec.SessionError.Code()`, and `flowersec.RPCError.Error()`.
- Controller ownership: `flowersec.NewConnectionController(...)` accepts only a refreshable `ArtifactSource`, never a bare lease. `RetryNow` wakes the existing wait, `Close` cancels the single scheduler and current session, and a replacement session never inherits streams, RPCs, or writes.
- Opaque formatting and serialization: `flowersec.Artifact.String()`, `flowersec.Artifact.GoString()`, `flowersec.Artifact.MarshalJSON()`, `flowersec.ArtifactLease.String()`, `flowersec.ArtifactLease.GoString()`, and `flowersec.ArtifactLease.MarshalJSON()`.
- Connection outcomes: `flowersec.ConnectArtifactInvalid`, `flowersec.ConnectExpired`, `flowersec.ConnectTransportSecurityUnsupported`, `flowersec.ConnectTransportSecurityFailed`, `flowersec.ConnectConnectionFailed`, `flowersec.ErrInvalidConnectorOptions`, and `flowersec.ErrConnectionFailed`.
- Session outcomes: `flowersec.SessionCanceled`, `flowersec.SessionTimeout`, `flowersec.SessionClosed`, `flowersec.SessionGoingAway`, `flowersec.SessionResourceExhausted`, `flowersec.SessionStreamRejected`, `flowersec.SessionStreamReset`, `flowersec.SessionRekeyFailed`, `flowersec.SessionLivenessFailed`, `flowersec.SessionUnreliableUnavailable`, `flowersec.SessionUnreliableTooLarge`, `flowersec.SessionUnreliableDropped`, and `flowersec.SessionOperationFailed`.
- Unreliable send outcomes: `flowersec.UnreliableAccepted`, `flowersec.UnreliableDroppedExpired`, `flowersec.UnreliableDroppedBudget`, and `flowersec.UnreliableDroppedCarrier`.

Opaque values have fixed redacted string and JSON behavior. Zero-value or deserialized handles cannot establish a session or spend a lease.

### Go server-side control plane

The Go-only server import `github.com/floegence/flowersec/flowersec-go/v3/controlplane`, conventionally named `controlplane`, issues v3 artifacts and answers the `flowersec-runtime` authorization callback without exposing carrier, candidate, FSB3, PSK, or session-contract objects.

- Endpoint policy: `controlplane.EndpointSet` is created by `controlplane.NewEndpointSet(...)` from structured `controlplane.EndpointConfig` values containing a URL plus `controlplane.TLSPolicy`; URL schemes and TLS policy are converted to internal candidate fields only during issuance. `controlplane.CAPolicy()` selects CA verification, while `controlplane.PinPolicy(...)` accepts normalized `controlplane.CertificatePin` values. `controlplane.CertificatePin.String()`, `controlplane.CertificatePin.GoString()`, `controlplane.TLSPolicy.String()`, and `controlplane.TLSPolicy.GoString()` are redacted and never reveal pin bytes.
- Endpoint validation: invalid structured endpoints return `controlplane.ControlPlaneError` with a stable `controlplane.ControlPlaneErrorCode`. `controlplane.ControlPlaneError.Error()`, `controlplane.ControlPlaneError.Code()`, `controlplane.ControlPlaneError.FieldPath()`, and `controlplane.ControlPlaneError.Unwrap()` expose only the bounded failure and field boundary. Callers use `errors.As` to recover `controlplane.ControlPlaneError`; its `Unwrap()` returns only `controlplane.ErrInvalidControlPlaneInput`, which is matched with `errors.Is`. `controlplane.ErrIssuanceFailed` is an independent non-input failure and is never a `controlplane.ControlPlaneError`. The closed codes are `controlplane.InvalidEndpointCount`, `controlplane.InvalidEndpointID`, `controlplane.InvalidEndpointURL`, `controlplane.DuplicateEndpoint`, `controlplane.InvalidTLSPolicy`, and `controlplane.InvalidPin`. The complete public symbol/error inventory is `stability/api_contract_manifest.json`.
- Issuance: `controlplane.Issuer` from `controlplane.NewIssuer()` accepts carrier-neutral `controlplane.SessionOptions`, bounded `controlplane.Scope` and `controlplane.ArtifactMetadata`, plus either `controlplane.DirectIssueOptions` or `controlplane.TunnelIssueOptions`. `controlplane.Issuer.IssueDirect(...)` returns one `controlplane.IssuedArtifact`; `controlplane.Issuer.IssueTunnelPair(...)` returns one opaque `controlplane.IssuedTunnelPair`.
- Explicit delivery: `controlplane.IssuedArtifact.ArtifactJSON()` is the only client artifact serialization boundary. `controlplane.IssuedArtifact.LookupKey()` is a non-secret credential hash, and `controlplane.IssuedArtifact.AuthorizationRecord()` returns the matching opaque `controlplane.AuthorizationRecord`.
- Durable authorization: `controlplane.AuthorizationRecord.Encode()` and `controlplane.ParseAuthorizationRecord(...)` are the explicit secret-storage boundary. The caller must atomically reserve the one-time record before allowing a request; `controlplane.AuthorizationRecord.LookupKey()` never returns the bearer credential.
- Runtime callback: `controlplane.ParseRuntimeAuthorizationRequest(...)` returns a redacted `controlplane.RuntimeAuthorizationRequest`. Its `controlplane.RuntimeAuthorizationRequest.LookupKey()` locates the record; `controlplane.AuthorizeRuntime(...)` verifies a direct FSB3 and returns `controlplane.AuthorizationResponse`. `controlplane.AuthorizeTunnelRuntime(...)` verifies a tunnel FSB3 and returns the secret-free `controlplane.TunnelAuthorizationResponse`; an application authorizer that performs equivalent admission validation may use `controlplane.AllowTunnelRuntime(...)` to construct the same bounded allow response. Neither path exposes a Session contract or E2EE key to the relay. `controlplane.RejectRuntime(...)` creates only validated reject or retry decisions. `controlplane.AuthorizationResponse.JSON()` and `controlplane.TunnelAuthorizationResponse.JSON()` are the only response serialization boundaries.

### Go application acceptor

Applications that own direct server sessions use `flowersec.NewAcceptor(...)`. Its listeners are direct-only and its handler resolver and `OnSession` callback are never invoked by a relay. `flowersec.NewTunnelRuntime(...)` is the separate untrusted relay boundary: it accepts only tunnel listeners, authorizes pairing claims, and forwards opaque carrier streams through the built-in bounded bridge. It exposes no `Session`, `AcceptedSession`, RPC router, or handler registration.

The root Go proxy server is an application protocol owner. `flowersec.NewProxyServer(...)` validates a fixed upstream and
resource/header policy; `flowersec.ProxyServer.Register(...)` preserves the accepted-session `SessionHandlers` entrypoint,
while `flowersec.ProxyServer.RegisterStreamHandlers(...)` installs the same HTTP
and WebSocket handlers on a carrier-neutral `StreamHandlers`. The browser/Node
peer uses the published TypeScript `/proxy` entrypoint. Carrier objects, JSON
frames, proxy stream kinds, and WebSocket frames remain internal.
- Opaque formatting: `controlplane.EndpointSet.String()`, `controlplane.EndpointSet.GoString()`, `controlplane.IssuedArtifact.String()`, `controlplane.IssuedArtifact.GoString()`, `controlplane.IssuedArtifact.MarshalJSON()`, `controlplane.AuthorizationRecord.String()`, `controlplane.AuthorizationRecord.GoString()`, `controlplane.AuthorizationRecord.MarshalJSON()`, `controlplane.RuntimeAuthorizationRequest.String()`, `controlplane.RuntimeAuthorizationRequest.GoString()`, `controlplane.RuntimeAuthorizationRequest.MarshalJSON()`, `controlplane.AuthorizationResponse.String()`, `controlplane.AuthorizationResponse.GoString()`, `controlplane.AuthorizationResponse.MarshalJSON()`, `controlplane.TunnelAuthorizationResponse.String()`, `controlplane.TunnelAuthorizationResponse.GoString()`, and `controlplane.TunnelAuthorizationResponse.MarshalJSON()` reveal no credential-bearing content. `controlplane.AuthorizeTunnelRuntime(...)` and `controlplane.RejectTunnelRuntime(...)` return only the secret-free tunnel response.
- Invalid issuance, record, request, lease, expiry, or binding inputs return only `controlplane.ErrInvalidControlPlaneInput` at the public boundary. An unavailable cryptographic random source returns the stable redacted `controlplane.ErrIssuanceFailed` value.

This package owns transport-neutral issuance and authorization mechanics. Tenant selection, endpoint placement, permissions, billing, durable lease state, and upstream routing decisions remain application control-plane responsibilities.

## TypeScript

The supported package entrypoints are `@floegence/flowersec-core`, `@floegence/flowersec-core/browser`, `@floegence/flowersec-core/node`, and `@floegence/flowersec-core/proxy`.

The root exposes v3 application names: `Artifact`, `ArtifactError`,
`ArtifactErrorCode`, `ArtifactLease`, `ArtifactLeaseError`, `Session`,
`SessionTermination`, `RpcPeer`, `JsonValue`, `ByteStream`, `StreamMetadata`,
`createStreamMetadata(...)`, `StreamMetadataError`, `StreamHandlers`,
`StreamHandler`, `StreamHandlerOptions`, `HandlerRegistrationError`,
`ConnectionController`, `ArtifactSource`, `ConnectionSnapshot`,
`ConnectionControllerError`, `RetryDisposition`, typed `RpcResult<Response>`,
`ConnectError`, and `SessionError`. Default names bind only the v3 contract;
version-explicit v3 aliases and the explicit `v2` namespace are available
without negotiating or downgrading a v3 connection.

`StreamHandlers.handleStream(...)` freezes on the first `serve(...)`,
dispatches application streams on any established browser or Node Session,
bounds concurrency, resets unknown and excess streams, isolates handler
rejection, and closes the Session before waiting for active handlers during
shutdown. Application stream kinds follow the exact OPEN contract: 1 through
128 canonical UTF-8 bytes, no leading or trailing Unicode whitespace, control,
or unassigned scalars, and neither package-owned `flowersec.rpc.v2` nor
`flowersec.rpc.v3`. Immutable
controller snapshots publish `ConnectionSnapshot.retryDisposition` while the
corresponding retry decision applies and omit it before a new attempt, after
connection, and on close.

`parseArtifact(...)` projects all parser implementation failures to the closed
`ArtifactError` codes `artifact_too_large` or `invalid_artifact`.
`RpcPeer.call(...)` requires a successful-response decoder;
`RpcResult<Response>` is a discriminated union whose success payload has passed
application validation, while bounded remote application failures remain in
the `ok: false` branch. RPC calls and notifications accept only `JsonValue`
payloads and reject unsupported or non-finite values before wire I/O.
`RpcPeer.call(...)` and `RpcPeer.notify(...)` use the local outbound reserved
RPC stream. `RpcPeer.onNotify(typeId, decodePayload, handler)` subscribes to
peer outbound notifications delivered through the local inbound reserved RPC
stream and requires an explicit decoder; invalid payloads never reach the
business handler, decoder and handler failures remain isolated, and
unsubscribe is idempotent. Subscribers are independent from inbound request
handlers. `Session.waitTermination()` is the sole public termination waiting
entrypoint. A negotiated session may expose `UnreliableMessageChannel`, which
sends and receives defensively copied `Uint8Array` values; invalid operations
return `UnreliableMessageError`.

Browser and Node subpaths each expose `connect(...)` and
`createConnectionController(...)`; the module path identifies the runtime. The
Node subpath additionally exposes reusable `RPCHandlers`, direct-only
`createAcceptor(...)`, `Acceptor`, `AcceptedSession`, and accepted-server-only
`SessionHandlers`, plus opaque `createTunnelRuntime(...)` and `TunnelRuntime`.
`RuntimeAuthorizationRequest` is an opaque, non-enumerable callback value whose
`lookupKey()` returns only a SHA-256 credential digest. An
`AcceptorOptions.authorize(...)` success returns the opaque `Artifact` created
by `parseArtifact(...)`; neither the authorization nor handler-resolution
callback receives raw FSB3, credentials, URLs, candidates, PSK, or pin state.
Node tunnel authorization uses `verifyTunnelAuthorizationGrant(...)` to verify
the complete observed FSB3 against the trusted opaque `Artifact`, then returns
only a request-bound, secret-free `TunnelAuthorizationGrant`. The relay
consumes that grant and never unwraps or retains the artifact, Session contract,
or E2EE key material. Direct admission
uses a configurable `admissionTimeoutMs` with a ten-second default across FSB3
receive, authorization, handler resolution, FSA3, and Session establishment.
`AcceptorOptions.resolveHandlers(...)` resolves and freezes the v3 registry
only after artifact binding and expiry validation and before successful
admission and session establishment. Every accepted Session receives a fresh
RPC router, and `AcceptedSession.serve(...)` owns stream-dispatch lifecycle.
Node one-shot `SessionOptions.rpcHandlers` and
`ConnectionControllerOptions.rpcHandlers` freeze the same reusable
RPC/notification definition, while each established Session receives a fresh
router. The tunnel runtime owns authorization, pairing, opaque forwarding, and
cleanup but no `Session`, application handler, or PSK. The `flowersec-ts-cli`
binary composes the same internal Node WebSocket connector and acceptor without
exporting native carrier handles. Both connectors use a shared ten-second
connection timeout by default and accept `connectTimeoutMs` without exposing
internal clock or candidate-cleanup controls. Invalid public connector options
are projected to `ConnectError`. Low-level carrier factories, capability
descriptors, candidate diagnostics, wire contracts, and cryptographic state
are not package exports.

Node `SessionOptions.origin` and `ConnectionControllerOptions.origin` are optional. An absolute HTTP(S) origin enables WebSocket candidates, while an omitted origin leaves only non-WebSocket candidates eligible.

The proxy entrypoint exposes `PROXY_RUNTIME_SCOPE`, `assertProxyRuntimeScope(...)`, `connectProxyBrowser(...)`, `connectProxyControllerBrowser(...)`, `createProxyRuntime(...)`, bounded Service Worker generation and registration, exact-origin controller/app-window bridges, and `installWebSocketPatch(...)`. Composition accepts only an opaque `ArtifactLease`; the runtime accepts only `Session` and returns only `ByteStream`. Carrier, Yamux, candidate selection, raw artifact scopes, proxy wire frames, and `proxy.runtime@1` remain internal. Window bridges fail closed on origin, source, capability, frame-size, queue, or response-contract mismatch; messages expose only closed proxy status/code values.

## Swift

Applications `import Flowersec` from the `Flowersec` product. The public lifecycle is `parseArtifact(...)`, opaque `Artifact` and `ArtifactLease` values, `ConnectorOptions`, one-shot `connect(lease:options:)`, and `ConnectionController(source:options:maximumAttempts:)`. Artifact parsing reports `ArtifactError`; invalid stream metadata reports only `StreamMetadataError.invalidValue`, while metadata size limits remain implementation details. The returned `Session` exposes only `RPCPeer`, `ByteStream`, `IncomingStream`, and construction-validated `StreamMetadata`. Carrier-neutral `StreamHandlers`, `StreamHandlerOptions`, `StreamHandler`, and `HandlerRegistrationError` register and serve application streams on any established Session. The registry freezes on first serve, applies the exact 128-byte canonical OPEN kind contract, bounds concurrency, resets unknown, excess, and failed streams, closes successful write directions, and closes the Session before canceling and waiting for active handler tasks. Swift exposes no server `ProxyServer` or registrar. Session, stream, RPC peer, and notification subscription wrappers have fixed opaque description and reflection behavior. `RPCError` description, debug description, and reflection expose only its type and code; applications must explicitly read `message`. `ByteStream.read(maxBytes:)` requires a positive value and rejects invalid input as `SessionError.operationFailed`. `RPCPeer.subscribeNotification(_:as:handler:)` completes only after registration, decodes each payload as the requested `Decodable & Sendable` type, and returns an `RPCNotificationSubscription` whose async `cancel()` is idempotent. Decode failures are delivered as `Result.failure(RPCNotificationError.invalidPayload)` without passing unvalidated data, throwing handlers are isolated, and Session close removes all subscriptions. `ConnectError`, `SessionError`, and structured `RetryDisposition` are the public failure boundary. Swift represents `retryAfter` as an exact absolute Unix-millisecond `UInt64` while the controller waits on an internal monotonic deadline; retry timing is not publicly configurable. A controller requires a refreshable source and creates a fresh lease and session per attempt; a connected snapshot retains the successful session's 1-based attempt ordinal, while session termination starts a new cycle whose waiting or terminal snapshot has attempt 0 and whose first Acquire advances to 1. A `retryAfter` deadline cannot be bypassed by `retryNow()`, which returns a Boolean. When retries stop, the snapshot retains the last real `ConnectionAttemptFailure` without a policy wrapper. Old session work is never replayed. Concrete carrier sessions and runtime capability descriptors are internal.

## Rust

The `flowersec` crate exposes strict-v3 `Artifact`, `ArtifactError`, `ArtifactLease`, `ArtifactSpendError`, `ConnectorOptions`, `RpcHandlers`, `StreamHandlers`, `StreamHandlerOptions`, `StreamHandler`, `StreamHandlerRegistrar`, `connect(...)`, `connect_with_cancellation(...)`, `ConnectionController`, `ConnectionControllerOptions`, `ArtifactSource`, `ArtifactSourceError`, `ConnectionState`, `ConnectionFailure`, `ConnectionSnapshot`, `RetryDisposition`, `ConnectError`, `ConnectErrorCode`, `Session`, `SessionTermination`, `SessionError`, `RpcPeer`, `RpcPeerExt`, `RpcError`, `RpcCallError`, `ByteStream`, `IncomingStream`, `JsonObject`, `StreamMetadata`, `StreamMetadataError`, and the carrier-neutral optional `UnreliableMessageChannel`. Explicit legacy APIs, including the v2 artifact, connector, server runtime, issuer, and authorization types, live under `flowersec::v2`; a v3 failure never selects that namespace. `ConnectorOptions::with_rpc_handlers(...)` consumes a reusable request/notification definition, and every one-shot connection or Controller generation creates a fresh runtime router. `RpcHandlers` has no application-stream method. `StreamHandlers::handle_stream(...)` freezes on the first `StreamHandlers::serve(...)`, dispatches on any established Session, applies the exact 128-byte canonical OPEN kind contract, bounds concurrency, resets unknown, excess, failed, or panicked streams, and closes the Session before waiting for active handlers during shutdown. The default `connect(...)` entrypoint is one-shot; `ConnectError::retry_disposition()` exposes whether that one-shot failure is terminal or retryable with a fresh artifact, while `ConnectionController` alone refreshes artifacts, applies fixed shared backoff, and replaces sessions. `ConnectionController::wait_for_snapshot_change(...)` returns immediately for an outdated snapshot, otherwise waits for the next controller transition; dropping the future cancels only that wait, and close wakes it with the closed snapshot. Rust `ByteStream::terminal_error()` and all session operations use the same portable `SessionError` states without an overlapping stream-only error enum. `UnreliableSendOutcome` contains `Accepted`, `DroppedExpired`, `DroppedBudget`, and `DroppedCarrier`, matching the public send-result semantics of Go and TypeScript. `ConnectError::as_str()`, `ConnectErrorCode::as_str()`, `SessionError::as_str()`, and `AcceptErrorCode::as_str()` return canonical public code strings for redacted error text. `ArtifactLease` exposes neither its artifact nor connector-owned commit state. `RpcPeerExt::call_typed(...)` adds typed JSON encoding and decoding while preserving `RpcCallError::Application`. Native strict-v3 server runtimes additionally use direct-only `AcceptorOptions`, `Acceptor`, `AcceptError`, and `AcceptErrorCode`, plus opaque `TunnelRuntimeOptions`, `TunnelAdmissionOptions`, `TunnelRuntime`, `RuntimeAuthorizationRequest`, `TunnelAuthorizationResponse`, and `TunnelAuthorizer`. The v3 relay delegates each opaque deployment authorization request through `TunnelAuthorizer`; the callback receives a cancellation token and must release any application-owned pre-response reservation when cancellation wins. It does not expose an issuer or SDK-owned control-plane record type. `Acceptor::accept_with_handlers(...)` consumes the accepted-server-only `SessionHandlers` registry before establishment and returns `AcceptedSession`; `SessionHandlers` composes the portable stream dispatcher with accepted-session RPC handlers. The sealed registrar preserves `ProxyServer::register(&mut SessionHandlers)` and adds `ProxyServer::register_stream_handlers(&mut StreamHandlers)`. `RpcHandler`, `NotificationHandler`, `SessionHandlerOptions`, and `HandlerRegistrationError` remain application-only. `AcceptedSession::serve(...)` uses the same dispatcher. `TunnelRuntime::bind_websocket(...)` and `TunnelRuntime::bind_raw_quic(...)` use a ten-second admission deadline and 1,024 concurrent admissions; the corresponding `bind_*_with_admission_options(...)` calls accept explicit `TunnelAdmissionOptions`. `TunnelRuntime::close(...)` is a completion barrier for listener release, pending legs, active pairs, and authorization leases; the relay owns no application `Session`, handler, or PSK. `ProxyServer::close().await` cancels active upstream work, waits for handler cleanup, and makes registered handlers reject future dispatch. Quinn connections, admission frames, capability descriptors, candidate plans, session ledgers, and implementation modules remain crate-private.

Rust `ConnectorOptions::new()` creates options without trust roots, and
`with_trust_roots_der(...)` adds validated explicit roots for TLS candidates.
Without configured roots, CA candidates use platform trust roots. Configured
roots replace that source for private-CA deployments. Pin candidates ignore CA
roots, verify only the active artifact-bound leaf-certificate hashes, and never
downgrade to CA. Production v3 has no plaintext carrier.

## Cross-language semantics

A failed DATA, FIN, or stream-rekey write makes that stream terminal because its wire commit boundary is no longer reusable; unrelated streams remain live unless the failed record is required to complete a session rekey. Rekey-assisted receive processing never crosses unread DATA. Rust and TypeScript bound that auxiliary receive queue by the shared `e2ee.max_inbound_buffered_bytes` high-water mark and pause carrier reads until the application consumes buffered DATA.

Remote application RPC failures are semantically separate from session and transport failures across the SDKs. An application error requires a nonzero code, an exact `code`/optional `message` shape, and, when present, a valid UTF-8 message of at most 1024 bytes. Invalid inbound errors fail at the existing session or protocol boundary; invalid outbound handler errors are replaced by the SDK's existing internal application error before wire I/O. The expression is language-native rather than byte-for-byte identical: TypeScript uses typed `RpcResult<Response>` with an `ok: false` application `error`, Go returns `flowersec.RPCError`, Swift throws `RPCError`, and Rust returns `RpcCallError::Application`. Raw error-code taxonomies remain SDK-local; the portable contract is the RPC application/session boundary plus structured controller dispositions. Session, stream, carrier, handshake, and credential-spend failures remain redacted public connection or session failures instead of application RPC failures.

Application stream metadata is a construction-validated value in every SDK. Invalid JSON shape, number, depth, or size fails before `openStream`/`open_stream`; incoming streams expose the same validated value model. Each language uses its native constructor and immutable/read-only access conventions.

Unreliable messages are an SDK-profile capability, not a mandatory method shape for every language. Go exposes `flowersec.UnreliableMessageChannel`, TypeScript exposes `UnreliableMessageChannel`, and Rust exposes `UnreliableMessageChannel` when the session negotiated support. Swift currently exposes no public unreliable-message channel; its portable `Session` core remains complete without receiving DATAGRAM or carrier objects.

## Error Boundary

Public connection and session failures contain only a stable code. They never retain raw artifacts, credential-bearing URLs, tokens, peer payloads, candidate diagnostics, path or stage selection, key material, carrier handles, or implementation objects. Sanitized remote application RPC errors may retain only their bounded semantic code and message.

The shared controller decision has only three dispositions: `terminal`, `retryable`, and an absolute `retry_after` deadline in the inclusive safe range `0..253402300799999` Unix milliseconds. `retry_after` is combined with deterministic monotonic backoff using the later deadline; the backoff floor is 250 ms, doubles per failure ordinal, saturates at 30 seconds, and has zero jitter. `retryNow()` cannot cross the absolute wall-clock deadline. `ConnectionController` obtains a fresh artifact for every attempt, uses deterministic exponential backoff, and never reuses a committed credential. It does not migrate streams or replay RPCs and writes. The exact cross-language lifecycle is `testdata/transport_v3/controller_vectors.json`.

### Durable spend integration

Applications must durably commit a one-time artifact's spend record before any network send that can consume its credential. Production integrations should use one of these persistence patterns:

The first spend callback attempt permanently burns the Lease, including when the callback fails or is canceled. Once the callback begins, the SDK cannot distinguish a definite pre-commit failure from an uncertain durable commit, so retry requires a newly acquired Lease from the `ArtifactSource`.

- **Database uniqueness:** insert the artifact's opaque spend identifier under a unique constraint in the same durable transaction that authorizes the attempt. Network activity may begin only after that transaction commits successfully.
- **Atomic file:** create a record with create-new/no-overwrite semantics, write the complete record, sync the file, and sync its containing directory before allowing network activity.
- **Transactional state:** persist the consumed state or an idempotency record in the application's existing durable business transaction, and allow the connection attempt only after that transaction commits.

If a persistence commit has an uncertain outcome, fail closed and treat the artifact as spent. An in-memory ledger is not an acceptable production default, and recovery logic must never automatically reuse an artifact whose spend may have committed.

## Version Scope

The maintained tree uses the v3 module path and the current Flowersec transport,
session, control-plane, and proxy contracts.

Public changes follow `docs/API_CHANGE_POLICY.md`; stable failures follow `docs/ERROR_MODEL.md`, and the reviewed symbol inventory is `stability/api_contract_manifest.json`.
