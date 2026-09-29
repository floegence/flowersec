# Flowersec Public API Contract

Rust's `V4ContractAcceptance`, `V4ContractRange` and `V4ContractRangeField`
describe immutable exact or bounded local contract policy. A candidate that
changes an unapproved canonical field returns `V4ContractPolicyRejected`.
Explicit digest approval does not override the captured bounded policy.

Flowersec exposes opaque artifacts, carrier-neutral one-shot connection functions, sessions, RPC, byte streams, and an optional `ConnectionController` for long-lived connections. Applications cannot inspect candidates, selected carriers, Yamux, QUIC handles, wire frames, credentials, keys, endpoint identities, logical stream IDs, or spend ledgers.

The unversioned SDK entrypoints use Transport v3. Explicit v4 Environment
entrypoints and their current implementation limits are documented below;
neither entrance negotiates or falls back to the other wire profile. The v3
wire is strict and fail-closed: artifacts, candidates, TLS policy, FSB3/FSA3,
and the frame family are versioned. Production artifacts use WSS, QUIC, or
HTTPS carriers; there is no version negotiation, protocol fallback, or CA/pin downgrade. TLS policy
is part of candidate identity, canonicalization, candidate-set hashing, and
admission binding.

Across all four SDKs, an omitted public connection timeout uses the shared ten-second default from `stability/sdk_defaults.json`. The portable core is artifact/lease lifecycle, one-shot connection, authenticated sessions and reliable streams with construction-validated metadata, outbound RPC call/notify, redacted connection/session errors, and the optional single-owner `ConnectionController`. SDK profiles add runtime and carrier capabilities; language conveniences improve syntax and typing without changing wire semantics.

The runtime registry has 16 portable capability declarations and explicit
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
direct and 18 tunnel coordinates. Its release gate proves all 10 direct cells
and 14 pairwise tunnel cells that include Go; the remaining 8 direct and 4
tunnel cells remain explicitly unverified. Four additional WSS client profiles
prove Swift and browser TypeScript against Go over direct and tunneled paths.

The separate `flowersec-private-loopback/1` product-private profile is not a
deployment capability registry entry and does not extend the closed
`flowersec/3` TLS policy. Its complete security and wire boundary is documented
in `docs/PRIVATE_LOOPBACK_V1.md`.

Trust-root sourcing is policy-specific. CA candidates use platform roots or
deployment-provided private roots. Pin candidates use only the complete leaf
DER SHA-256 pin set and never fall back to CA. Browser WebTransport passes only
active pins through the production `serverCertificateHashes` API; Browser
WebSocket is CA-only. Native adapters enforce the v3 TLS profile and declare
unsupported tuples when they cannot do so. None of these choices changes the
shared ten-second default connection timeout.

Browser JavaScript cannot inspect the peer leaf SPKI or independently prove
P-256-only. Browser WebTransport may accept another non-RSA algorithm according
to browser policy, so an endpoint requiring P-256-only has no cross-runtime
profile or interoperability guarantee through JavaScript. The SDK does not
claim that JavaScript verified P-256-only; deployments requiring that proof use
a native verifier or an explicitly browser-supported profile.

Every production CA-mode TLS connector validates both the certificate chain and the requested target identity; an untrusted root or hostname/IP mismatch fails closed. Pin mode instead uses only the complete leaf DER hashes authorized by the artifact, while still enforcing the certificate profile and the TLS private-key proof; it never adds or falls back to CA chain or hostname authorization. Test-only roots are supplied explicitly by acceptance fixtures or the browser test runner. No production connector has an insecure verification fallback.

The public contract is split into four layers. The portable core is the shared artifact, lease, one-shot connector, session, RPC, and stream model implemented by every SDK. An optional `ConnectionController` is the sole Flowersec long-lived connection owner above a refreshable artifact source. Each SDK profile records runtime-owned carrier support, listener support, and platform trust constraints. A language convenience is an ecosystem-specific API shape layered on top of the portable core, not a promise that every SDK exposes the same syntax. Retry decisions are structured as `terminal`, `retryable`, or an absolute `retry_after` deadline. The public connection, session, controller, and unreliable-message codes are frozen cross-language values; only application-defined RPC error-code taxonomies remain SDK-local. Unversioned artifact, lease, connector, error, and controller names are the Transport v3 entrypoints. Explicit v4 Environment APIs are listed in their language-specific sections.

## Product-private loopback adapter

The Go server surface adds `flowersec.PrivateLoopbackHandlerOptions` and
`flowersec.Acceptor.PrivateLoopbackHandler()`. The Go control plane exposes
`controlplane.PrivateLoopbackProfile`,
`controlplane.PrivateLoopbackIssueOptions`,
`controlplane.Issuer.IssuePrivateLoopbackDirect(...)`, and the opaque
`controlplane.IssuedPrivateLoopbackArtifact`. Its only delivery and durable
authorization boundaries are
`controlplane.IssuedPrivateLoopbackArtifact.ArtifactJSON()`,
`controlplane.IssuedPrivateLoopbackArtifact.AuthorizationRecord()`, and
`controlplane.IssuedPrivateLoopbackArtifact.LookupKey()`; its
`controlplane.IssuedPrivateLoopbackArtifact.String()`,
`controlplane.IssuedPrivateLoopbackArtifact.GoString()`, and
`controlplane.IssuedPrivateLoopbackArtifact.MarshalJSON()` representations are
redacted.

The TypeScript browser entrypoint exposes the runtime values
`PRIVATE_LOOPBACK_PROFILE_V1`, `PrivateLoopbackArtifactErrorV1`,
`parsePrivateLoopbackArtifactV1(...)`,
`createPrivateLoopbackArtifactLeaseV1(...)`,
`connectPrivateLoopbackV1(...)`, and
`createPrivateLoopbackConnectionControllerV1(...)`. Its opaque types are
`PrivateLoopbackArtifactV1`, `PrivateLoopbackArtifactLeaseV1`,
`PrivateLoopbackArtifactSourceV1`,
`PrivateLoopbackArtifactSourceResultV1`,
`PrivateLoopbackSessionOptionsV1`, and
`PrivateLoopbackConnectionControllerOptionsV1`.

These APIs accept only the explicit private envelope and exact numeric-loopback
origin. Ordinary connectors continue to reject it, and the dedicated
controller preserves the existing attempt, cancellation, timeout, backoff,
lease, and replacement-session semantics.

## Explicit public HTTP direct adapter

The Go server surface adds `flowersec.HTTPDirectHandlerOptions` and
`flowersec.Acceptor.HTTPDirectHandler()`. The Go control plane exposes
`controlplane.HTTPDirectProfile`,
`controlplane.HTTPDirectIssueOptions`,
`controlplane.Issuer.IssueHTTPDirect(...)`, and the opaque
`controlplane.IssuedHTTPDirectArtifact`. Its only delivery and durable
authorization boundaries are
`controlplane.IssuedHTTPDirectArtifact.ArtifactJSON()`,
`controlplane.IssuedHTTPDirectArtifact.AuthorizationRecord()`, and
`controlplane.IssuedHTTPDirectArtifact.LookupKey()`; its
`controlplane.IssuedHTTPDirectArtifact.String()`,
`controlplane.IssuedHTTPDirectArtifact.GoString()`, and
`controlplane.IssuedHTTPDirectArtifact.MarshalJSON()` representations are
redacted.

The TypeScript browser entrypoint exposes the runtime values
`HTTP_DIRECT_PROFILE_V1`, `HTTPDirectArtifactErrorV1`,
`parseHTTPDirectArtifactV1(...)`,
`createHTTPDirectArtifactLeaseV1(...)`,
`connectHTTPDirectV1(...)`, and
`createHTTPDirectConnectionControllerV1(...)`. Its opaque types are
`HTTPDirectArtifactV1`, `HTTPDirectArtifactLeaseV1`,
`HTTPDirectArtifactSourceV1`,
`HTTPDirectArtifactSourceResultV1`,
`HTTPDirectSessionOptionsV1`, and
`HTTPDirectConnectionControllerOptionsV1`.

These APIs accept only `flowersec-http-direct/1` and an exact same-origin HTTP
endpoint on localhost or a canonical IP address. HTTP must be explicitly
selected; TLS failures never select this profile. The private-loopback
profile remains loopback-only and application-token admitted.

`flowersec.HTTPDirectServerOptions` and `flowersec.NewHTTPDirectServer(...)`
compose this explicit handler with an `ApplicationHandler` on one HTTP port.
The existing TLS server also accepts an `ApplicationHandler` on its TLS port.
Its optional `WebSocketHTTPServerOptions.AuthorizeWebSocketRequest` callback
adds application-owned request admission for the direct and tunnel paths before
upgrade or session authorization. A rejection returns HTTP 403; application
routes are unaffected. A nil callback preserves existing admission behavior.
The callback can only restrict admission: TLS policy, configured allowed
Origins, and session authorization remain independently required. It does not
change the transport protocol or the carrier-neutral Acceptor interface.
Both reserve the direct and tunnel protocol paths and preserve server-owned
connection shutdown. See `docs/HTTP_DIRECT_V1.md` for the admission and security
contract. Standard v3 connectors remain TLS-only.

## Go

The supported application import is `github.com/floegence/flowersec/flowersec-go/v6`, conventionally named `flowersec`. Its unversioned application lifecycle uses Transport v3; explicit v4 Environment entrypoints are documented in the Go transport v4 section below.

- Artifact lifecycle: `flowersec.Artifact`, `flowersec.ArtifactLease`, `flowersec.ParseArtifact(...)`, `flowersec.NewArtifactLease(...)`, `flowersec.NewArtifactLeaseWithRetirement(...)`, and `flowersec.ErrInvalidArtifact`. The retirement-aware constructor gives an artifact source an explicit cleanup boundary when cancellation wins before spend.
- Connection: `flowersec.ConnectorOptions`, `flowersec.Connect(...)`, `flowersec.ConnectError`, and `flowersec.ConnectErrorCode`. Optional `ConnectorOptions.RPCHandlers` freezes a reusable `flowersec.RPCHandlers` request/notification definition before session establishment; each one-shot connection and Controller generation creates a fresh RPC router from that definition. Invalid artifacts and options are returned as redacted `flowersec.ConnectError` values. `ConnectorOptions.Origin` may be omitted for artifacts that use non-WebTransport carriers; a non-empty value must be an absolute HTTP(S) origin.
- Session values: `flowersec.Session`, `flowersec.SessionTermination`, `flowersec.StreamMetadata`, `flowersec.NewStreamMetadata(...)`, `flowersec.EmptyStreamMetadata()`, `flowersec.StreamMetadata.Values()`, `flowersec.ErrInvalidMetadata`, `flowersec.ByteStream`, `flowersec.IncomingStream`, and `flowersec.RPCPeer`. `SessionTermination.Error` is a required `flowersec.SessionError` value; cancellation of the wait is returned separately.
- Streams: `flowersec.ByteStream.Read(...)`, `flowersec.ByteStream.Write(...)`, `flowersec.ByteStream.Close()`, `flowersec.ByteStream.Kind()`, `flowersec.ByteStream.TerminalError()`, `flowersec.ByteStream.CloseWrite()`, and `flowersec.ByteStream.Reset()`. `CloseWrite` is the only graceful stream FIN operation and preserves the receive direction. `Reset` aborts both directions, and `Close` is its cleanup-oriented alias. A failed write makes that stream terminal because its wire commit boundary is no longer reusable; unrelated streams remain live.
- RPC: `flowersec.RPCPeer.Call(...)`, `flowersec.RPCPeer.Notify(...)`, `flowersec.RPCPeer.OnNotify(...)`, and sanitized application `flowersec.RPCError` values.
- Inbound serving: endpoint clients use `flowersec.RPCHandlers` from `flowersec.NewRPCHandlers()`, with `flowersec.RPCHandler` registrations through `flowersec.RPCHandlers.HandleRPC(...)` and `flowersec.RPCNotificationHandler` registrations through `flowersec.RPCHandlers.HandleNotification(...)`; it has no stream or serve API. Any established Session can use carrier-neutral `flowersec.StreamHandlers` from `flowersec.NewStreamHandlers(...)`, with bounded `flowersec.StreamHandlerOptions`, immutable `flowersec.StreamHandler` registrations through `flowersec.StreamHandlers.HandleStream(...)`, and lifecycle ownership through `flowersec.StreamHandlers.Serve(...)`. Accepted server Sessions use `flowersec.SessionHandlers` from `flowersec.NewSessionHandlers(...)` with `flowersec.SessionHandlerOptions`; that accepted-session configuration composes the same stream dispatcher with request and notification registration. Application stream kinds contain 1 through 128 canonical UTF-8 bytes, have no leading or trailing Unicode whitespace or control or unassigned scalars, and exclude Flowersec-reserved RPC names. RPC and notification registrations share one nonzero uint32 namespace. Consumption freezes a reusable definition; later registrations return `flowersec.ErrHandlerRegistryFrozen`, while repeated snapshot reads remain valid. A successful handler closes its write direction; a handler error or failed write close resets and closes only that stream, and unrelated dispatch continues. Notification failures remain isolated. Unhandled or excess streams are reset and closed. Invalid or duplicate registrations return `flowersec.ErrInvalidHandlerRegistration` or `flowersec.ErrHandlerAlreadyExists`. `flowersec.StreamHandlerRegistrar` is sealed to Flowersec registries. Registry string, debug, and JSON representations reveal no registration state.
- Accepted Session registries also provide `flowersec.SessionHandlers.HandleStream(...)`, `flowersec.SessionHandlers.HandleRPC(...)`, `flowersec.SessionHandlers.HandleNotification(...)`, and `flowersec.SessionHandlers.Serve(...)`; `flowersec.RPCHandlers.String()`, `flowersec.RPCHandlers.GoString()`, `flowersec.RPCHandlers.MarshalJSON()`, `flowersec.StreamHandlers.String()`, `flowersec.StreamHandlers.GoString()`, `flowersec.StreamHandlers.MarshalJSON()`, `flowersec.SessionHandlers.String()`, `flowersec.SessionHandlers.GoString()`, and `flowersec.SessionHandlers.MarshalJSON()` are redacted and reveal no registration state.
- Server acceptance: `flowersec.AcceptorOptions`, `flowersec.Acceptor`, `flowersec.NewAcceptor(...)`, `flowersec.Acceptor.Handler()`, and `flowersec.Acceptor.Serve(...)` own direct application Sessions. `flowersec.DirectListener`, `flowersec.RawQUICListenerOptions`, `flowersec.WebTransportListenerOptions`, `flowersec.NewWebSocketDirectListener()`, `flowersec.NewRawQUICDirectListener(...)`, and `flowersec.NewWebTransportDirectListener(...)` are the direct-only listener surface. `AcceptorOptions.ResolveHandlers` freezes one `flowersec.SessionHandlers` registry before Session establishment. `flowersec.TunnelListener`, `flowersec.TunnelRuntimeOptions`, `flowersec.TunnelRuntime`, `flowersec.NewTunnelRuntime(...)`, `flowersec.TunnelRuntime.Handler()`, `flowersec.TunnelRuntime.Serve(...)`, `flowersec.NewWebSocketTunnelListener()`, `flowersec.NewRawQUICTunnelListener(...)`, and `flowersec.NewWebTransportTunnelListener(...)` form the supported opaque relay boundary. `flowersec.WebSocketHTTPServerOptions`, `flowersec.WebSocketHTTPServer`, and `flowersec.NewWebSocketHTTPServer(...)` are required for standard TLS direct or tunnel WebSocket handlers; its `flowersec.WebSocketHTTPServer.Serve(...)`, `flowersec.WebSocketHTTPServer.ListenAndServe(...)`, `flowersec.WebSocketHTTPServer.Shutdown(...)`, and `flowersec.WebSocketHTTPServer.Close()` methods own lifecycle. The wrapper owns a private TLS clone, forces TLS 1.3 only, and disables session tickets before handshakes. Direct `Handler()` installation on a caller-owned `http.Server` fails closed. `flowersec.ErrInvalidAcceptor`, `flowersec.ErrInvalidTunnelRuntime`, and `flowersec.ErrInvalidWebSocketServer` are the construction failures. `flowersec.WebSocketDirectPath` and `flowersec.WebSocketTunnelPath` remain fixed wire paths.
- Server proxy application: `flowersec.ProxyServerOptions`, `flowersec.ProxyServer`, `flowersec.NewProxyServer(...)`, `flowersec.ProxyServer.RegisterStreamHandlers(...)`, `flowersec.ProxyServer.Close()`, and `flowersec.ErrInvalidProxyServer` provide the fixed-upstream HTTP and WebSocket counterpart to `@floegence/flowersec-core/proxy`. Registration is atomic on the sealed carrier-neutral `StreamHandlerRegistrar`; upstream selection, proxy wire framing, header filtering, body/frame limits, cancellation, and reset cleanup remain Flowersec-owned. `ProxyServer.Close()` cancels active upstream work, waits for handler cleanup, and makes previously registered handlers reject future dispatch.
- Optional unreliable messages: `flowersec.Session.UnreliableMessages()` returns the carrier-neutral `flowersec.UnreliableMessageChannel`; `flowersec.UnreliableMessageChannel.MaxMessageBytes()`, `flowersec.UnreliableMessageChannel.Send(...)`, and `flowersec.UnreliableMessageChannel.Receive(...)` use `flowersec.UnreliableSendOptions` and `flowersec.UnreliableSendStatus` without exposing DATAGRAM or carrier objects. Accepted sends and dropped sends are public outcomes. `flowersec.UnreliableMessageError` exposes only `unavailable`, `invalid_message`, `too_large`, `canceled`, `closed`, or `operation_failed` without mapping to session termination errors.
- Session lifecycle: `flowersec.Session.RPC()`, `flowersec.Session.OpenStream(...)`, `flowersec.Session.AcceptStream(...)`, `flowersec.Session.Rekey(...)`, `flowersec.Session.ProbeLiveness(...)`, `flowersec.Session.WaitTermination(...)`, and `flowersec.Session.Close()`.
- Long-lived connection: `flowersec.NewConnectionController(...)`, `flowersec.ConnectionController`, `flowersec.ConnectionControllerOptions`, `flowersec.ArtifactSource`, `flowersec.ArtifactSourceError`, `flowersec.RetryDisposition`, `flowersec.ConnectionState`, `flowersec.ConnectionFailure`, and `flowersec.ConnectionSnapshot`. `Start` is idempotent, `RetryNow` returns whether the current wait was woken, `Snapshot` exposes only the established one-shot session and core lifecycle fields, and `Close` cancels all controller-owned work. `flowersec.ConnectionController.WaitForSession(...)` is passive: it never starts the controller, returns an existing or newly established Session, and reports failed, closed, or canceled through `flowersec.ConnectionControllerError`. `flowersec.ConnectionSnapshot.Diagnostic()` and the error's `Diagnostic()` expose only state, attempt, failure phase/code, and retry disposition. `flowersec.ConnectionFailurePhase` is the closed `artifact`, `connect`, and `session` boundary, exposed by `flowersec.ConnectionFailure.Phase()` through `flowersec.ConnectionFailureArtifact`, `flowersec.ConnectionFailureConnect`, and `flowersec.ConnectionFailureSession` without changing the two-field `flowersec.ConnectionFailure` layout.
- Redacted failures: `flowersec.ConnectError.Error()`, `flowersec.ConnectError.Unwrap()`, `flowersec.ConnectError.Is(...)`, `flowersec.ConnectError.Code()`, `flowersec.ConnectErrorCode.String()`, `flowersec.SessionError`, `flowersec.SessionErrorCode`, `flowersec.SessionError.Error()`, `flowersec.SessionError.Unwrap()`, `flowersec.SessionError.Code()`, and `flowersec.RPCError.Error()`.
- Controller ownership: `flowersec.NewConnectionController(...)` accepts only a refreshable `ArtifactSource`, never a bare lease. `RetryNow` wakes the existing wait, `Close` cancels the single scheduler and current session, and a replacement session never inherits streams, RPCs, or writes.
- Opaque formatting and serialization: `flowersec.Artifact.String()`, `flowersec.Artifact.GoString()`, `flowersec.Artifact.MarshalJSON()`, `flowersec.ArtifactLease.String()`, `flowersec.ArtifactLease.GoString()`, and `flowersec.ArtifactLease.MarshalJSON()`.
- Connection outcomes: `flowersec.ConnectArtifactInvalid`, `flowersec.ConnectExpired`, `flowersec.ConnectTransportSecurityUnsupported`, `flowersec.ConnectTransportSecurityFailed`, `flowersec.ConnectConnectionFailed`, `flowersec.ErrInvalidConnectorOptions`, and `flowersec.ErrConnectionFailed`.
- Session outcomes: `flowersec.SessionCanceled`, `flowersec.SessionTimeout`, `flowersec.SessionClosed`, `flowersec.SessionGoingAway`, `flowersec.SessionResourceExhausted`, `flowersec.SessionStreamRejected`, `flowersec.SessionStreamReset`, `flowersec.SessionRekeyFailed`, `flowersec.SessionLivenessFailed`, and `flowersec.SessionOperationFailed`.
- Unreliable send outcomes: `flowersec.UnreliableAccepted`, `flowersec.UnreliableDroppedExpired`, `flowersec.UnreliableDroppedBudget`, and `flowersec.UnreliableDroppedCarrier`.

Opaque values have fixed redacted string and JSON behavior. Zero-value or deserialized handles cannot establish a session or spend a lease.

### Go server-side control plane

The Go-only server import `github.com/floegence/flowersec/flowersec-go/v6/controlplane`, conventionally named `controlplane`, issues v3 artifacts and answers the `flowersec-runtime` authorization callback without exposing carrier, candidate, FSB3, PSK, or session-contract objects.

- Endpoint policy: `controlplane.EndpointSet` is created by `controlplane.NewEndpointSet(...)` from structured `controlplane.EndpointConfig` values containing a URL plus `controlplane.TLSPolicy`; URL schemes and TLS policy are converted to internal candidate fields only during issuance. `controlplane.CAPolicy()` selects CA verification, while `controlplane.PinPolicy(...)` accepts normalized `controlplane.CertificatePin` values. `controlplane.CertificatePin.String()`, `controlplane.CertificatePin.GoString()`, `controlplane.TLSPolicy.String()`, and `controlplane.TLSPolicy.GoString()` are redacted and never reveal pin bytes.
- Endpoint validation: invalid structured endpoints return `controlplane.ControlPlaneError` with a stable `controlplane.ControlPlaneErrorCode`. `controlplane.ControlPlaneError.Error()`, `controlplane.ControlPlaneError.Code()`, `controlplane.ControlPlaneError.FieldPath()`, and `controlplane.ControlPlaneError.Unwrap()` expose only the bounded failure and field boundary. Callers use `errors.As` to recover `controlplane.ControlPlaneError`; its `Unwrap()` returns only `controlplane.ErrInvalidControlPlaneInput`, which is matched with `errors.Is`. `controlplane.ErrIssuanceFailed` is an independent non-input failure and is never a `controlplane.ControlPlaneError`. The closed codes are `controlplane.InvalidEndpointCount`, `controlplane.InvalidEndpointID`, `controlplane.InvalidEndpointURL`, `controlplane.DuplicateEndpoint`, `controlplane.InvalidTLSPolicy`, and `controlplane.InvalidPin`. The complete public symbol/error inventory is `stability/api_contract_manifest.json`.
- Issuance: `controlplane.Issuer` from `controlplane.NewIssuer()` accepts carrier-neutral `controlplane.SessionOptions`, bounded `controlplane.Scope` and `controlplane.ArtifactMetadata`, plus either `controlplane.DirectIssueOptions` or `controlplane.TunnelIssueOptions`. `controlplane.Issuer.IssueDirect(...)` returns one `controlplane.IssuedArtifact`; `controlplane.Issuer.IssueTunnelPair(...)` returns one opaque `controlplane.IssuedTunnelPair`.
- Explicit delivery: `controlplane.IssuedArtifact.ArtifactJSON()` is the only client artifact serialization boundary. `controlplane.IssuedArtifact.LookupKey()` is a non-secret credential hash, and `controlplane.IssuedArtifact.AuthorizationRecord()` returns the matching opaque `controlplane.AuthorizationRecord`.
- Durable authorization: `controlplane.AuthorizationRecord.Encode()` and `controlplane.ParseAuthorizationRecord(...)` are the explicit secret-storage boundary. The caller must atomically reserve the one-time record before allowing a request; `controlplane.AuthorizationRecord.LookupKey()` never returns the bearer credential.
- Runtime callback: `controlplane.ParseRuntimeAuthorizationRequest(...)` returns a redacted `controlplane.RuntimeAuthorizationRequest`. Its `controlplane.RuntimeAuthorizationRequest.LookupKey()` locates the record; `controlplane.AuthorizeRuntime(...)` verifies a direct FSB3 and returns `controlplane.AuthorizationResponse`. `controlplane.AuthorizeTunnelRuntime(...)` verifies a tunnel FSB3 and returns the secret-free `controlplane.TunnelAuthorizationResponse`; an application authorizer that performs equivalent admission validation may use `controlplane.AllowTunnelRuntime(...)` to construct the same bounded allow response. Neither path exposes a Session contract or E2EE key to the relay. `controlplane.RejectRuntime(...)` creates only validated reject or retry decisions. `controlplane.AuthorizationResponse.JSON()` and `controlplane.TunnelAuthorizationResponse.JSON()` are the only response serialization boundaries.

### Go application acceptor

Applications that own direct server sessions use `flowersec.NewAcceptor(...)`. Its listeners are direct-only and its handler resolver and `OnSession` callback are never invoked by a relay. `flowersec.NewTunnelRuntime(...)` is the separate untrusted relay boundary: it accepts only tunnel listeners, authorizes pairing claims, and forwards opaque carrier streams through the built-in bounded bridge. It exposes no `Session`, `AcceptedSession`, RPC router, or handler registration.

The root Go proxy server is an application protocol owner. `flowersec.NewProxyServer(...)` validates a fixed upstream and
resource/header policy; `flowersec.ProxyServer.RegisterStreamHandlers(...)` installs the HTTP
and WebSocket handlers on a carrier-neutral `StreamHandlers`. The browser/Node
peer uses the published TypeScript `/proxy` entrypoint. Carrier objects, JSON
metadata, proxy stream kinds, and WebSocket frames remain internal.

`ProxyServerOptions.AllowedUpstreamAddresses` fixes the permitted IP addresses or
canonical CIDRs for a named upstream. Numeric upstreams are pinned to their exact
normalized address, including explicit private/loopback deployments. Both HTTP
and WebSocket validate the entire bounded DNS answer before numeric dialing and
check the actual peer before HTTP credentials or body publication. TLS retains
the original logical hostname. The private HTTP/1 keep-alive pool uses one
`ClientConn.RoundTrip` per request and retains body owners through actual exit;
method names and idempotency keys never authorize implicit request replay.
Automatic redirects, ambient proxies and HTTP/2 connection coalescing are absent.
The standard resolver's internal allocation allowance remains a native runtime
qualification requirement; the 64-result acceptance limit alone does not prove
its allocation bound.

The Go private connection entrance captures bounded original HTTP/1 response
headers before native transfer normalization. Conflicting lengths, TE/CL mixes,
singleton conflicts and Connection nominations are checked using those facts.
The native HTTP implementation remains responsible for body/chunk/trailer
framing; the proxy preserves the original facts through application filtering.

The Node `ProxyServerOptions.allowedUpstreamAddresses` and Rust
`ProxyServerOptions::allowed_upstream_addresses` configure the same address/CIDR
boundary for their native HTTP and WebSocket adapters. Named upstreams require
explicit ranges in addition to hostname approval. Both adapters validate all
resolved candidates, normalize mapped IPv6, reject an out-of-policy answer as a
whole, use at most three numeric connection-preparation attempts, and check the
actual peer before exposing a socket to HTTP or WS. The original logical host
still controls Host and TLS identity. Each request owns its connection; no
redirect, ambient proxy, global agent or implicit request replay can bypass the
policy. Resolver and actual socket cleanup retain finite policy slots until
completion, including after the original waiter times out. Native resolver and
TLS internal allocation allowances still require host qualification.

Rust `ProxyServerOptions::max_concurrent_http_streams`,
`ProxyServerOptions::max_concurrent_event_streams`, and
`ProxyServerOptions::event_stream_idle_timeout` reserve separate finite HTTP and
event-stream capacity. Zero selects SDK defaults: at most 24 HTTP streams, an
event subset of at most 16, and a 45-second event idle deadline. An explicitly
accepted `text/event-stream` response uses that idle deadline and bounded chunks
instead of the ordinary response's lifetime/body limit. Content-Length remains
an integrity assertion even when Connection removes it from forwarded headers.
Other responses keep their original finite deadline. Reset, excess input or
cancellation ends only that request, and idle expiration releases actual native
I/O before its policy slot becomes available again.

- Opaque formatting: `controlplane.EndpointSet.String()`, `controlplane.EndpointSet.GoString()`, `controlplane.IssuedArtifact.String()`, `controlplane.IssuedArtifact.GoString()`, `controlplane.IssuedArtifact.MarshalJSON()`, `controlplane.AuthorizationRecord.String()`, `controlplane.AuthorizationRecord.GoString()`, `controlplane.AuthorizationRecord.MarshalJSON()`, `controlplane.RuntimeAuthorizationRequest.String()`, `controlplane.RuntimeAuthorizationRequest.GoString()`, `controlplane.RuntimeAuthorizationRequest.MarshalJSON()`, `controlplane.AuthorizationResponse.String()`, `controlplane.AuthorizationResponse.GoString()`, `controlplane.AuthorizationResponse.MarshalJSON()`, `controlplane.TunnelAuthorizationResponse.String()`, `controlplane.TunnelAuthorizationResponse.GoString()`, and `controlplane.TunnelAuthorizationResponse.MarshalJSON()` reveal no credential-bearing content. `controlplane.AuthorizeTunnelRuntime(...)` and `controlplane.RejectTunnelRuntime(...)` return only the secret-free tunnel response.
- Invalid issuance, record, request, lease, expiry, or binding inputs return only `controlplane.ErrInvalidControlPlaneInput` at the public boundary. An unavailable cryptographic random source returns the stable redacted `controlplane.ErrIssuanceFailed` value.

This package owns transport-neutral issuance and authorization mechanics. Tenant selection, endpoint placement, permissions, billing, durable lease state, and upstream routing decisions remain application control-plane responsibilities.

## TypeScript

The supported package entrypoints are `@floegence/flowersec-core`, `@floegence/flowersec-core/browser`, `@floegence/flowersec-core/node`, and `@floegence/flowersec-core/proxy`.

The root exposes v3 application names: `Artifact`, `ArtifactError`,
`ArtifactErrorCode`, `ArtifactLease`, `ArtifactLeaseError`, `Session`,
`SessionTermination`, `RpcPeer`, `JsonValue`, `ByteStream`, `StreamMetadata`,
`createStreamMetadata(...)`, `createStreamMetadataEnvelope(...)`,
`StreamMetadataError`, `StreamHandlers`,
`StreamHandler`, `StreamHandlerOptions`, `HandlerRegistrationError`,
`ConnectionController`, `ArtifactSource`, `ConnectionSnapshot`,
`ConnectionControllerError`, `ConnectionDiagnostic`, `RetryDisposition`, typed `RpcResult<Response>`,
`ConnectError`, and `SessionError`. These unversioned names are the complete
public application surface for Transport v3. Explicit v4 Environment and WSS
configuration exports are registered in the TypeScript v4 section below.

`StreamHandlers.handleStream(...)` freezes on the first `serve(...)`,
dispatches application streams on any established browser or Node Session,
bounds concurrency, resets unknown and excess streams, isolates handler
rejection, and closes the Session before waiting for active handlers during
shutdown. Application stream kinds follow the exact OPEN contract: 1 through
128 canonical UTF-8 bytes, no leading or trailing Unicode whitespace, control,
or unassigned scalars, and no Flowersec-reserved RPC kind. Immutable
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

`ConnectError.retryDisposition` is the retry property. For `retry_after`, `notBeforeUnixMilliseconds` is the absolute deadline. `ConnectionController.waitForSession(...)` is passive and returns structured failed, closed, or canceled errors; `connectionDiagnostic(...)` projects snapshots to state, attempt, failure phase/code, and retry disposition without retaining a Session. Unreliable-message failures use only `unavailable`, `invalid_message`, `too_large`, `canceled`, `closed`, and `operation_failed`; accepted and the three `dropped_*` states remain send outcomes.

Node `SessionOptions.origin` and `ConnectionControllerOptions.origin` are optional. An absolute HTTP(S) origin enables WebSocket candidates, while an omitted origin leaves only non-WebSocket candidates eligible.

The proxy entrypoint exposes `PROXY_RUNTIME_SCOPE`, `assertProxyRuntimeScope(...)`, `connectProxyBrowser(...)`, `connectProxyControllerBrowser(...)`, `createProxyRuntime(...)`, bounded Service Worker generation and registration, exact-origin controller/app-window bridges, `registerProxyAppWindowWithServiceWorkerRuntime(...)`, and `installWebSocketPatch(...)`. The high-level Service Worker runtime entrypoint composes the existing app-window bridge with Flowersec's private runtime listener and returns only the opaque `ProxyAppWindowHandle`; initialization rolls back partial listeners and disposal is idempotent. Its request envelope, decoder, message constants, ports, flow-control fields, and response protocol remain package-private and are not exported. Composition accepts only an opaque `ArtifactLease`; the runtime accepts only `Session`, returns standard streaming `Response` values for HTTP fetches and `ByteStream` values for WebSockets. Carrier, Yamux, candidate selection, raw artifact scopes, proxy wire frames, and `proxy.runtime@2` remain internal. Window bridges fail closed on origin, source, capability, frame-size, queue, or response-contract mismatch; messages expose only closed proxy status/code values.

`ProxyRuntime.fetch(input, init)` runs HTTP over the current Session using the same execution core as Service Worker and window dispatch. Inputs are origin-relative paths or absolute URLs at the configured `externalOrigin`; arbitrary upstream origins, credentials, forbidden headers, and paths outside the policy are rejected or filtered. A response body is demand-driven with at most one chunk in flight. Abort, body cancellation, runtime disposal, and stream errors release admission and reset upstream work; no transport retry or native HTTP fallback occurs.

The TypeScript runtime and Go/Node proxy servers recognize persistent SSE only when both the request Accept header and response Content-Type specify `text/event-stream`. Intake and response establishment retain the finite request deadline. Confirmed event responses use a 45-second activity timeout (including stalled consumer backpressure), retain chunk and session buffer limits, and do not accumulate a lifetime byte limit. Finite responses retain their total deadline and body limit. HTTP admission defaults to 24 concurrent requests with at most 16 event candidates, leaving eight slots for finite work. Excess event subscriptions fail with `resource_exhausted` without queueing; non-event responses release their event reservation. Server HTTP/event limits are subordinate to the existing overall proxy/session stream limits and do not increase transport capacity. Each feature owns subscription recovery.

The validated proxy scope may declare bounded `http.additionalPathPrefixes` and `http.extraRequestHeaders`. Additional HTTP paths require an explicit `appBasePath`; composition permits that base plus the declared paths while retaining the base-only WebSocket policy. Header names use the same forbidden-header validation as the runtime, and absent HTTP additions grant no extra access. These declarations are immutable acquisition authority, not page-message overrides.


## Swift

### Transport v3 entrance

Swift `ConnectorOptions.origin` is required and must be an absolute HTTP(S) origin for the Apple WebSocket admission policy; the API does not provide an implicit origin.

Applications `import Flowersec` from the `Flowersec` product. The public lifecycle is `parseArtifact(...)`, opaque `Artifact` and `ArtifactLease` values, `ConnectorOptions`, one-shot `connect(lease:options:)`, and `ConnectionController(source:options:maximumAttempts:)`. `RetryDisposition` is the current structured retry contract. Artifact parsing reports `ArtifactError`; invalid stream metadata reports only `StreamMetadataError.invalidValue`, while metadata size limits remain implementation details. The returned `Session` exposes only `RPCPeer`, `ByteStream`, `IncomingStream`, and construction-validated `StreamMetadata`. Carrier-neutral `StreamHandlers`, `StreamHandlerOptions`, `StreamHandler`, and `HandlerRegistrationError` register and serve application streams on any established Session. The registry freezes on first serve, applies the exact 128-byte canonical OPEN kind contract, bounds concurrency, resets unknown, excess, and failed streams, closes successful write directions, and closes the Session before canceling and waiting for active handler tasks. Swift exposes no server `ProxyServer` or registrar and no unreliable-message API. Session, stream, RPC peer, and notification subscription wrappers have fixed opaque description and reflection behavior. `RPCError` description, debug description, and reflection expose only its type and code; applications must explicitly read `message`. `ByteStream.read(maxBytes:)` requires a positive value and rejects invalid input as `SessionError.operationFailed`. `RPCPeer.subscribeNotification(_:as:handler:)` completes only after registration, decodes each payload as the requested `Decodable & Sendable` type, and returns an `RPCNotificationSubscription` whose async `cancel()` is idempotent. Decode failures are delivered as `Result.failure(RPCNotificationError.invalidPayload)` without passing unvalidated data, throwing handlers are isolated, and Session close removes all subscriptions. `ConnectError`, `SessionError`, and structured `RetryDisposition` are the public failure boundary. `ArtifactSourceFailure` exposes the same redacted `ConnectErrorCode` plus its retry disposition, including `artifact_invalid / terminal` for an invalid source contract. Swift represents `retryAfter` as an exact absolute Unix-millisecond `UInt64` while the controller waits on an internal monotonic deadline; retry timing is not publicly configurable. `ConnectionController.waitForSession()` is passive and throws a structured failed, closed, or canceled `ConnectionControllerError`; `ConnectionSnapshot.diagnostic` contains only state, attempt, failure phase/code, and retry disposition. A controller requires a refreshable source and creates a fresh lease and session per attempt; a connected snapshot retains the successful session's 1-based attempt ordinal, while session termination starts a new cycle whose waiting or terminal snapshot has attempt 0 and whose first Acquire advances to 1. A `retryAfter` deadline cannot be bypassed by `retryNow()`, which returns a Boolean. When retries stop, the snapshot retains the last real `ConnectionAttemptFailure` without a policy wrapper. Session work is never replayed. Concrete carrier sessions and runtime capability descriptors are internal.

### Configured Swift transport v4 client

`TransportEnvironment` provides `init(configuration:)`,
`generateApplicationIdentity(profile:)`,
`importApplicationIdentity(profile:signingSeed:noiseStaticPrivateKey:)`,
`preparePoolMaterial(_:identity:)`, `connectMaterial(_:requirements:)`,
`connect(source:requirements:)`, `refreshTrustedTime()`,
`refreshNamespace(authority:head:state:)`, `invalidateTimeContinuity()`,
`close()` and `cleanupStatus()`. Its configured native entrance supports one
direct WSS preauthorized-pool candidate on macOS/iOS, the transport application
profile, both Noise profiles and no optional features. An unconfigured
Environment reports `TransportV4AvailabilityError.runtimeUnavailable`.

Configuration types are `TransportV4ClientConfiguration`,
`TransportV4CryptoProfile`, `TransportV4TrustedTime`, `TransportV4TimePolicy`,
`TransportV4TrustNamespace`, `TransportV4NamespaceSnapshot`,
`TransportV4Endpoint` and `TransportV4PoolHistory`. The host independently
configures trusted time, namespace roots and bootstrap transport, signed-host
to numerical-address mapping, and a complete-history/anti-rollback continuity
gate. The SDK verifies the nonce-bound bootstrap, full namespace state,
credentials and original identity, and owns irreversible SQLite consumption.

`TransportV4ApplicationIdentity` exports only public identity keys and a close
operation. Exact `TransportV4PoolCredential` bytes become an opaque
`ConnectionMaterial` attached to that original Environment.
`ConnectionMaterialSource` supplies such material; `ConnectionRequirements`
rejects unsupported requirements before acquisition. Material exposes only
`close()`, `waitCleanup()` and `cleanupStatus()`. `CleanupStatus` reports actual
retained ownership. Environment close does not pretend a noncooperative source
has completed, and retained charged aliases can delay resource release.

The real TLS 1.3 socket validates the signed WSS route and CA or active
leaf-DER-SHA-256 pin policy before pool consumption. Pin validation checks the
actual X.509v3 P-256 leaf certificate, its full fourteen-day lifetime bound and
signed interval; the original active set and matched deadline cannot be
extended by rotation. HELLO, signed FSB/FSA, KKpsk0 Noise and both READY
obligations precede Session publication. `TransportV4ConnectError` is the
redacted connection boundary, including authenticated admission rejection.
No retry, replay, reconnect or v3 fallback occurs through this entrance.

The Swift native v4 Session enforces the signed idle duration under its original
Environment gate. Only a complete protocol-valid authenticated input or an
actual successful binary record write completion refreshes its monotonic anchor.
Native WebSocket Ping/Pong, ignored input and queue admission do not refresh it.
The original window is checked before refresh and every Session operation;
`SessionError.idleTimeout` and `SessionError.timeUnavailable` distinguish idle
expiration from clock continuity failure. Rekey and drain never reset the anchor.

Swift v4 `probeLiveness()` owns at most eight independent samples and measures
elapsed time from local acceptance. `TransportV4LivenessError` retains the finite
`TransportV4LivenessFailure` and `TransportV4LivenessProgress` (submitted,
complete, optional elapsedMilliseconds). Cancellation and the ten-second
original deadline remove the matcher while retaining actual provider tails.
Rekey intent interrupts probes before preparing or waiting to publish REQUEST.
`TransportV4ClientConfiguration.automaticLiveness` optionally captures a
`TransportV4AutomaticLivenessPolicy`, protecting one of the eight slots. Only
complete timely publication followed by a full real response budget without
known local stalls can count a miss. Automatic PONG and successful independent
rekey reset misses; the threshold reports `SessionError.livenessPathUnresponsive`.
Automatic probing is disabled by default.

The returned `Session` supports reliable `ByteStream` operations, stream
acceptance, rekey, liveness, termination and close. V4 `StreamMetadata` adds
`init(namespace:version:values:)`, `init(encodedV4:)`, `encodedV4()`,
`v4Namespace`, `v4Version` and `v4Values`. It preserves exact deterministic CBOR
with the shared namespace, UInt16 version, text-to-bytes map and 4,096-byte
bounds. Zero bytes is the empty sentinel; an ordinary empty values map retains
its namespace. `StreamMetadata.init(_:)` encodes the optional `application/json`
version 1 codec, with each JSON value stored in the same ordinary byte map.
`jsonValues()` decodes that codec explicitly; binary namespaces remain opaque.
`JSONValue.number(_:)` accepts finite fractional values, and integer values
retain their full Int64 range. Invalid values report
`StreamMetadataError.invalidValue`.

`ReaderCursor`, `ReaderCursorOptions`, `ReaderCursorSnapshot`, `ReadProgress`,
`ReadResult`, `ReadWaitStatus`, `ReadStreamStatus`, `ReadCause`,
`ReadStreamError`, `ReadMethodFailure`, `WriteOperation`, `WriteProgress`,
`WritePhase`, `WriteTerminalReason`, `NotificationSubscription`,
`OperationReference`, `OperationStatus`, `ResultPayload` and `OperationHandle`
are public owned contracts. Their presence does not claim public cursor/write
factories or completed v4 RPC, execution or notification assembly. The current
client's `Session.rpc` operations are unavailable. Services, live authority,
accepted-server v4, tunnel, raw QUIC, WebTransport, datagrams, resume, candidate
racing and a v4 controller are outside this entrance. See
[Swift transport v4](SWIFT_TRANSPORT_V4.md).

## Rust

The `flowersec` crate exposes strict-v3 `Artifact`, `ArtifactError`, `ArtifactLease`, `ArtifactSpendError`, `ConnectorOptions`, `RpcHandlers`, `StreamHandlers`, `StreamHandlerOptions`, `StreamHandler`, `StreamHandlerRegistrar`, `connect(...)`, `connect_with_cancellation(...)`, `ConnectionController`, `ConnectionControllerOptions`, `ArtifactSource`, `ArtifactSourceError`, `ConnectionState`, `ConnectionFailure`, `ConnectionSnapshot`, `ConnectionDiagnostic`, `RetryDisposition`, `ConnectError`, `ConnectErrorCode`, `Session`, `SessionTermination`, `SessionError`, `RpcPeer`, `RpcPeerExt`, `RpcError`, `RpcCallError`, `ByteStream`, `IncomingStream`, `JsonObject`, `StreamMetadata`, `StreamMetadataError`, and the carrier-neutral optional `UnreliableMessageChannel`. `ArtifactSourceError::code()` and `ConnectionFailure::code()` expose only the canonical redacted `ConnectErrorCode`; neither accessor reveals source, transport, credential, or peer diagnostics. `ConnectorOptions::with_rpc_handlers(...)` consumes a reusable request/notification definition, and every one-shot connection or Controller generation creates a fresh runtime router. `RpcHandlers` has no application-stream method. `StreamHandlers::handle_stream(...)` freezes on the first `StreamHandlers::serve(...)`, dispatches on any established Session, applies the exact 128-byte canonical OPEN kind contract, bounds concurrency, resets unknown, excess, failed, or panicked streams, and closes the Session before waiting for active handlers during shutdown. The default `connect(...)` entrypoint is one-shot; `ConnectError::retry_disposition()` exposes whether that one-shot failure is terminal or retryable with a fresh artifact, while `ConnectionController` alone refreshes artifacts, applies fixed shared backoff, and replaces sessions. `ConnectionController::wait_for_session()` is passive and returns a structured failed, closed, or canceled `ConnectionControllerError`; `ConnectionSnapshot::diagnostic()` contains only state, attempt, failure phase/code, and retry disposition. `ConnectionController::wait_for_snapshot_change(...)` returns immediately for an outdated snapshot, otherwise waits for the next controller transition; dropping the future cancels only that wait, and close wakes it with the closed snapshot. Rust `ByteStream::terminal_error()` and all session operations use the same portable `SessionError` states without an overlapping stream-only error enum. `UnreliableMessageErrorCode` contains only `Unavailable`, `InvalidMessage`, `TooLarge`, `Canceled`, `Closed`, and `OperationFailed`; current `UnreliableMessageError` values map into this closed set. `UnreliableSendOutcome` contains `Accepted`, `DroppedExpired`, `DroppedBudget`, and `DroppedCarrier`, matching the public send-result semantics of Go and TypeScript. `ConnectError::as_str()`, `ConnectErrorCode::as_str()`, `SessionError::as_str()`, and `AcceptErrorCode::as_str()` return canonical public code strings for redacted error text. `ArtifactLease` exposes neither its artifact nor connector-owned commit state. `RpcPeerExt::call_typed(...)` adds typed JSON encoding and decoding while preserving `RpcCallError::Application`. Native strict-v3 server runtimes additionally use direct-only `AcceptorOptions`, `Acceptor`, `AcceptError`, and `AcceptErrorCode`, plus opaque `TunnelRuntimeOptions`, `TunnelAdmissionOptions`, `TunnelRuntime`, `RuntimeAuthorizationRequest`, `TunnelAuthorizationResponse`, and `TunnelAuthorizer`. The v3 relay delegates each opaque deployment authorization request through `TunnelAuthorizer`; the callback receives a cancellation token and must release any application-owned pre-response reservation when cancellation wins. It does not expose an issuer or SDK-owned control-plane record type. `Acceptor::accept_with_handlers(...)` consumes the accepted-server-only `SessionHandlers` registry before establishment and returns `AcceptedSession`; `SessionHandlers` composes the portable stream dispatcher with accepted-session RPC handlers. The sealed registrar exposes only `ProxyServer::register_stream_handlers(...)` for carrier-neutral stream registries. `RpcHandler`, `NotificationHandler`, `SessionHandlerOptions`, and `HandlerRegistrationError` remain application-only. `AcceptedSession::serve(...)` uses the same dispatcher. `TunnelRuntime::bind_websocket(...)` and `TunnelRuntime::bind_raw_quic(...)` use a ten-second admission deadline and 1,024 concurrent admissions; the corresponding `bind_*_with_admission_options(...)` calls accept explicit `TunnelAdmissionOptions`. `TunnelRuntime::close(...)` is a completion barrier for listener release, pending legs, active pairs, and authorization leases; the relay owns no application `Session`, handler, or PSK. `ProxyServer::close().await` cancels active upstream work, waits for handler cleanup, and makes registered handlers reject future dispatch. Quinn connections, admission frames, capability descriptors, candidate plans, session ledgers, and implementation modules remain crate-private.

Rust `ConnectorOptions::new()` creates options without trust roots, and
`with_trust_roots_der(...)` adds validated explicit roots for TLS candidates.
Without configured roots, CA candidates use platform trust roots. Configured
roots replace that source for private-CA deployments. Pin candidates ignore CA
roots, verify only the active artifact-bound leaf-certificate hashes, and never
downgrade to CA. Production v3 has no plaintext carrier.

### Explicit Rust transport v4

The `V4TransportEnvironment` publishes `identity_keys`, `namespace`,
`pool_connection_material`, `sqlite_pool_backing`, `connect_pool_wss`,
`connect_pool_wss_with_handler_plan` and `serve_pool_wss`.
Its asynchronous `close` returns `Result<CleanupStatus, SessionError>` after a
bounded observation of the original cleanup operation. Actual tails remain
charged after `cleanup_incomplete`; an independent `wait_cleanup` timeout does
not close an active Environment.
The supported production tuple is one direct network WSS candidate from a
preauthorized pool, the transport application profile, and no negotiated
optional features. It requires a Tokio multithread runtime. The original
Environment provides trusted time, authorization subscriptions, finite resource
accounts, irreversible SQLite consumption and actual carrier cleanup.
The unversioned connector and server APIs above continue to use their stated
strict-v3 contract; they do not establish v4 connections.

Connection material and trust types are `V4IdentityKeys`, `V4Namespace`,
`V4NamespaceTrustRoot`, `V4PoolCredentialBytes`, `V4PoolConnectionMaterial`,
`V4WssConnectOptions`, `V4ConnectError` and `V4PostSpendFailure`. Private identity
keys stay in original handles; exact signed material is consumed once. Native
TLS validates TLS 1.3, the signed route and Origin policy, and either explicit
CA roots or the active complete DER pins. No platform-root fallback, DNS retry,
redirect, credential replay or fresh connection adoption occurs.

Durable pool types are `V4SQLitePoolBacking`, `V4SQLitePoolStore`,
`V4SQLitePoolOptions`, `V4SQLitePoolIdentity`, `V4SQLitePoolBinding`,
`V4SQLitePoolLimits`, `V4SQLitePoolContinuity`, `V4PoolStoreError`,
`V4PoolStoreFailure` and `V4PoolWriteState`. Continuity must come from independently
trusted host history. Closing a store does not release persistent disk backing;
`release_removed` requires the actual database and journal files to be removed.
A successful irreversible consume followed by connection failure is explicitly
`V4ConnectError::Spent`; it never grants retry authority.

Accepted servers use `V4AcceptedMaterialSource`, `V4WssServeOptions`,
`V4WssServerIdentity`, `V4ServeHandle`, `V4SQLiteAdmissionBinding` and
`V4SQLiteAdmissionAuthority`. The material callback supplies lookup bytes;
the original namespace and accepted socket independently verify admission.
The authority retains distinct ParentWinner and AdmissionLedger facts in
SQLite revision 2. `V4ServeHandle` exposes `local_address`, `accept`, `drain`,
`wait_drain`, `close`, `cleanup_status` and `wait_cleanup`. A pending or late
READY cannot publish after Serve Drain/Close, and shared Environment ownership
remains with the caller. Conflict results are `AdmissionConflict` and
`WinnerConflict` on `V4PoolStoreFailure`.

`V4WssServeOptions` fixes `V4ServeCallbacks`, `V4ApplicationLimits` and parent
cancellation. `authorize_request` accepts a bounded `V4ServeRequestContext` and
returns `V4RequestAuthorization` before upgrade. After authenticated FSB and
identity checks, `resolve_handlers` and `authorize_application` use
`V4AuthenticatedRequestContext` and its detached `V4ApplicationBinding`.
`reserve_lease` registers one `V4ApplicationAuthorizationLease` during the
original authorization callback, including late success. Only an authorized
`V4AuthorizeApplicationResult` with that lease reaches durable admission.
`V4ApplicationAuthorization` records not-started, authorized, rejected or
unknown authorization in the final `V4ServeReleaseContext`.

`V4TransportEnvironment::handler_plan` captures `V4HandlerPlanOptions` into an
immutable, Environment-bound `V4HandlerPlan`. `V4StreamDispatch` selects explicit
manual acceptance or frozen `V4RawStreamRegistration` entries. Registered
`V4RawStreamHandler` implementations return `V4StreamAuthorization` and own
bounded authorization/handler work; public `next_open` cannot bypass this
dispatcher. Closing a plan seals future captures and preserves existing ones.
The Connect variant accepts the same plan with explicit `V4ApplicationLimits`,
captures it before durable pool consumption, and attaches it before returning
the READY Session. Connect cleanup waits for admitted handler work before
returning the original application charge.

After the original READY publication claim, `on_session` returns
`V4SessionAcceptance`: Retained, Queue (for `accept`) or Rejected. A later Close
cannot cancel the already-claimed call. `release` runs once after real cleanup
or an explicit incomplete observation. Cancellation closes a registered or
late lease once, without dropping its running authorizer. Incomplete lease
observations reuse that owner; an incomplete Release cannot be retried or
refunded. `V4ServeError` projects `V4ServeFailure` and actual cleanup without
application error strings. Callback futures must retain their own work until
exit; independently retained work belongs to the registered lease, whose
cleanup must not depend on Release starting. Error snapshots grant no new
background-work ownership. See [Rust transport v4](RUST_TRANSPORT_V4.md) for the
fixed limits and original callback/worker cleanup ordering.

`V4ServeDrainOperation` exposes `result` and `wait` over the original group
operation. `V4ServeDrainResult` contains the stable `outcome`, bounded `error`
and current `cleanup` view. Every child uses the earlier of its original Drain
deadline and the group's first absolute deadline. Historical physical tails
remain cleanup responsibilities; failures after group closure remain part of
the group result after the child exits. `wait_drain`, `wait_cleanup` and the
operation's `wait` return `Result` and share sixteen prepaid pending observer
slots; full capacity returns `V4ConnectError::Capacity`. Canceled observation
only releases its slot, and terminal observation requires no new slot.

The completed owner exposes `V4Session`, `V4Stream`, `V4OpenRequest`,
`V4Metadata`, `V4ProbeOutcome`, `V4ProbeResult`, `V4DrainOperation`,
`V4DrainOutcome` and `V4DrainResult`. Streams implement the existing `ByteStream`
contract. Probe, rekey, Drain, termination and cleanup share the original
Session and carrier. A successful publish waits for actual ordered I/O.
`V4ProbeResult` retains finite outcome, `submitted`, `complete` and optional
elapsed time from original admission. Eight probe owners share the original
maintenance budget; cancellation and timeout remove their matchers while real
provider tails retain ownership. Rekey interrupts ordinary samples. Optional
`V4AutomaticLivenessPolicy` on `TransportEnvironmentOptions::automatic_liveness`
reserves one of those owners and counts only fully published, unstalled samples
with a complete response budget. It defaults to disabled; a configured miss
threshold reports `SessionError::LivenessPathUnresponsive` without business replay.
`V4Stream::wait_peer_authenticated` waits for an already accepted offset to be
covered by a real ACK or normal DRAINED proof, retaining fulfilled observations
after retirement. Dropping `close_write` or `finish` waits does not revoke the
original FIN; aborted proof and missing stream state cannot report successful
Finish.

Environment configuration and observations use `TransportEnvironmentOptions`,
`ResourceLimits`, `EnvironmentError`, `TrustedTimeSource`, `TrustedTimeSample`,
`TrustedTimeProfile`, `ConnectionRequirements` and `CleanupStatus`. The current
Rust resource ledger separately bounds all eleven local dimensions:
`sdk_bytes`, `provider_bytes`, `disk_bytes`, `items`, `work_slots`, `tasks`,
`timers`, `connections`, `tls_handshakes`, `sessions` and `native_handles`.
`ResourceLimits::DIMENSIONS` and `ResourceLimits::values` expose that fixed order.
Each reservation, split and release preserves the same original owner chain.
Provider runtime, SDK queues and retained disk backing have separate caps and
lifetimes. Full provider/deployment qualification remains unfinished; configured
bounds do not prove total host RSS or independently qualify every design profile.

Owned read/write helpers are `ReadProgress`, `ReadResult`, `ReadWaitStatus`,
`ReadStreamStatus`, `ReadCause`, `ReadError`, `ReadErrorCode`, `ReadErrorScope`,
`ReadRetryDisposition`, `ReadMethodFailure`, `ReadMethodFailureReason`,
`ReaderCursor`, `ReaderCursorOptions`, `ReaderCursorSnapshot`, `StreamReadOwner`,
`StreamReadPermit`, `ReadDeliveryAuthorization`, `StreamV4Ext`, `WriteOperation`,
`WriteProgress`, `WriteRequestAdmission` and `WriteStagingOwner`. The public
`OperationHandle`, `OperationReference`, `OperationStatus`, `ResultPayload` and
`V4NotificationSubscription` types do not imply a completed v4 RPC, service,
execution or notification transport. Those application assemblies,
candidate racing, live-authority,
tunnel, raw QUIC, WebTransport, datagrams and controller assembly remain outside
this Rust client entrance. See [Rust transport v4](RUST_TRANSPORT_V4.md).

## Cross-language semantics

Go preserves RPC error message presence with `RPCError.MessagePresent`, so a missing message remains distinguishable from an explicitly empty message. Swift exposes the same distinction through optional `RPCError.message`.

A failed DATA, FIN, or stream-rekey write makes that stream terminal because its wire commit boundary is no longer reusable; unrelated streams remain live unless the failed record is required to complete a session rekey. Rekey-assisted receive processing never crosses unread DATA. Rust and TypeScript bound that auxiliary receive queue by the shared `e2ee.max_inbound_buffered_bytes` high-water mark and pause carrier reads until the application consumes buffered DATA.

Remote application RPC failures are semantically separate from session and transport failures across the SDKs. An application error requires a nonzero code, an exact `code`/optional `message` shape, and, when present, a valid UTF-8 message of at most 1024 bytes. Invalid inbound errors fail at the existing session or protocol boundary; invalid outbound handler errors are replaced by the SDK's existing internal application error before wire I/O. The expression is language-native rather than byte-for-byte identical: TypeScript uses typed `RpcResult<Response>` with an `ok: false` application `error`, Go returns `flowersec.RPCError`, Swift throws `RPCError`, and Rust returns `RpcCallError::Application`. Application RPC error-code taxonomies remain SDK-local, while public connection, session, and controller codes remain the shared cross-language values. The portable contract is the RPC application/session boundary plus structured controller dispositions. Session, stream, carrier, handshake, and credential-spend failures remain redacted public connection or session failures instead of application RPC failures.

Application stream metadata is a construction-validated value in every SDK. Invalid JSON shape, number, depth, or size fails before `openStream`/`open_stream`; incoming streams expose the same validated value model. Each language uses its native constructor and immutable/read-only access conventions.

Unreliable messages are an SDK-profile capability, not a mandatory method shape for every language. Go exposes `flowersec.UnreliableMessageChannel`, TypeScript exposes `UnreliableMessageChannel`, and Rust exposes `UnreliableMessageChannel` when the session negotiated support. Their public failures normalize to `unavailable`, `invalid_message`, `too_large`, `canceled`, `closed`, and `operation_failed`; send outcomes remain `accepted`, `dropped_expired`, `dropped_budget`, and `dropped_carrier`. Swift explicitly reports the capability as unsupported and exposes no placeholder channel.

## Error Boundary

Public connection and session failures contain only a stable code. They never retain raw artifacts, credential-bearing URLs, tokens, peer payloads, candidate diagnostics, path or stage selection, key material, carrier handles, or implementation objects. `ConnectionDiagnostic` is the only monitoring projection: it contains state, attempt, optional failure phase/code, and optional retry disposition, and never contains a URL, carrier, candidate, raw error, credential, peer identity, or Session. Snapshot, update, and subscription APIs may coalesce intermediate states but always expose their latest state. Sanitized remote application RPC errors may retain only their bounded semantic code and message.

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

## Native HTTP application streams

`flowersec.ServeHTTPStream(...)` serves a single already-authorized ByteStream with
`flowersec.HTTPStreamOptions` header and idle admission limits. It owns HTTP
keep-alive, upgrades, and cancellation of hijacked connections without a listening
TCP port. Read deadline interruption preserves subsequent reads; write deadline
expiry terminates the stream. Product authorization and stream-kind registration
remain with the embedding application. There is no response-body transformation.

The Node-only `createByteStreamDuplex(...)` export adapts one ByteStream to a
bounded Node Duplex with half-close, 64 KiB write chunks, partial-write progress,
read backpressure, and abort/reset propagation. It never decodes HTTP or WebSocket
frames, reconnects, or replays application bytes. These embedding helpers do not
change wire identifiers, artifacts, or carrier selection.

The Node-only v4 `asNodeDuplex(...)` directly owns an accepted v4 Stream with a
finite producer profile and original Stream/Session resource admission.
`V4NodeDuplex`, `V4NodeDuplexOptions` and `V4NodeProducerProfile` describe its
native API and deployment bounds. `V4NodeDuplexError` carries a bounded
`V4NodeDuplexFailure` and stable partial write progress. Native writable finish
requires normal authenticated DRAINED; reverse reads continue independently.
Normal automatic cleanup is distinguished from caller destroy/abort, which
resets the Stream. Cleanup timeouts retain real native tails and report
`cleanup_incomplete`. See [the v4 Node adapter contract](TYPESCRIPT_TRANSPORT_V4.md#node-carrier-and-sqlite-store).

The v4 `asWebStreams(...)` export returns the standard pair described by
`V4WebStreams` and `V4WebStreamsOptions`, with exclusive original Stream I/O
ownership and finite native queue admission. `V4WebStreamError` exposes a bounded
`V4WebStreamFailure` and partial write progress. Readable cancel and writable
abort terminate their own direction; writable close requires authenticated
Finish while reverse reads continue. Standard pipe options keep their native
meaning. [The Web Streams contract](TYPESCRIPT_TRANSPORT_V4.md#closure-and-persistent-history)
describes the queue, backing and cleanup bounds.

## Go transport v4 environment and operations

The public Go v4 assembly is `flowersec.NewTransportEnvironment(...)`. Its
explicit clock, verification-continuity registry, executor, resource root and
same-root account handles are supplied by trusted host composition. The
Environment hosts immutable connection material and admits its original bounded
Session position before acquisition, carrier preparation and spend. Source,
static material and preauthorized pool inputs share that implementation.

`ConnectSource` takes an immutable identity plus an original lease provider;
`ConnectMaterial` consumes an Environment-hosted material; `ConnectPool` takes a
complete installed pool item after local admission. Pool acquisition never
starts a TopUp or falls back to live issuance. An uncertain or canceled Connect
cannot turn consumed material into a reusable attempt. Pool and live authority
inputs are explicit and mutually exclusive.

`V4Session` exposes authenticated `Info`, `Drain`/`WaitDrain`, `Rekey`,
`ProbeLiveness`, unary preparation, fixed-session service binding, and termination
and cleanup observation. `OperationHandle` retains the original request,
contract, publication and deferred result rights. Repeated Start joins the same
operation; TakeResult and TakeEncodedResult share one consumption right. Waiting
cancellation does not retry the operation or release active provider work.
`Cancel` ends local result interest; `RequestCancel` requests authenticated
business cancellation through the management path.

`V4MethodRoutes.InitialOffers` installs bounded, exact admission windows during
RPC assembly. `AdvertisedContract` selects one digest from that method's declared
contracts after its windows are installed. An execution advertisement requires a
currently usable window; construction does not issue or renew one. The immutable
connection recipe copies and charges these windows before material acquisition.

Durable service hosts use `V4SQLiteExecutions.ReadRegistration` to read the
original canonical contract and `V4SQLiteExecutionRegistration` from their
explicitly created or reopened execution database. The caller supplies bounded
contract storage and its original finite trusted registration guard. The result
contains the persisted revision, enabled state and at most eight unchanged
windows; it grants no execution rights. Hosts install only applicable original
windows and advertise only a currently usable one. Expired windows require an
explicit durable registration update before new admission can be advertised.
Reopening requires independent continuity evidence and never replays a handler.
`V4DurableServiceBinding` attaches the original durable owner to the shared
service registry; dispatch, duplicate joins and management reads use that owner.

Restart-flush unary handlers receive their original `ResponsePublication` before
execution and may transfer its observation once to the invocation's own
`MaintenanceOwner`. Only the original complete provider publication can report
flushed. Handler failure, STOP_OUTPUT, expiry, or owner unavailability cannot
manufacture that outcome.

`V4PreauthorizedPoolSource.TopUp` joins its one unresolved durable intent.
`RecoverPendingTopUps` reconstructs the original journal facts without appending
new material; `TopUpStatus` reads the exact opaque operation handle without
control I/O. Installed and acknowledged frontiers remain distinct. Caller wait
cancellation does not cancel the source worker. Source Close seals new work and
WaitCleanup joins actual provider tails.

Environment cleanup retires its metadata only after original Session, material,
source and provider obligations finish. Shared clocks, resource roots, executors,
trust stores and durable stores remain caller-owned. See
[Go transport v4 assembly](GO_TRANSPORT_V4.md) for construction and cleanup order.

The following table registers the current public v4 assembly, owner operations
and result vocabulary. Schema/provider qualification is a separate requirement
and is not implied by symbol availability.

| Symbol | Declaration |
| --- | --- |
| `(*flowersec.ConnectionMaterial).Close` | method |
| `(*flowersec.ConnectionMaterial).WaitCleanup` | method |
| `(*flowersec.MaintenanceOwner).Close` | method |
| `(*flowersec.NotificationSubscription).CleanupStatus` | method |
| `(*flowersec.NotificationSubscription).Close` | method |
| `(*flowersec.NotificationSubscription).WaitClosed` | method |
| `(*flowersec.OperationHandle).AbandonResult` | method |
| `(*flowersec.OperationHandle).Cancel` | method |
| `(*flowersec.OperationHandle).CleanupStatus` | method |
| `(*flowersec.OperationHandle).Close` | method |
| `(*flowersec.OperationHandle).Progress` | method |
| `(*flowersec.OperationHandle).Reference` | method |
| `(*flowersec.OperationHandle).RequestCancel` | method |
| `(*flowersec.OperationHandle).Start` | method |
| `(*flowersec.OperationHandle).StartContext` | method |
| `(*flowersec.OperationHandle).Status` | method |
| `(*flowersec.OperationHandle).TakeEncodedResult` | method |
| `(*flowersec.OperationHandle).TakeResult` | method |
| `(*flowersec.OperationHandle).TakeResultContext` | method |
| `(*flowersec.OperationHandle).WaitCleanup` | method |
| `(*flowersec.OperationHandle).WaitStatus` | method |
| `(*flowersec.ReaderCursor).Close` | method |
| `(*flowersec.ReaderCursor).Progress` | method |
| `(*flowersec.ReaderCursor).ReadExactly` | method |
| `(*flowersec.ReaderCursor).ReadLine` | method |
| `(*flowersec.ReaderCursor).ReadUntil` | method |
| `(*flowersec.ReaderCursor).TakePrefix` | method |
| `(*flowersec.ResponsePublication).State` | method |
| `(*flowersec.ResponsePublication).TransferTo` | method |
| `(*flowersec.ResponsePublication).Wait` | method |
| `(*flowersec.ServeHandle).CleanupStatus` | method |
| `(*flowersec.ServeHandle).Close` | method |
| `(*flowersec.ServeHandle).Drain` | method |
| `(*flowersec.ServeHandle).WaitCleanup` | method |
| `(*flowersec.ServeHandle).WaitDrain` | method |
| `(*flowersec.TransportEnvironment).Close` | method |
| `(*flowersec.TransportEnvironment).Connect` | method |
| `(*flowersec.TransportEnvironment).ConnectMaterial` | method |
| `(*flowersec.TransportEnvironment).WaitCleanup` | method |
| `(*flowersec.TypedMessageStream).CleanupStatus` | method |
| `(*flowersec.TypedMessageStream).Close` | method |
| `(*flowersec.TypedMessageStream).CloseWrite` | method |
| `(*flowersec.TypedMessageStream).Finish` | method |
| `(*flowersec.TypedMessageStream).Receive` | method |
| `(*flowersec.TypedMessageStream).ReceiveEncoded` | method |
| `(*flowersec.TypedMessageStream).Send` | method |
| `(*flowersec.TypedMessageStream).WaitCleanup` | method |
| `(*flowersec.V4AuthenticatedMaterial).Close` | method |
| `(*flowersec.V4AuthenticatedMaterial).WaitCleanup` | method |
| `(*flowersec.V4Environment).Close` | method |
| `(*flowersec.V4Environment).Connect` | method |
| `(*flowersec.V4Environment).ConnectMaterial` | method |
| `(*flowersec.V4Environment).ConnectMaterialLiveSQLite` | method |
| `(*flowersec.V4Environment).ConnectMaterialPool` | method |
| `(*flowersec.V4Environment).ConnectPool` | method |
| `(*flowersec.V4Environment).ConnectSource` | method |
| `(*flowersec.V4Environment).ConnectSourceLiveSQLite` | method |
| `(*flowersec.V4Environment).ConnectSourcePool` | method |
| `(*flowersec.V4Environment).CreateMaterial` | method |
| `(*flowersec.V4Environment).NewMaterialPool` | method |
| `(*flowersec.V4Environment).Snapshot` | method |
| `(*flowersec.V4Environment).WaitCleanup` | method |
| `(*flowersec.V4PreauthorizedPoolSource).Acquire` | method |
| `(*flowersec.V4PreauthorizedPoolSource).Close` | method |
| `(*flowersec.V4PreauthorizedPoolSource).GoString` | method |
| `(*flowersec.V4PreauthorizedPoolSource).MarshalJSON` | method |
| `(*flowersec.V4PreauthorizedPoolSource).RecoverPendingTopUps` | method |
| `(*flowersec.V4PreauthorizedPoolSource).String` | method |
| `(*flowersec.V4PreauthorizedPoolSource).TopUp` | method |
| `(*flowersec.V4PreauthorizedPoolSource).TopUpStatus` | method |
| `(*flowersec.V4PreauthorizedPoolSource).WaitCleanup` | method |
| `(*flowersec.V4ServiceClient).Call` | method |
| `(*flowersec.V4ServiceClient).Close` | method |
| `(*flowersec.V4ServiceClient).CleanupStatus` | method |
| `(*flowersec.V4ServiceClient).WaitCleanup` | method |
| `(*flowersec.V4ServiceClient).Dispatch` | method |
| `(*flowersec.V4ServiceClient).Prepare` | method |
| `(*flowersec.V4Session).BindService` | method |
| `(*flowersec.V4Session).CleanupStatus` | method |
| `(*flowersec.V4Session).Close` | method |
| `(*flowersec.V4Session).Drain` | method |
| `(*flowersec.V4Session).Info` | method |
| `(*flowersec.V4Session).OpenStream` | method |
| `(*flowersec.V4Session).PrepareUnary` | method |
| `(*flowersec.V4Session).ProbeLiveness` | method |
| `(*flowersec.V4Session).QueryOperation` | method |
| `(*flowersec.V4Session).Rekey` | method |
| `(*flowersec.V4Session).RequestOperationCancel` | method |
| `(*flowersec.V4Session).WaitCleanup` | method |
| `(*flowersec.V4Session).WaitDrain` | method |
| `(*flowersec.V4Session).WaitTermination` | method |
| `(*flowersec.WriteOperation).Cancel` | method |
| `(*flowersec.WriteOperation).CleanupStatus` | method |
| `(*flowersec.WriteOperation).Progress` | method |
| `(*flowersec.WriteOperation).Start` | method |
| `(*flowersec.WriteOperation).Wait` | method |
| `flowersec.ApplicationIdentity` | type |
| `flowersec.CleanupStatus` | type |
| `flowersec.CloseResult` | type |
| `flowersec.ConnectionMaterial` | type |
| `flowersec.ConnectionMaterialSource` | type |
| `flowersec.ConnectionMaterialSource.AcquireLease` | interface_method |
| `flowersec.ConnectionRequirements` | type |
| `flowersec.CopyOptions` | type |
| `flowersec.CopyResult` | type |
| `flowersec.CreateV4SQLite` | func |
| `flowersec.CreateV4SQLiteTopUpJournal` | func |
| `flowersec.DelimiterNotFound` | const |
| `flowersec.EncodeV4PoolMaterial` | func |
| `flowersec.ErrAlreadyStarted` | var |
| `flowersec.ErrCleanupIncomplete` | var |
| `flowersec.ErrOperationClosed` | var |
| `flowersec.ErrOperationNotStarted` | var |
| `flowersec.ErrPublicationAlreadyTransferred` | var |
| `flowersec.ErrPublicationExpired` | var |
| `flowersec.ErrPublicationInvalid` | var |
| `flowersec.ErrPublicationOwnerUnavailable` | var |
| `flowersec.ErrReadInProgress` | var |
| `flowersec.ErrResponseLimitUnsupported` | var |
| `flowersec.ErrResultAbandoned` | var |
| `flowersec.ErrResultAlreadyDelivered` | var |
| `flowersec.ErrTransportUnavailable` | var |
| `flowersec.ErrV4MaterialNotReady` | var |
| `flowersec.ErrV4SpendNotObserved` | var |
| `flowersec.ErrV4StorageFormat` | var |
| `flowersec.ErrV4StorageUnavailable` | var |
| `flowersec.MaintenanceOwner` | type |
| `flowersec.MessageSendAdmission` | type |
| `flowersec.MessageSendOptions` | type |
| `flowersec.MessageSendQueued` | const |
| `flowersec.MessageSendResult` | type |
| `flowersec.MessageSendTryNow` | const |
| `flowersec.MessageStreamDefinition` | type |
| `flowersec.NewConnectionMaterial` | func |
| `flowersec.NewTransportEnvironment` | func |
| `flowersec.NewV4Age` | func |
| `flowersec.NewV4ApplicationExecutor` | func |
| `flowersec.NewV4ApplicationIdentity` | func |
| `flowersec.NewV4ApplicationIdentityFromBytes` | func |
| `flowersec.NewV4ArtifactLease` | func |
| `flowersec.NewV4ArtifactLeaseFromBytes` | func |
| `flowersec.NewV4AuthenticatedMaterial` | func |
| `flowersec.NewV4Clock` | func |
| `flowersec.NewV4Deadline` | func |
| `flowersec.NewV4Environment` | func |
| `flowersec.NewV4NamespaceDurableBootstrap` | func |
| `flowersec.NewV4NamespaceOnlineBootstrap` | func |
| `flowersec.NewV4NamespaceTrustAnchor` | func |
| `flowersec.NewV4PoolHTTPSTransport` | func |
| `flowersec.NewV4PoolMaterialDecoder` | func |
| `flowersec.NewV4PoolResultDecoder` | func |
| `flowersec.NewV4PreauthorizedPoolSource` | func |
| `flowersec.NewV4PreparedMessages` | func |
| `flowersec.NewV4PreparedStream` | func |
| `flowersec.NewV4ResourceRoot` | func |
| `flowersec.NewV4SQLiteBacking` | func |
| `flowersec.NewV4SQLiteLiveMaintenance` | func |
| `flowersec.NewV4SQLiteLiveSpendRead` | func |
| `flowersec.NewV4ServiceRegistry` | func |
| `flowersec.NewV4SessionPlan` | func |
| `flowersec.NewV4StreamHandlerPlan` | func |
| `flowersec.NewV4UnaryRegistration` | func |
| `flowersec.NewV4VerificationNamespaces` | func |
| `flowersec.NotificationSubscription` | type |
| `flowersec.OpenV4SQLite` | func |
| `flowersec.OpenV4SQLiteTopUpJournal` | func |
| `flowersec.OperationAccepted` | const |
| `flowersec.OperationCompleted` | const |
| `flowersec.OperationExecuting` | const |
| `flowersec.OperationFailed` | const |
| `flowersec.OperationHandle` | type |
| `flowersec.OperationManagementResult` | type |
| `flowersec.OperationObservation` | type |
| `flowersec.OperationPending` | const |
| `flowersec.OperationProgress` | type |
| `flowersec.OperationReference` | type |
| `flowersec.OperationReference.GoString` | method |
| `flowersec.OperationReference.MarshalJSON` | method |
| `flowersec.OperationReference.String` | method |
| `flowersec.OperationReference.Valid` | method |
| `flowersec.OperationStartResult` | type |
| `flowersec.OperationStatus` | type |
| `flowersec.OperationUnknown` | const |
| `flowersec.PrepareOperation` | func |
| `flowersec.PublicationCause` | type |
| `flowersec.PublicationFlushed` | const |
| `flowersec.PublicationNotApplicable` | const |
| `flowersec.PublicationPending` | const |
| `flowersec.PublicationStatus` | type |
| `flowersec.PublicationUnknown` | const |
| `flowersec.ReadCause` | type |
| `flowersec.ReadMethodError` | type |
| `flowersec.ReadMethodFailure` | type |
| `flowersec.ReadProgress` | type |
| `flowersec.ReadResult` | type |
| `flowersec.ReaderCursor` | type |
| `flowersec.ReaderCursorOptions` | type |
| `flowersec.ReaderCursorSnapshot` | type |
| `flowersec.ResponsePublication` | type |
| `flowersec.ResponsePublicationState` | type |
| `flowersec.RestoreV4Namespace` | func |
| `flowersec.Result` | type |
| `flowersec.ServeHandle` | type |
| `flowersec.Stream` | type |
| `flowersec.Stream.AsTypedMessages` | interface_method |
| `flowersec.Stream.Close` | interface_method |
| `flowersec.Stream.CloseResult` | interface_method |
| `flowersec.Stream.CloseWrite` | interface_method |
| `flowersec.Stream.Copy` | interface_method |
| `flowersec.Stream.Finish` | interface_method |
| `flowersec.Stream.PrepareWrite` | interface_method |
| `flowersec.Stream.Read` | interface_method |
| `flowersec.Stream.ReaderCursor` | interface_method |
| `flowersec.Stream.Reset` | interface_method |
| `flowersec.Stream.Write` | interface_method |
| `flowersec.Stream.WriteAll` | interface_method |
| `flowersec.StreamAborted` | const |
| `flowersec.StreamEOF` | const |
| `flowersec.StreamError` | const |
| `flowersec.StreamMetadata.Bytes` | method |
| `flowersec.StreamOpen` | const |
| `flowersec.StreamStatus` | type |
| `flowersec.TopUpErrorProjection` | func |
| `flowersec.TransportEnvironment` | type |
| `flowersec.TransportEnvironmentOptions` | type |
| `flowersec.TypedMessageStream` | type |
| `flowersec.UnexpectedEOF` | const |
| `flowersec.V4AdmissionOffer` | type |
| `flowersec.V4ApplicationBinding` | type |
| `flowersec.V4ApplicationExecutor` | type |
| `flowersec.V4ApplicationExecutorCharge` | func |
| `flowersec.V4ApplicationExecutorConfig` | type |
| `flowersec.V4ApplicationIdentity` | type |
| `flowersec.V4ApplicationIdentityBytesConfig` | type |
| `flowersec.V4ApplicationIdentityCharge` | func |
| `flowersec.V4ApplicationIdentityConfig` | type |
| `flowersec.V4ApplicationLease` | type |
| `flowersec.V4ArtifactLease` | type |
| `flowersec.V4ArtifactLeaseBytesConfig` | type |
| `flowersec.V4ArtifactLeaseCharge` | func |
| `flowersec.V4ArtifactLeaseConfig` | type |
| `flowersec.V4AuthenticatedMaterial` | type |
| `flowersec.V4AuthenticatedRequestContext` | type |
| `flowersec.V4AuthorizationAuthorized` | const |
| `flowersec.V4AuthorizationDenied` | const |
| `flowersec.V4AuthorizationOutcome` | type |
| `flowersec.V4AuthorizationUnknown` | const |
| `flowersec.V4AuthorizeApplicationResult` | type |
| `flowersec.V4AutomaticLivenessPolicy` | type |
| `flowersec.V4CarrierAttemptBudget` | type |
| `flowersec.V4CarrierPreparationRequest` | type |
| `flowersec.V4ClientToServer` | const |
| `flowersec.V4Clock` | type |
| `flowersec.V4ClockMark` | type |
| `flowersec.V4ClockProfile` | type |
| `flowersec.V4ClockRate` | type |
| `flowersec.V4ClockTick` | type |
| `flowersec.V4ConnectOptions` | type |
| `flowersec.V4ConnectionGuarantees` | type |
| `flowersec.V4ConnectionMaterialCharge` | func |
| `flowersec.V4Connections` | const |
| `flowersec.V4ConsumerCarrierFactory` | type |
| `flowersec.V4ContractQueryMethod` | type |
| `flowersec.V4ContractRoutesConfig` | type |
| `flowersec.V4CredentialPolicy` | type |
| `flowersec.V4CredentialScope` | type |
| `flowersec.V4CredentialSubscriptionsCharge` | func |
| `flowersec.V4CredentialValidation` | type |
| `flowersec.V4Deadline` | type |
| `flowersec.V4DecodeContext` | type |
| `flowersec.V4Direction` | type |
| `flowersec.V4DirectionAccount` | const |
| `flowersec.V4DiskBytes` | const |
| `flowersec.V4DrainDeadlineAborted` | const |
| `flowersec.V4DrainFailed` | const |
| `flowersec.V4DrainOutcome` | type |
| `flowersec.V4DrainPending` | const |
| `flowersec.V4DrainResult` | type |
| `flowersec.V4Drained` | const |
| `flowersec.V4DurableRestore` | const |
| `flowersec.V4EngineResourceOptions` | type |
| `flowersec.V4Environment` | type |
| `flowersec.V4EnvironmentAccount` | const |
| `flowersec.V4EnvironmentCharge` | func |
| `flowersec.V4EnvironmentConfig` | type |
| `flowersec.V4EnvironmentSnapshot` | type |
| `flowersec.V4EstablishmentCharge` | func |
| `flowersec.V4EstablishmentLimits` | type |
| `flowersec.V4FeatureEnvelope` | type |
| `flowersec.V4HTTPSBootstrapCharge` | func |
| `flowersec.V4HTTPSBootstrapConfig` | type |
| `flowersec.V4HelloLimits` | type |
| `flowersec.V4HelloPolicy` | type |
| `flowersec.V4IdentitySigner` | type |
| `flowersec.V4InitialConfig` | type |
| `flowersec.V4InitialHello` | type |
| `flowersec.V4InitialLimits` | type |
| `flowersec.V4InitialMessages` | type |
| `flowersec.V4IssuerPermission` | type |
| `flowersec.V4Items` | const |
| `flowersec.V4LiveActivationFields` | type |
| `flowersec.V4LiveMaintenanceConfig` | type |
| `flowersec.V4LiveMaintenanceStatus` | type |
| `flowersec.V4LiveNamespace` | type |
| `flowersec.V4LiveProofVerification` | type |
| `flowersec.V4LiveSessionInput` | type |
| `flowersec.V4LiveSpendOwner` | type |
| `flowersec.V4LiveSpendReadAccess` | type |
| `flowersec.V4LiveSpendReadTarget` | type |
| `flowersec.V4LiveSpendRetirement` | type |
| `flowersec.V4LiveSpendRetirementPolicy` | type |
| `flowersec.V4LivenessResult` | type |
| `flowersec.V4MaintenanceIngressPolicy` | type |
| `flowersec.V4MaintenanceMessagePolicy` | type |
| `flowersec.V4MaintenanceReserve` | type |
| `flowersec.V4MapSigner` | type |
| `flowersec.V4MaterialAcquisitionCharge` | func |
| `flowersec.V4MaterialConnectConfig` | type |
| `flowersec.V4MaterialGeneration` | type |
| `flowersec.V4MaterialLeaseProvider` | type |
| `flowersec.V4MaterialLeaseRequest` | type |
| `flowersec.V4MaterialPool` | type |
| `flowersec.V4MaterialPoolCharge` | func |
| `flowersec.V4MaterialPoolConfig` | type |
| `flowersec.V4MaterialRequirements` | type |
| `flowersec.V4MethodRoutes` | type |
| `flowersec.V4NamespaceAllocation` | type |
| `flowersec.V4NamespaceBootstrapCharge` | func |
| `flowersec.V4NamespaceBootstrapLimits` | type |
| `flowersec.V4NamespaceBootstrapProvider` | type |
| `flowersec.V4NamespaceBootstrapRequest` | type |
| `flowersec.V4NamespaceContent` | type |
| `flowersec.V4NamespaceContinuityLimits` | type |
| `flowersec.V4NamespaceContinuityScope` | type |
| `flowersec.V4NamespaceContinuityStore` | type |
| `flowersec.V4NamespaceContinuityVersion` | type |
| `flowersec.V4NamespaceDurabilityCharge` | func |
| `flowersec.V4NamespaceDurabilityConfig` | type |
| `flowersec.V4NamespaceOnlineBootstrap` | type |
| `flowersec.V4NamespaceRules` | type |
| `flowersec.V4NamespaceTrustCharge` | func |
| `flowersec.V4NamespaceTrustLimits` | type |
| `flowersec.V4NamespaceTrustRoot` | type |
| `flowersec.V4NamespaceTrustStore` | type |
| `flowersec.V4NativeHandles` | const |
| `flowersec.V4OnlineBootstrap` | const |
| `flowersec.V4OpenLimits` | type |
| `flowersec.V4OperationOptions` | type |
| `flowersec.V4PoolAccount` | const |
| `flowersec.V4PoolControlResultDecoder` | type |
| `flowersec.V4PoolHTTPSConfig` | type |
| `flowersec.V4PoolHTTPSTransport` | type |
| `flowersec.V4PoolHTTPSTransportCharge` | func |
| `flowersec.V4PoolIdentityRestorer` | type |
| `flowersec.V4PoolLeaseDecoder` | type |
| `flowersec.V4PoolMaterialBundle` | type |
| `flowersec.V4PoolMaterialDecoder` | type |
| `flowersec.V4PoolMaterialDecoderCharge` | func |
| `flowersec.V4PoolMaterialDecoderConfig` | type |
| `flowersec.V4PoolResultDecoder` | type |
| `flowersec.V4PoolResultDecoderCharge` | func |
| `flowersec.V4PoolResultDecoderConfig` | type |
| `flowersec.V4PoolSessionInput` | type |
| `flowersec.V4PoolSourceCharge` | func |
| `flowersec.V4PoolSourceConfig` | type |
| `flowersec.V4PoolSpendFacts` | type |
| `flowersec.V4PreauthorizedPoolSource` | type |
| `flowersec.V4PreparedCarrier` | type |
| `flowersec.V4PreparedCarrierCharge` | func |
| `flowersec.V4PreparedCarrierConfig` | type |
| `flowersec.V4ProviderBytes` | const |
| `flowersec.V4QueryBinding` | type |
| `flowersec.V4RPCServicesConfig` | type |
| `flowersec.V4RPCServicesRequirements` | func |
| `flowersec.V4RawStreamHandlerConfig` | type |
| `flowersec.V4RekeyPhaseBudgets` | type |
| `flowersec.V4RequiredGuarantees` | type |
| `flowersec.V4ResourceAccount` | type |
| `flowersec.V4ResourceAccountKey` | type |
| `flowersec.V4ResourceAccountKind` | type |
| `flowersec.V4ResourceConfig` | type |
| `flowersec.V4ResourceOwnerKey` | type |
| `flowersec.V4ResourceReference` | type |
| `flowersec.V4ResourceRequest` | type |
| `flowersec.V4ResourceRoot` | type |
| `flowersec.V4ResourceVector` | type |
| `flowersec.V4SDKBytes` | const |
| `flowersec.V4SQLiteBacking` | type |
| `flowersec.V4SQLiteBackingCharge` | func |
| `flowersec.V4SQLiteContinuity` | type |
| `flowersec.V4SQLiteIdentity` | type |
| `flowersec.V4SQLiteLimits` | type |
| `flowersec.V4SQLiteLiveAuthority` | type |
| `flowersec.V4SQLiteLiveMaintenance` | type |
| `flowersec.V4SQLiteLiveMaintenanceCharge` | func |
| `flowersec.V4SQLiteLiveSpendCharges` | func |
| `flowersec.V4SQLiteLiveSpendRead` | type |
| `flowersec.V4SQLiteLiveSpendReadCharge` | func |
| `flowersec.V4SQLitePoolAuthority` | type |
| `flowersec.V4SQLitePoolSpendCharge` | func |
| `flowersec.V4SQLiteStore` | type |
| `flowersec.V4SQLiteStoreCharge` | func |
| `flowersec.V4SQLiteTopUpAuthority` | type |
| `flowersec.V4SQLiteTopUpConfig` | type |
| `flowersec.V4SQLiteTopUpJournal` | type |
| `flowersec.V4SQLiteTopUpJournalCharge` | func |
| `flowersec.V4ServeConfig` | type |
| `flowersec.V4ServeGroup` | type |
| `flowersec.V4ServerToClient` | const |
| `flowersec.V4ServiceBinding` | type |
| `flowersec.V4ServiceClient` | type |
| `flowersec.V4ServiceRegistry` | type |
| `flowersec.V4ServiceRegistryCharge` | func |
| `flowersec.V4ServiceRegistryConfig` | type |
| `flowersec.V4Session` | type |
| `flowersec.V4SessionAccount` | const |
| `flowersec.V4SessionAdmissionConfig` | type |
| `flowersec.V4SessionAdmissionRequirements` | func |
| `flowersec.V4SessionCoreConfig` | type |
| `flowersec.V4SessionInfo` | type |
| `flowersec.V4SessionPlan` | type |
| `flowersec.V4SessionPlanCharge` | func |
| `flowersec.V4SessionPlanConfig` | type |
| `flowersec.V4SessionPlanFactory` | type |
| `flowersec.V4SessionPlanFactory.Create` | method |
| `flowersec.V4SessionRekeyInProgress` | const |
| `flowersec.V4SessionResourceScope` | type |
| `flowersec.V4SessionStreamConfig` | type |
| `flowersec.V4SessionStreamHandlerConfig` | type |
| `flowersec.V4SessionTimeUnavailable` | const |
| `flowersec.V4Sessions` | const |
| `flowersec.V4SharedDiscardPolicy` | type |
| `flowersec.V4SignedMap` | type |
| `flowersec.V4SignedMapCodec` | type |
| `flowersec.V4SourceConnectConfig` | type |
| `flowersec.V4SourceLiveIssuance` | type |
| `flowersec.V4SourcePreparationCharge` | func |
| `flowersec.V4SpendConsumed` | const |
| `flowersec.V4SpendReceipt` | type |
| `flowersec.V4SpendSpending` | const |
| `flowersec.V4SpendState` | type |
| `flowersec.V4StaticDH` | type |
| `flowersec.V4StorageFormatBackend` | const |
| `flowersec.V4StorageFormatError` | type |
| `flowersec.V4StorageFormatIdentity` | const |
| `flowersec.V4StorageFormatManifest` | const |
| `flowersec.V4StorageFormatNewer` | const |
| `flowersec.V4StorageFormatOlder` | const |
| `flowersec.V4StorageFormatProjection` | type |
| `flowersec.V4StorageFormatReason` | type |
| `flowersec.V4StorageFormatRevisionConflict` | const |
| `flowersec.V4StorageFormatState` | const |
| `flowersec.V4StorageRevision` | type |
| `flowersec.V4StreamHandlerPlan` | type |
| `flowersec.V4StreamHandlerPlanCharge` | func |
| `flowersec.V4StreamHandlerPlanConfig` | type |
| `flowersec.V4StreamOwnership` | type |
| `flowersec.V4StreamTerminationPolicy` | type |
| `flowersec.V4TLSHandshakes` | const |
| `flowersec.V4Tasks` | const |
| `flowersec.V4TenantAccount` | const |
| `flowersec.V4TimeInterval` | type |
| `flowersec.V4Timers` | const |
| `flowersec.V4TopUpAccess` | type |
| `flowersec.V4TopUpAcked` | const |
| `flowersec.V4TopUpControlTransport` | type |
| `flowersec.V4TopUpEntryFacts` | type |
| `flowersec.V4TopUpError` | type |
| `flowersec.V4TopUpErrorCode` | type |
| `flowersec.V4TopUpErrorCodeCapacityExhausted` | const |
| `flowersec.V4TopUpErrorCodeConfigurationCapacity` | const |
| `flowersec.V4TopUpErrorCodeFutureGeneration` | const |
| `flowersec.V4TopUpErrorCodeFutureOperation` | const |
| `flowersec.V4TopUpErrorCodeOperationConflict` | const |
| `flowersec.V4TopUpErrorCodePermissionDenied` | const |
| `flowersec.V4TopUpErrorCodeRelinkRequired` | const |
| `flowersec.V4TopUpErrorCodeSequenceGap` | const |
| `flowersec.V4TopUpErrorCodeSourceContractInvalid` | const |
| `flowersec.V4TopUpErrorCodeSourceExhausted` | const |
| `flowersec.V4TopUpErrorCodeSourceResetRequired` | const |
| `flowersec.V4TopUpErrorCodeSourceStateUnknown` | const |
| `flowersec.V4TopUpErrorCodeSourceUnavailable` | const |
| `flowersec.V4TopUpErrorCodeSpentUnknown` | const |
| `flowersec.V4TopUpErrorCodeStaleGeneration` | const |
| `flowersec.V4TopUpErrorCodeStaleOperation` | const |
| `flowersec.V4TopUpErrorCodeTopUpRequestExpired` | const |
| `flowersec.V4TopUpErrorScope` | type |
| `flowersec.V4TopUpErrorScopeOperation` | const |
| `flowersec.V4TopUpErrorScopeRequest` | const |
| `flowersec.V4TopUpErrorScopeSource` | const |
| `flowersec.V4TopUpExchangeResult` | type |
| `flowersec.V4TopUpFailure` | type |
| `flowersec.V4TopUpFenceAuthority` | type |
| `flowersec.V4TopUpFenceProvider` | type |
| `flowersec.V4TopUpHandle` | type |
| `flowersec.V4TopUpIdentityProvider` | type |
| `flowersec.V4TopUpInstalled` | const |
| `flowersec.V4TopUpOptions` | type |
| `flowersec.V4TopUpPending` | const |
| `flowersec.V4TopUpPermanentFenceEvidence` | type |
| `flowersec.V4TopUpPermanentFenceReceipt` | type |
| `flowersec.V4TopUpRecoveryResult` | type |
| `flowersec.V4TopUpRequestFacts` | type |
| `flowersec.V4TopUpResponseFacts` | type |
| `flowersec.V4TopUpResult` | type |
| `flowersec.V4TopUpServerSnapshot` | type |
| `flowersec.V4TopUpState` | type |
| `flowersec.V4TopUpTerminal` | const |
| `flowersec.V4TopUpTerminalEvidence` | type |
| `flowersec.V4TopUpWireResult` | type |
| `flowersec.V4TopUpWireResultCapacityExhausted` | const |
| `flowersec.V4TopUpWireResultConfigurationCapacity` | const |
| `flowersec.V4TopUpWireResultFutureGeneration` | const |
| `flowersec.V4TopUpWireResultFutureOperation` | const |
| `flowersec.V4TopUpWireResultOperationConflict` | const |
| `flowersec.V4TopUpWireResultPermissionDenied` | const |
| `flowersec.V4TopUpWireResultRelinkRequired` | const |
| `flowersec.V4TopUpWireResultReplay` | const |
| `flowersec.V4TopUpWireResultSequenceGap` | const |
| `flowersec.V4TopUpWireResultSourceContractInvalid` | const |
| `flowersec.V4TopUpWireResultSourceExhausted` | const |
| `flowersec.V4TopUpWireResultSourceResetRequired` | const |
| `flowersec.V4TopUpWireResultSourceStateUnknown` | const |
| `flowersec.V4TopUpWireResultSourceUnavailable` | const |
| `flowersec.V4TopUpWireResultSpentUnknown` | const |
| `flowersec.V4TopUpWireResultStaleGeneration` | const |
| `flowersec.V4TopUpWireResultStaleOperation` | const |
| `flowersec.V4TopUpWireResultSuccess` | const |
| `flowersec.V4TopUpWireResultTopUpRequestExpired` | const |
| `flowersec.V4TopUpWriteAction` | type |
| `flowersec.V4TopUpWriteActionNone` | const |
| `flowersec.V4TopUpWriteActionTerminal` | const |
| `flowersec.V4UnaryCodec` | type |
| `flowersec.V4UnaryMethod` | type |
| `flowersec.V4UnaryRegistration` | type |
| `flowersec.V4UnaryRequest` | type |
| `flowersec.V4UnaryRequest.MaintenanceOwner` | method |
| `flowersec.V4UnaryRequest.ResponsePublication` | method |
| `flowersec.V4UnaryResponse` | type |
| `flowersec.V4UnaryResultDecoder` | type |
| `flowersec.V4VerificationContinuity` | type |
| `flowersec.V4VerificationNamespaces` | type |
| `flowersec.V4VerificationNamespacesCharge` | func |
| `flowersec.V4VerificationNamespacesConfig` | type |
| `flowersec.V4WorkClass` | type |
| `flowersec.V4WorkResident` | const |
| `flowersec.V4WorkShort` | const |
| `flowersec.V4WorkSlots` | const |
| `flowersec.WriteOperation` | type |
| `flowersec.WriteOptions` | type |
| `flowersec.WritePhase` | type |
| `flowersec.WritePrepared` | const |
| `flowersec.WriteProgress` | type |
| `flowersec.WriteRunning` | const |
| `flowersec.WriteTerminal` | const |

`(*flowersec.V4Session).CleanupStatus` projects the original Session cleanup
observation. `flowersec.ErrCleanupIncomplete` means the fixed cleanup observation
deadline elapsed while physical work remains owned and charged; later observations
can report actual completion. Canceling one wait does not close or restart cleanup.

## Go v4 owners and control adapters

These entries expose bounded original owners, connection assembly, authenticated
control transports, issuance authorities and read-only authorization facts. Each
capability retains its own admission and lifecycle gates. A receipt or reconciled
fact never grants callback dispatch or connection activation. See
[Go transport v4 assembly](GO_TRANSPORT_V4.md) for construction and cleanup.

| Symbol | Declaration |
| --- | --- |
| `(*flowersec.V4LiveAuthoritySource).AcquireLease` | method |
| `(*flowersec.V4LiveAuthoritySource).Close` | method |
| `(*flowersec.V4LiveAuthoritySource).GoString` | method |
| `(*flowersec.V4LiveAuthoritySource).MarshalJSON` | method |
| `(*flowersec.V4LiveAuthoritySource).PreparationNamespaceSet` | method |
| `(*flowersec.V4LiveAuthoritySource).String` | method |
| `(*flowersec.V4LiveAuthoritySource).WaitCleanup` | method |
| `(*flowersec.V4MaterialAcquisition).Acquire` | method |
| `(*flowersec.V4MaterialAcquisition).Close` | method |
| `(*flowersec.V4MaterialAcquisition).WaitCleanup` | method |
| `(*flowersec.V4Session).AcceptStream` | method |
| `(*flowersec.V4StreamingResponse).SaveContent` | method |
| `flowersec.NewStreamMetadataFromBytes` | func |
| `flowersec.NewV4ArtifactIssueSource` | func |
| `flowersec.NewV4CarrierSet` | func |
| `flowersec.NewV4LiveAuthorityMaterialAcquisition` | func |
| `flowersec.NewV4LiveAuthoritySource` | func |
| `flowersec.NewV4MaintenanceOwner` | func |
| `flowersec.NewV4MaterialAcquisition` | func |
| `flowersec.NewV4PreauthorizedPoolMaterialAcquisition` | func |
| `flowersec.NewV4PreparedRelayMessages` | func |
| `flowersec.NewV4PreparedRelayStream` | func |
| `flowersec.NewV4RelayHop` | func |
| `flowersec.NewV4RelayMessagePair` | func |
| `flowersec.NewV4RelayPair` | func |
| `flowersec.NewV4RelayParentProjection` | func |
| `flowersec.NewV4SQLiteRelayAuthorityTable` | func |
| `flowersec.NewV4SQLiteRelayAuthorityTableContext` | func |
| `flowersec.NewV4TunnelAcceptedEntrance` | func |
| `flowersec.NewV4TunnelServerAllowHTTPSService` | func |
| `flowersec.NewV4TunnelServerAllowHTTPSTransport` | func |
| `flowersec.NewV4TunnelServerAllowRecipient` | func |
| `flowersec.NewV4TunnelServerAllowRegistration` | func |
| `flowersec.V4AcceptedEntrance` | type |
| `flowersec.V4ActivationAuthority` | type |
| `flowersec.V4ActivationTrustBinding` | type |
| `flowersec.V4ArtifactIssueSource` | type |
| `flowersec.V4ArtifactIssueSourceCharge` | func |
| `flowersec.V4ArtifactIssueSourceConfig` | type |
| `flowersec.V4ArtifactIssueSourceTunnel` | type |
| `flowersec.V4ArtifactLeaseTunnel` | type |
| `flowersec.V4ArtifactLeaseTunnelBytes` | type |
| `flowersec.V4CarrierEndpoint` | type |
| `flowersec.V4CarrierSet` | type |
| `flowersec.V4CarrierSetCharge` | func |
| `flowersec.V4CarrierSetConfig` | type |
| `flowersec.V4ContentObservation` | type |
| `flowersec.V4IncomingStream` | type |
| `flowersec.V4LiveAuthoritySource` | type |
| `flowersec.V4LiveGrantPreparation` | type |
| `flowersec.V4LiveServerAllowConfig` | type |
| `flowersec.V4LiveTunnelAuthorizationProvider` | type |
| `flowersec.V4MaintenanceOwnerCharge` | func |
| `flowersec.V4MaterialAcquisition` | type |
| `flowersec.V4MaterialNamespaceProvider` | type |
| `flowersec.V4MaterialNamespaceSet` | type |
| `flowersec.V4MaterialNamespaceSetProvider` | type |
| `flowersec.V4PoolTunnelMaterial` | type |
| `flowersec.V4PoolTunnelTrust` | type |
| `flowersec.V4RawStreamMetadataContract` | type |
| `flowersec.V4RawStreamMetadataField` | type |
| `flowersec.V4RawStreamMetadataType` | type |
| `flowersec.V4RelayClaimFacts` | type |
| `flowersec.V4RelayClaimFields` | type |
| `flowersec.V4RelayDeploymentBinding` | type |
| `flowersec.V4RelayGrantIssuer` | type |
| `flowersec.V4RelayGrantLimits` | type |
| `flowersec.V4RelayHop` | type |
| `flowersec.V4RelayHopCharges` | func |
| `flowersec.V4RelayHopConfig` | type |
| `flowersec.V4RelayHopReservations` | type |
| `flowersec.V4RelayIssuerMapping` | type |
| `flowersec.V4RelayMessagePair` | type |
| `flowersec.V4RelayMessagePairCharge` | func |
| `flowersec.V4RelayMessagePairConfig` | type |
| `flowersec.V4RelayPair` | type |
| `flowersec.V4RelayPairCharge` | func |
| `flowersec.V4RelayPairConfig` | type |
| `flowersec.V4RelayParentKey` | type |
| `flowersec.V4RelayParentProjection` | type |
| `flowersec.V4RelayParentProjectionBackingBytes` | func |
| `flowersec.V4RelayParentSelection` | type |
| `flowersec.V4SQLiteCommittedRelayLeg` | type |
| `flowersec.V4SQLiteCommittedRelayLegCharge` | func |
| `flowersec.V4SQLiteLiveRelayPublicationCharge` | func |
| `flowersec.V4SQLiteLiveRelayPublicationConfig` | type |
| `flowersec.V4SQLiteRelayAuthority` | type |
| `flowersec.V4SQLiteRelayAuthorityCharge` | func |
| `flowersec.V4SQLiteRelayAuthorityConfig` | type |
| `flowersec.V4SQLiteRelayAuthorityTable` | type |
| `flowersec.V4SQLiteRelayParentRegistration` | type |
| `flowersec.V4SourceCarrierCharge` | func |
| `flowersec.V4TunnelAcceptedEntranceRequirements` | func |
| `flowersec.V4TunnelServerAllowConfig` | type |
| `flowersec.V4TunnelServerAllowEndpoint` | type |
| `flowersec.V4TunnelServerAllowHTTPSConfig` | type |
| `flowersec.V4TunnelServerAllowHTTPSService` | type |
| `flowersec.V4TunnelServerAllowHTTPSServiceCharge` | func |
| `flowersec.V4TunnelServerAllowHTTPSServiceConfig` | type |
| `flowersec.V4TunnelServerAllowHTTPSTransport` | type |
| `flowersec.V4TunnelServerAllowHTTPSTransportCharge` | func |
| `flowersec.V4TunnelServerAllowPrepared` | type |
| `flowersec.V4TunnelServerAllowProvider` | type |
| `flowersec.V4TunnelServerAllowRecipient` | type |
| `flowersec.V4TunnelServerAllowRecipientCharge` | func |
| `flowersec.V4TunnelServerAllowRegistration` | type |
| `flowersec.V4TunnelServerAllowRegistrationCharges` | func |
| `flowersec.V4TunnelServerAllowRegistrationConfig` | type |
| `flowersec.V4TunnelServerAllowRequest` | type |
| `(*controlplane.V4ArtifactIssuer).Close` | method |
| `(*controlplane.V4ArtifactIssuer).GoString` | method |
| `(*controlplane.V4ArtifactIssuer).IssueArtifactBytes` | method |
| `(*controlplane.V4ArtifactIssuer).NamespaceClosure` | method |
| `(*controlplane.V4ArtifactIssuer).String` | method |
| `(*controlplane.V4ArtifactIssuer).WaitCleanup` | method |
| `(*controlplane.V4LiveRelayRegistrationService).CaptureRelayLeg` | method |
| `(*controlplane.V4LiveRelayRegistrationService).Close` | method |
| `(*controlplane.V4LiveRelayRegistrationService).WaitCleanup` | method |
| `controlplane.CreateV4SQLiteTopUpServer` | func |
| `controlplane.DeriveV4LiveGrantPreparation` | func |
| `controlplane.NewV4ArtifactIssueHTTPSService` | func |
| `controlplane.NewV4ArtifactIssuer` | func |
| `controlplane.NewV4LiveActivationPlan` | func |
| `controlplane.NewV4LiveArtifactHost` | func |
| `controlplane.NewV4LiveRelayRegistrationService` | func |
| `controlplane.NewV4PoolActivationPlan` | func |
| `controlplane.NewV4PoolBatchSigningIssuer` | func |
| `controlplane.NewV4PoolRelayFactory` | func |
| `controlplane.NewV4PoolService` | func |
| `controlplane.NewV4SQLiteLiveRelayPublication` | func |
| `controlplane.NewV4SQLitePoolRelayPublication` | func |
| `controlplane.NewV4TopUpCodec` | func |
| `controlplane.NewV4TunnelServerAllowHTTPSService` | func |
| `controlplane.OpenV4SQLiteTopUpServer` | func |
| `controlplane.V4ArtifactIssueAuthority` | type |
| `controlplane.V4ArtifactIssueFacts` | type |
| `controlplane.V4ArtifactIssueHTTPSConfig` | type |
| `controlplane.V4ArtifactIssueHTTPSService` | type |
| `controlplane.V4ArtifactIssueHTTPSServiceCharge` | func |
| `controlplane.V4ArtifactIssuePermit` | type |
| `controlplane.V4ArtifactIssueRequest` | type |
| `controlplane.V4ArtifactIssueRetention` | type |
| `controlplane.V4ArtifactIssuer` | type |
| `controlplane.V4ArtifactIssuerCharge` | func |
| `controlplane.V4ArtifactIssuerConfig` | type |
| `controlplane.V4ArtifactRetentionSlot` | type |
| `controlplane.V4ArtifactTunnelIssueConfig` | type |
| `controlplane.V4ArtifactTunnelLegIssueConfig` | type |
| `controlplane.V4AuthenticatedArtifactIssueClient` | func |
| `controlplane.V4LiveActivationConfig` | type |
| `controlplane.V4LiveActivationPlan` | type |
| `controlplane.V4LiveActivationPlanCharge` | func |
| `controlplane.V4LiveArtifactGrantConfig` | type |
| `controlplane.V4LiveArtifactHost` | type |
| `controlplane.V4LiveArtifactHostCharges` | func |
| `controlplane.V4LiveArtifactHostConfig` | type |
| `controlplane.V4LiveArtifactPolicy` | type |
| `controlplane.V4LiveArtifactServerMaterial` | type |
| `controlplane.V4LiveArtifactServerRegistration` | type |
| `controlplane.V4LiveArtifactServerResolver` | type |
| `controlplane.V4LiveArtifactTunnelConfig` | type |
| `controlplane.V4LiveGrantIssuance` | type |
| `controlplane.V4LiveGrantPreparationConfig` | type |
| `controlplane.V4LiveGrantProjection` | type |
| `controlplane.V4LiveRelayReadAccess` | type |
| `controlplane.V4LiveRelayRegistrationService` | type |
| `controlplane.V4LiveRelayRegistrationServiceCharges` | func |
| `controlplane.V4LiveServerAllowConfig` | type |
| `controlplane.V4LiveTunnelActivationConfig` | type |
| `controlplane.V4PoolActivationConfig` | type |
| `controlplane.V4PoolActivationPlan` | type |
| `controlplane.V4PoolActivationPlanCapacity` | func |
| `controlplane.V4PoolActivationPlanCharge` | func |
| `controlplane.V4PoolAttemptLimits` | type |
| `controlplane.V4PoolBatchIssuer` | type |
| `controlplane.V4PoolBatchSigningConfig` | type |
| `controlplane.V4PoolBatchSigningIssuer` | type |
| `controlplane.V4PoolBatchSigningIssuerCharge` | func |
| `controlplane.V4PoolIssuancePolicy` | type |
| `controlplane.V4PoolIssueResult` | type |
| `controlplane.V4PoolRelayFactory` | type |
| `controlplane.V4PoolRelayFactoryCharge` | func |
| `controlplane.V4PoolRelayFactoryConfig` | type |
| `controlplane.V4PoolRelayPublicationFactory` | type |
| `controlplane.V4PoolRelayRouteConfig` | type |
| `controlplane.V4PoolService` | type |
| `controlplane.V4PoolServiceCharge` | func |
| `controlplane.V4PoolServiceConfig` | type |
| `controlplane.V4PoolTunnelIssueConfig` | type |
| `controlplane.V4SQLiteLiveRelayPublication` | type |
| `controlplane.V4SQLiteLiveRelayPublicationCharge` | func |
| `controlplane.V4SQLiteLiveRelayPublicationConfig` | type |
| `controlplane.V4SQLitePoolRelayParent` | type |
| `controlplane.V4SQLitePoolRelayPublication` | type |
| `controlplane.V4SQLitePoolRelayPublicationCharge` | func |
| `controlplane.V4SQLitePoolRelayPublicationConfig` | type |
| `controlplane.V4SQLiteTopUpCommit` | type |
| `controlplane.V4SQLiteTopUpServer` | type |
| `controlplane.V4SQLiteTopUpServerAuthority` | type |
| `controlplane.V4SQLiteTopUpServerCharge` | func |
| `controlplane.V4SQLiteTopUpServerConfig` | type |
| `controlplane.V4TopUpAccess` | type |
| `controlplane.V4TopUpBatch` | type |
| `controlplane.V4TopUpCodec` | type |
| `controlplane.V4TopUpCodecBackingBytes` | func |
| `controlplane.V4TopUpIssueEntry` | type |
| `controlplane.V4TopUpRequestFacts` | type |
| `controlplane.V4TopUpServerCommitted` | const |
| `controlplane.V4TopUpServerEmpty` | const |
| `controlplane.V4TopUpServerPending` | const |
| `controlplane.V4TopUpServerRetired` | const |
| `controlplane.V4TopUpServerSnapshot` | type |
| `controlplane.V4TopUpServerTerminal` | const |
| `controlplane.V4TopUpSourceFence` | type |
| `controlplane.V4TunnelServerAllowHTTPSService` | type |
| `controlplane.V4TunnelServerAllowHTTPSServiceCharge` | func |
| `controlplane.V4TunnelServerAllowHTTPSServiceConfig` | type |
| `(*controlplane.SpendReceiptService).Close` | method |
| `(*controlplane.SpendReceiptService).QuerySpendReceiptBytes` | method |
| `(*controlplane.SpendReceiptService).QuerySpendReceipt` | method |
| `(*controlplane.SpendReceiptService).WaitCleanup` | method |
| `(*controlplane.V4DirectIssuer).Close` | method |
| `(*controlplane.V4DirectIssuer).GoString` | method |
| `(*controlplane.V4DirectIssuer).IssueArtifactBytes` | method |
| `(*controlplane.V4DirectIssuer).String` | method |
| `(*controlplane.V4DirectIssuer).WaitCleanup` | method |
| `(*flowersec.V4SQLiteLiveSpendRead).Cleanup` | method |
| `(*flowersec.V4SQLiteLiveSpendRead).Close` | method |
| `(*flowersec.V4SQLiteLiveSpendRead).Receipt` | method |
| `(*flowersec.V4SQLiteLiveSpendRead).ReconcileAuthorization` | method |
| `(*flowersec.V4SQLiteLiveSpendRead).RecoverExpired` | method |
| `controlplane.EncodeV4LiveAuthorizationRequest` | func |
| `controlplane.NewSpendReceiptService` | func |
| `controlplane.NewV4DirectIssueHTTPSService` | func |
| `controlplane.NewV4DirectIssuer` | func |
| `controlplane.NewV4LiveAuthorizationCodec` | func |
| `controlplane.NewV4LiveAuthorizationHTTPSService` | func |
| `controlplane.NewV4SQLiteDirectIssueAuthority` | func |
| `controlplane.SpendQueryFailure` | type |
| `controlplane.SpendReceiptServiceCharges` | func |
| `controlplane.SpendReceiptServiceConfig` | type |
| `controlplane.SpendReceiptService` | type |
| `controlplane.SpendReceipt` | type |
| `controlplane.V4AuthenticatedDirectIssueClient` | func |
| `controlplane.V4DirectIssueAuthority` | type |
| `controlplane.V4DirectIssueCommitted` | const |
| `controlplane.V4DirectIssueFacts` | type |
| `controlplane.V4DirectIssueHTTPSConfig` | type |
| `controlplane.V4DirectIssueHTTPSServiceCharge` | func |
| `controlplane.V4DirectIssueHTTPSService` | type |
| `controlplane.V4DirectIssueObligationState` | type |
| `controlplane.V4DirectIssuePermit` | type |
| `controlplane.V4DirectIssuePolicyConfig` | type |
| `controlplane.V4DirectIssuePolicyLimits` | type |
| `controlplane.V4DirectIssueRequest` | type |
| `controlplane.V4DirectIssueReserved` | const |
| `controlplane.V4DirectIssueRetired` | const |
| `controlplane.V4DirectIssuerCharge` | func |
| `controlplane.V4DirectIssuerConfig` | type |
| `controlplane.V4DirectIssuer` | type |
| `controlplane.V4IssueFailure.Error` | method |
| `controlplane.V4IssueFailure` | type |
| `controlplane.V4LiveAuthorizationAccess` | type |
| `controlplane.V4LiveAuthorizationCodecBackingBytes` | func |
| `controlplane.V4LiveAuthorizationCodec` | type |
| `controlplane.V4LiveAuthorizationHTTPSConfig` | type |
| `controlplane.V4LiveAuthorizationHTTPSServiceCharges` | func |
| `controlplane.V4LiveAuthorizationHTTPSService` | type |
| `controlplane.V4LiveAuthorizationHost` | type |
| `controlplane.V4LiveAuthorizationMaterial` | type |
| `controlplane.V4LiveAuthorizationRequest` | type |
| `controlplane.V4SQLiteDirectIssueAccess` | type |
| `controlplane.V4SQLiteDirectIssueAuthority` | type |
| `controlplane.V4SQLiteDirectIssueCharge` | func |
| `controlplane.V4SQLiteDirectIssueConfig` | type |
| `controlplane.V4SQLiteDirectIssueHost` | type |
| `controlplane.V4SQLiteDirectIssuePublication` | type |
| `controlplane.V4SQLiteDirectIssueStatus` | type |
| `flowersec.NewV4DirectIssueSource` | func |
| `flowersec.NewV4LiveHTTPSTransport` | func |
| `flowersec.NewV4WebSocketCarrierFactory` | func |
| `flowersec.V4AuthorizationNotStarted` | const |
| `flowersec.V4DirectIssueSourceCharge` | func |
| `flowersec.V4DirectIssueSourceConfig` | type |
| `flowersec.V4DirectIssueSource` | type |
| `flowersec.V4LiveAuthorizationFact` | type |
| `flowersec.V4LiveAuthorizationProvider` | type |
| `flowersec.V4LiveAuthorizationQuery` | type |
| `flowersec.V4LiveAuthorizationRequest` | type |
| `flowersec.V4LiveControlCharge` | func |
| `flowersec.V4LiveControlConfig` | type |
| `flowersec.V4LiveHTTPSConfig` | type |
| `flowersec.V4LiveHTTPSTransportCharge` | func |
| `flowersec.V4LiveHTTPSTransport` | type |
| `flowersec.V4WebSocketCarrierFactoryCharge` | func |
| `flowersec.V4WebSocketCarrierFactory` | type |
| `flowersec.V4WebSocketFactoryConfig` | type |
| `flowersec.V4WebSocketProviderOptions` | type |
| `(*flowersec.ServeHandle).AcceptWebSocket` | method |
| `(*flowersec.V4Environment).Serve` | method |
| `flowersec.NewV4WebSocketServer` | func |
| `flowersec.V4AcceptedEntranceConfig` | type |
| `flowersec.V4AcceptedMaterialSource` | type |
| `flowersec.V4AcceptedMaterialSource.ResolveAcceptedMaterial` | interface_method |
| `flowersec.V4AcceptedSessionInput` | type |
| `flowersec.V4AcceptedWebSocketEndpoint` | type |
| `flowersec.V4AdmissionOwner` | type |
| `flowersec.V4SQLiteAdmissionAuthority` | type |
| `flowersec.V4ServeCharge` | func |
| `flowersec.V4ServeOptions` | type |
| `flowersec.V4WebSocketAcceptOptions` | type |
| `flowersec.V4WebSocketServer` | type |
| `flowersec.V4WebSocketServerCharge` | func |
| `flowersec.V4WebSocketServerConfig` | type |
| `flowersec.V4WebSocketUpgradeConfig` | type |
| `flowersec.V4QUICLimits` | type |
| `flowersec.V4QUICProviderOptions` | type |
| `flowersec.V4QUICFactoryConfig` | type |
| `flowersec.V4QUICCarrierFactory` | type |
| `flowersec.DefaultV4QUICLimits` | func |
| `flowersec.V4QUICCarrierFactoryCharge` | func |
| `flowersec.NewV4QUICCarrierFactory` | func |
| `(*flowersec.V4QUICCarrierFactory).PrepareCarrier` | method |
| `(*flowersec.V4QUICCarrierFactory).Close` | method |
| `(*flowersec.V4QUICCarrierFactory).WaitCleanup` | method |
| `flowersec.V4QUICServerConfig` | type |
| `flowersec.V4QUICServer` | type |
| `flowersec.V4QUICIngress` | type |
| `flowersec.V4QUICServerCharge` | func |
| `flowersec.NewV4QUICServer` | func |
| `(*flowersec.V4QUICServer).Accept` | method |
| `(*flowersec.V4QUICServer).Address` | method |
| `(*flowersec.V4QUICServer).Close` | method |
| `(*flowersec.V4QUICServer).WaitCleanup` | method |
| `(*flowersec.V4QUICIngress).Close` | method |
| `(*flowersec.V4QUICIngress).WaitCleanup` | method |
| `flowersec.V4QUICAcceptOptions` | type |
| `(*flowersec.ServeHandle).AcceptQUIC` | method |

## Go v4 Connection Controller

The Environment owns the optional Controller's current, candidate and one
retirement position. Source recipes transfer unused cleanup responsibility;
complete candidate headroom precedes Acquire. Verification waits reuse the
original attempt and namespace refresh owner. Initializer failure after entry
fences publication until explicit recovery. First-header publication is ordered
with current switching, and accepted tails stay on their original Session.
Public failures are redacted; cancellation and deadline identities remain stable.
See [Go transport v4 assembly](GO_TRANSPORT_V4.md#connection-controller) for
construction, retirement, ownership and the implemented dependency boundary.

| Symbol | Declaration |
| --- | --- |
| `flowersec.V4ControllerSource` | type |
| `flowersec.V4ControllerRequest` | type |
| `flowersec.V4ControllerPreparation` | type |
| `flowersec.V4ControllerRetirement` | type |
| `flowersec.V4ControllerReplaceOptions` | type |
| `flowersec.V4ControllerSourceError` | type |
| `flowersec.V4ControllerOptions` | type |
| `flowersec.V4ControllerReplaceResult` | type |
| `flowersec.V4ControllerSnapshot` | type |
| `flowersec.V4ConnectionController` | type |
| `flowersec.NewV4ControllerSourceError` | func |
| `flowersec.V4ControllerCharges` | func |
| `flowersec.V4ControllerDrain` | const |
| `flowersec.V4ControllerRetain` | const |
| `flowersec.ErrV4ControllerBusy` | var |
| `flowersec.ErrV4ControllerInitialization` | var |
| `flowersec.ErrV4RetirementCapacity` | var |
| `(*flowersec.V4Environment).NewConnectionController` | method |
| `(*flowersec.V4ConnectionController).Start` | method |
| `(*flowersec.V4ConnectionController).RetryNow` | method |
| `(*flowersec.V4ConnectionController).PrepareUnary` | method |
| `(*flowersec.V4ConnectionController).Dispatch` | method |
| `(*flowersec.V4ConnectionController).CaptureSession` | method |
| `(*flowersec.V4ConnectionController).WaitForSession` | method |
| `(*flowersec.V4ConnectionController).ReplaceSession` | method |
| `(*flowersec.V4ConnectionController).Snapshot` | method |
| `(*flowersec.V4ConnectionController).Close` | method |
| `(*flowersec.V4ConnectionController).WaitCleanup` | method |
| `(*flowersec.V4ConnectionController).CleanupStatus` | method |
| `flowersec.V4ControllerSource.PrepareConnection` | interface_method |

## TypeScript v4 owners and result registry

`createNodeWSSListener(...)` configures the single-use production Node WSS
listener consumed by `environment.serve(...)`. `createHandlerPlan(...)` captures
raw stream declarations and encoded service contracts with typed handlers.
Serve fixes `authorizeRequest`, `resolveHandlers`, `authorizeApplication`,
`onSession`, and `release` for the original listener lifetime. Authenticated
application authorization precedes the durable SQLite admission CAS; dual READY
precedes Session delivery. The opaque `ServeHandle` owns ingress, published
Sessions, and actual callback cleanup while borrowing its Environment. Its
Drain outcome and cleanup status remain separate. Startup failures are opaque
`ServeError` values with the original cleanup snapshot. See
`docs/TYPESCRIPT_TRANSPORT_V4.md` for lease and Release responsibilities.

`createV4TransportEnvironment(...)` owns resources, trusted time, credential
namespaces, material acquisition and Session lifetime. `configureV4NodeWSS(...)`
and `configureV4BrowserWSS(...)` install the actual direct WSS client entrance
for explicitly selected `preauthorized_pool` or `live_authority` activation and
the `transport` application profile, or explicit `services`/`execution` with
`V4ClientServicesConfig`. `configureV4BrowserWebTransport(...)`
installs the browser direct WebTransport entrance with the same identity,
material-source and admission owners and independent native application streams.
Its current public guarantees remain conservative; required independent
progress, input isolation, datagrams and consumer TLS inspection are refused.
`environment.connect(...)` consumes a registered source;
`environment.connectMaterial(...)` consumes already verified material once.
Connection requirements and Controller requirements are optional. Omitted
guarantee booleans default to `false`; an omitted application profile does not
select `transport`. The installed client captures its compiled application
profile and requests that exact profile from the source. An explicit mismatch
is rejected with `connection_requirement_unavailable` before acquisition.
Verified signed material is checked against the same profile before connecting
or spending it; incompatible material is released. Unsupported required
guarantees return `required_guarantee_unavailable` before acquisition or I/O.
Both return a Session only after actual pool TxA-P or verified live authority
authorization, HELLO/FSB/FSA, KKpsk0 Noise and authenticated dual READY.

The root, `./node` and `./browser` package entrances export the connection
configuration types. `V4NamespaceOptions` configures `client.namespace(...)`;
`V4CredentialPolicy` and `V4CredentialProvider` configure live or pool material
sources. The provider fills borrowed `V4CredentialBuffers` and returns
`V4CredentialLengths`, ending every borrow when its promise settles, including
after cancellation. The resulting `V4ConnectionMaterialSource` is accepted by
both `environment.connect(...)` and `createV4ConnectionController(...)`.

`V4LiveAuthorizationConfig` captures an independently authenticated host control
transport, finite concurrency and actual runtime/provider allowances.
`V4LiveAuthorizationProvider` receives one bounded `V4LiveAuthorizationRequest`
after carrier preparation and complete Session admission. The original attempt,
lease, identities and winner remain fixed. Its returned full signed proof is
independently validated before HELLO; an HTTP result or receipt alone is
insufficient. Live and pool sources do not fall back to one another. The SDK
does not implement an authority database inside a consumer, and the host must
provide the real authenticated control transport and authority durability.

`createV4BrowserLiveHTTPS` is the browser HTTPS control adapter.
`V4BrowserLiveHTTPSOptions` binds one authority, tenant, audience, explicit
bearer calling credential, expiry and bounded native/SDK allowances.
`V4BrowserLiveHTTPSDeployment` fixes the canonical endpoint and current
application origin with independent operator evidence for TLS 1.3, no early
data and observable response framing. Fetch omits cookies, refuses redirects
and performs one attempt. Signed activation validation remains in the original
credential owner. This is a controlled-terminator guarantee, not browser-side
inspection of the negotiated TLS version.

`V4Session.probeLiveness(...)` returns a finite `V4LivenessResult` with
`submitted`, `complete` and `elapsedMS`. Elapsed time starts at local acceptance
and includes queuing; an unavailable elapsed value is `null`. `V4LivenessError`
retains the same facts with a bounded `V4LivenessFailure`. Cancellation and
rekey interrupt only this wait; actual provider tails keep their original slot.
Eight independent owners are admitted, including one protected automatic slot
when an explicit `V4AutomaticLivenessPolicy` is configured. Automatic liveness
has no implicit default. Only complete timely publication followed by the full
response budget without known local stalls can count a miss.

`V4Session.drain` captures one original `V4DrainOperation`, with optional
`V4DrainOptions` whose `timeoutMS` is capped at thirty seconds. Repeated calls cannot
extend it. `V4DrainResult` preserves `V4DrainOutcome` (`pending`, `drained`,
`deadline_aborted` or `failed`) separately from actual cleanup status.
`V4DrainError` reports bounded observer failure; canceled waits do not reopen
admission. GOAWAY fixes the historical accepted frontier and pending OPENs
receive explicit rejection. Existing streams and necessary rekey continue.
`V4Session.waitCleanup` passively observes actual resource release, with one
five-second cleanup deadline after Close; deadline expiry reports incomplete
cleanup while retained native tails remain charged. Registered authorizers,
handlers and send encoders keep their execution permits and application
allowances until actual exit. Core I/O can finish independently, reported as
`core_cleanup: "complete"` with pending callbacks; the Environment then retains
only the compact cleanup owner and any independently authorized results.

`V4MessageStreamDefinition` binds opener/acceptor message directions through
`V4MessageDirection` and opaque `V4MessageCodec` values. Built-ins are
`v4BytesMessageCodec` and `v4UTF8MessageCodec`; `v4ApplicationMessageCodec`
captures explicit synchronous or asynchronous `V4ApplicationMessageCodec`
callbacks with a host allowance. The local execution choice does not change
the canonical definition or framing. `V4TypedMessageStream` is returned by
Session `openMessageStream`/`acceptMessageStream`, or by `asTypedMessages`
after exclusive conversion of a matching unused raw stream.

`V4MessageStreamOptions`, `V4MessageSendOptions` and
`V4MessageReceiveOptions` control the original adapter. `V4MessageSendResult`
keeps submission separate from cleanup; `V4MessageReceiveResult` keeps EOF
separate from empty payload and records `application_input_delivered` for
application decoding. `V4MessageStreamError` exposes a bounded
`V4MessageFailure`. Typed and encoded Receive use one cursor and one consumption
right. After an application decoder starts, encoded receive reports
`result_mode_conflict`; canceled typed waits join the same decode completion.
Complete private payloads retain original authorization after normal I/O exit.

`V4StreamRegistration` closes future raw or typed handler admission without
closing already accepted streams. `V4StreamRegistrationOptions` supplies
concurrency, work class, metadata policy and application allowance.
`V4StreamOpenAuthorizer`, `V4MessageStreamHandler` and `V4RawStreamHandler`
receive the original `V4ApplicationContext`, including its immutable
`V4AuthenticatedContext`. `V4ApplicationWaitOptions` carries explicit dependency
context for bounded cleanup waits. Root-shared ordinary and protected
Completion services retain actual running callbacks across cancellation.
Raw registrations may also provide a fixed `RawStreamMetadataContract`. The
contract names one metadata namespace/version and a data-only JSON field schema
with encoded/decoded caps. The runtime validates and projects the metadata
after OPEN authentication but before `authorizeOpen`; unknown, missing, or
mis-typed fields reject that pending stream through the ordinary rejection and
cleanup path. `StreamMetadata.descriptorValues()` exposes the immutable
projection to the authorizer and accepted handler while `encoded()` and
`byteValues()` retain detached copies of the original bytes. No custom decoder,
extra wire frame, or second registry is installed by this option.
See [typed message streams](TYPESCRIPT_TRANSPORT_V4.md#typed-message-streams)
for current limits, ownership and remaining qualification requirements.

The signed Session idle duration starts at the completed dual READY publication
gate. Only complete successful authenticated output or fully validated input
refreshes it. Zero disables the signed watchdog. An explicit positive local
idle policy may tighten the duration; rekey, drain and delayed timers do not
extend it. Local active stream capacity is bounded by the signed stream
allowance, the configured local limit and 1024.

| Current v4 client capability | Node | Browser |
| --- | --- | --- |
| Durable pool adapter | Actual SQLite transaction | Optional explicit host IndexedDB adapter with strict durability |
| TLS | TLS 1.3; signed CA or leaf-DER pin policy | Browser CA plus trusted immutable terminator/deployment binding |
| TLS guarantee | `consumer_enforced` | `controlled_terminator` |
| Application operations | Reliable streams, transient/execution unary clients, rekey, liveness and lifecycle | The same operations |
| Crypto profiles | X25519/ChaChaPoly/Ed25519 and P-256/AES256GCM/Ed25519 | The same two profiles |
| WSS guarantees | `shared_ordered`, `shared_failure_scope`, no datagram | The same WSS guarantees |

SQLite APIs are Node-only; IndexedDB APIs are browser-only. Both require an
independent trusted continuity authority, stable store identity, original
fencing epoch and unique tenant/issuer/lease consumption. They retain actual
native/store tails and cannot activate unknown commits through later readback.
The browser path requires extractable WebCrypto keys and an independently
configured deployment that enforces the actual TLS/Origin policy. It rejects
pin mode and required consumer TLS verification before consume. The optional
IndexedDB integration does not require ordinary users to configure a database;
a remote pool-consume service adapter is not implemented.

The Node entrypoint provides `createV4SQLiteExecutionBacking` and
`openV4SQLiteExecutionStore` for durable execution history and unary results.
The store uses its own `flowersec-v4-node-execution` format and requires explicit
provisioning, stable identity, finite storage limits and an independent
`V4SQLiteExecutionContinuity` host proof. Reopening requires proof that the
previous owner's real business work has settled or been fenced; a database
file alone is insufficient. Missing or incompatible history is rejected.

`V4SQLiteExecutionStore.installContract` persists the exact canonical contract
and finite Offer windows using an expected registry revision. `readRegistration`
copies that original body into caller-supplied storage and returns
`V4SQLiteExecutionRegistration` with the original revision and windows; it does
not extend admission. Use the store's original frozen `service` capability as
the handler's execution configuration and in management-only `executionServices`.
Copying the configuration does not copy storage authority. The same Environment
cannot replace an execution authority with another backend.

The original execution engine registers before handler entry, persists dispatch
before invoking business code, and commits the complete unary result before
response publication. An uncertain COMMIT fences that store instance. Explicit
reopen preserves committed results and marks unresolved dispatched work unknown;
it never recreates a Start capability or automatically reruns business work.
Imported references use the chosen Session's current permissions for Query,
Cancel and ordinary result reads. Notification and streaming execution restore
terminal metadata without replaying callbacks; streaming with content policy
`none` does not produce retained unary results. Application-error terminals are
committed after encoding validation and before publication. An authoritative
absence transaction above its domain floor returns `not_found`/`not_registered`
without creating a cancellation tombstone; absent records at or below that
floor remain `history_unknown`. Failed durable cancellation writes publish no
confirmed cancellation fact or cooperative signal. Result expiry removes the stored payload
without deleting identity/history; history collection advances its domain floor
in the same transaction as deletion. `close()` waits for the actual bound
execution owner; the backing retains disk charges until files are actually
removed and `releaseRemoved()` succeeds. SQLite execution and pool adapters
share bounded file/connection accounting, while keeping separate schemas and
transaction semantics. These Node adapters currently use synchronous SQLite;
independent scheduling and stall isolation are not qualified.

`createV4NodeLiveHTTPS` with `V4NodeLiveHTTPSOptions` supplies an Environment-owned
live control adapter for `liveAuthority`. It makes one direct mutual-TLS 1.3
POST to the independently configured authority's `/live/authorize` endpoint.
The bounded `live-authorization-1` request matches the Go control service.
Explicit CA trust, hostname/SAN, actual TLS version, client certificate and
trusted certificate time are checked before publication. It has no redirects,
automatic retries, ambient cookies, proxy or connection reuse. Response framing
is bounded HTTP/1.1 200 with an exact positive Content-Length and
`application/cbor`; signed proof verification remains with the original
credential owner. Cancellation retains request buffers and resource charges
until actual native callbacks and sockets exit. The adapter cannot be installed
in a different Environment.

These TypeScript v4 entrances do not implement raw QUIC, relay/listener roles,
datagrams, qualified independent stream progress, checkpoint/Resume,
restart-flush execution recovery, proxy integration or a v4 reconnect controller.
`V4Session.bindService(...)` returns a fixed-Session `V4ServiceClient` whose
`prepareOperation(...)` and `call(...)` share the original unary engine.
`V4ExecutionUnaryOperation.reference()` exposes a compact execution reference.
The chosen Session's `queryOperation` and `requestCancel` use the fixed M
channel with current identity and independent namespace permissions. Queries
return bounded result metadata. With the trusted fixed `resultRead` tuple,
`readOperationResult(reference)` returns an independently owned ordinary RPC
read. Its typed value is `Uint8Array` containing the original encoded result;
`takeEncodedResult()` exposes those bytes through the same once-only delivery
gate. It does not infer the original business error/success codec.
`createV4OperationReferenceCodec(environment)` exports/imports the canonical
reference without storage I/O. Import requires the expected local domain, and
Query/Cancel/read resolve it through the chosen Session's trusted
`services.referenceTargets` peer mappings. Import grants no Start or local
operation capability. Imported unary reads reserve the full 1 MiB result bound.
`createV4StaticServiceContracts` accepts complete canonical local
`ServiceContract` bodies and exact execution `AdmissionOffer` bytes for a
trusted definition/target. `bindService` can consume this source through
`contractSource`; all entries are decoded and checked before publication,
remote contract queries are not performed, and closing the source after Bind
is safe because the binding retains its original charged snapshots.

For observation notification methods, `V4ServiceClient.notify` composes the same
Prepare/Start/WaitSubmission/Close path. `prepareOperation` returns
`V4ObservationNotifyOperation`, exposing local submission and cleanup state with
no response or execution reference. Complete local `submitted` status does not
assert peer delivery or handler success. The Session owns the independently
framed fixed notification channel and its actual publication tails.

`V4Session.notifications.subscribe` returns a typed local
`V4NotificationSubscription` with serial delivery, isolated mutable decoding,
optional projection, observation status, idempotent Close/Unsubscribe and passive
bounded WaitClosed. Observation methods can be declared with trusted canonical
contracts without a business handler. `latest_pending` applies only to
observation methods and replaces only values that have not entered application
code. Closing a token retains its slot until actual callback cleanup completes.

Execution notification methods return `V4ExecutionNotifyOperation` from Prepare,
with the same submission lifecycle and a query-only execution reference.
PrepareAndSave composes the registered ReferenceStore before explicit Start.
The volatile receiver uses the original Environment execution key and current
authorization for one business dispatch and one observer fanout. Handler success
updates queryable execution state without allocating a response or result
payload; Query/Cancel use M and result reads reject notification references.

`V4ServiceClient.prepareAndSave` uses an optional
`createV4OperationReferenceStore(environment, policy, save)` adapter. Only a
confirmed durable create-or-compare and the original live delivery gate return
an operation; the caller then explicitly invokes Start. Unknown/conflict/rejected
saves and cancellation return bounded metadata and any query-only reference,
while actual callback tails retain their resources. The application backend
owns persistent quotas, expiration and deletion. A context already holding an
application execution permit is refused before encoding/store entry with
`admission_mode_incompatible`.
Trusted `services.executionDelegations` bind the current authenticated principal
to the original caller, namespace, direction, independent query/cancel grants
and a fixed trusted-time expiry. Incoming access also requires the current
certificate-bound identity and namespace permissions. A new authorized Session
can use the original reference without impersonating the caller or changing its
key. An incoming `executionServices` registration reuses the same Environment's
history and results without requiring another business handler.
A failed M channel can be reconstructed after
its original tasks, physical resources and retirement proof exit, within the
original recovery deadline and 16-allocation Session limit. Ordinary RPC reads
continue independently; complete native-provider saturation protection remains
unqualified.

`V4UnaryOperation` provides explicit Start, typed/encoded result collection,
metadata status and local Close. See the linked construction guide for result
ownership and the current application-profile qualification boundary.
Generated operation/result types describe observations, not executable support
or activation authority. Functional Chromium coverage uses explicit test trust;
public-CA deployment, independent continuity and Go/browser interoperability
remain separate qualifications. See
[TypeScript Transport v4](TYPESCRIPT_TRANSPORT_V4.md) for construction, cleanup
and the exact support boundary, and
[the implementation binding](TRANSPORT_V4_BINDING.md) for schema/release gates.

| Symbol | Package subpaths |
| --- | --- |
| `configureV4BrowserWSS` | `./browser` |
| `configureV4BrowserWebTransport` | `./browser` |
| `configureV4NodeWSS` | `./node` |
| `createV4NodeLiveHTTPS` | `./node` |
| `V4NodeLiveHTTPSOptions` | `./node` |
| `connectionAssurance` | `.`, `./node`, `./browser` |
| `createV4IndexedDBPoolBacking` | `./browser` |
| `createV4SQLiteExecutionBacking` | `./node` |
| `openV4SQLiteExecutionStore` | `./node` |
| `V4SQLiteExecutionBacking` | `./node` |
| `V4SQLiteExecutionStore` | `./node` |
| `V4ExecutionStoreError` | `./node` |
| `V4SQLiteExecutionLimits` | `./node` |
| `V4SQLiteExecutionIdentity` | `./node` |
| `V4SQLiteExecutionContinuity` | `./node` |
| `V4SQLiteExecutionOptions` | `./node` |
| `V4SQLiteExecutionRegistration` | `./node` |
| `V4DurableExecutionService` | `./node` |
| `createV4SQLitePoolBacking` | `./node` |
| `createV4TransportEnvironment` | `.`, `./node`, `./browser` |
| `openV4IndexedDBPoolStore` | `./browser` |
| `openV4SQLitePoolStore` | `./node` |
| `topUpErrorProjection` | `.`, `./node`, `./browser` |
| `transportV4APIResultsSchemaSHA256` | `.`, `./node`, `./browser` |
| `V4ApplicationProfile` | `.`, `./node`, `./browser` |
| `V4BoundStreamInputIsolation` | `.`, `./node`, `./browser` |
| `V4BrowserWSSClient` | `./browser` |
| `V4BrowserWSSClientConfig` | `./browser` |
| `V4BrowserWSSClientLimits` | `./browser` |
| `V4BrowserWSSDeployment` | `./browser` |
| `V4BrowserWSSOptions` | `./browser` |
| `V4BrowserWebTransportClient` | `./browser` |
| `V4BrowserWebTransportClientConfig` | `./browser` |
| `V4BrowserWebTransportClientLimits` | `./browser` |
| `V4BrowserWebTransportDeployment` | `./browser` |
| `V4BrowserWebTransportOptions` | `./browser` |
| `V4CleanupState` | `.`, `./node`, `./browser` |
| `V4CleanupStatus` | `.`, `./node`, `./browser` |
| `V4LifecycleObjectKind` | `.`, `./node`, `./browser` |
| `V4LifecycleState` | `.`, `./node`, `./browser` |
| `V4LifecycleReason` | `.`, `./node`, `./browser` |
| `V4LifecycleResult` | `.`, `./node`, `./browser` |
| `V4ClockRate` | `.`, `./node`, `./browser` |
| `V4CloseResult` | `.`, `./node`, `./browser` |
| `V4ConnectionGuaranteeAssumptions` | `.`, `./node`, `./browser` |
| `V4ConnectionGuarantees` | `.`, `./node`, `./browser` |
| `V4ConnectionGuaranteeScope` | `.`, `./node`, `./browser` |
| `V4ConnectionMaterial` | `.`, `./node`, `./browser` |
| `V4ConnectionRequirements` | `.`, `./node`, `./browser` |
| `V4ConsumerTLS13Verification` | `.`, `./node`, `./browser` |
| `V4CoreCleanup` | `.`, `./node`, `./browser` |
| `V4Direction` | `.`, `./node`, `./browser` |
| `V4DuplexDirectionResult` | `.`, `./node`, `./browser` |
| `V4DuplexEndpointKind` | `.`, `./node`, `./browser` |
| `V4DuplexOutcome` | `.`, `./node`, `./browser` |
| `V4DuplexResult` | `.`, `./node`, `./browser` |
| `V4DuplexSendResult` | `.`, `./node`, `./browser` |
| `V4EnvironmentClockConfig` | `.`, `./node`, `./browser` |
| `V4EnvironmentConfig` | `.`, `./node`, `./browser` |
| `V4ErrorCode` | `.`, `./node`, `./browser` |
| `V4ErrorScope` | `.`, `./node`, `./browser` |
| `V4IndexedDBPoolBacking` | `./browser` |
| `V4IndexedDBPoolContinuity` | `./browser` |
| `V4IndexedDBPoolError` | `./browser` |
| `V4IndexedDBPoolFailure` | `./browser` |
| `V4IndexedDBPoolIdentity` | `./browser` |
| `V4IndexedDBPoolLimits` | `./browser` |
| `V4IndexedDBPoolOpenOptions` | `./browser` |
| `V4IndexedDBPoolStore` | `./browser` |
| `V4NodeWSSClient` | `./node` |
| `V4NodeWSSClientConfig` | `./node` |
| `V4NodeWSSClientLimits` | `./node` |
| `V4NodeWSSOptions` | `./node` |
| `V4OperationHandle` | `.`, `./node`, `./browser` |
| `V4OperationStatus` | `.`, `./node`, `./browser` |
| `V4PoolStoreError` | `./node` |
| `V4PoolStoreFailure` | `./node` |
| `V4PublicationTransferResult` | `.`, `./node`, `./browser` |
| `V4ReadCause` | `.`, `./node`, `./browser` |
| `V4ReaderCursor` | `.`, `./node`, `./browser` |
| `V4ReaderCursorSnapshot` | `.`, `./node`, `./browser` |
| `V4ReadMethodFailure` | `.`, `./node`, `./browser` |
| `V4ReadMethodFailureReason` | `.`, `./node`, `./browser` |
| `V4ReadProgress` | `.`, `./node`, `./browser` |
| `V4ReadResult` | `.`, `./node`, `./browser` |
| `V4ReadTerminal` | `.`, `./node`, `./browser` |
| `V4ReliableProgress` | `.`, `./node`, `./browser` |
| `V4ResourceRoot` | `.`, `./node`, `./browser` |
| `V4ResourceRootConfig` | `.`, `./node`, `./browser` |
| `V4ResourceVector` | `.`, `./node`, `./browser` |
| `V4ResponsePublicationCause` | `.`, `./node`, `./browser` |
| `V4ResponsePublicationState` | `.`, `./node`, `./browser` |
| `V4ResponsePublicationStatus` | `.`, `./node`, `./browser` |
| `V4RetryDisposition` | `.`, `./node`, `./browser` |
| `V4SessionInfo` | `.`, `./node`, `./browser` |
| `V4SQLitePoolBacking` | `./node` |
| `V4SQLitePoolBinding` | `./node` |
| `V4SQLitePoolContinuity` | `./node` |
| `V4SQLitePoolIdentity` | `./node` |
| `V4SQLitePoolLimits` | `./node` |
| `V4SQLitePoolOpenOptions` | `./node` |
| `V4SQLitePoolStore` | `./node` |
| `V4StreamStatus` | `.`, `./node`, `./browser` |
| `V4TopUpError` | `.`, `./node`, `./browser` |
| `V4TopUpErrorCode` | `.`, `./node`, `./browser` |
| `V4TopUpErrorScope` | `.`, `./node`, `./browser` |
| `V4TopUpWireResult` | `.`, `./node`, `./browser` |
| `V4TopUpWriteAction` | `.`, `./node`, `./browser` |
| `V4TransferProgress` | `.`, `./node`, `./browser` |
| `V4TransportEnvironment` | `.`, `./node`, `./browser` |
| `V4TypedError` | `.`, `./node`, `./browser` |
| `V4WaitStatus` | `.`, `./node`, `./browser` |
| `V4WriteOperation` | `.`, `./node`, `./browser` |
| `V4WritePhase` | `.`, `./node`, `./browser` |
| `V4WriteProgress` | `.`, `./node`, `./browser` |
| `V4WriteTerminalReason` | `.`, `./node`, `./browser` |

## Go v4 WebTransport and unreliable messages

These entries expose bounded original owners, connection assembly, authenticated control transports, issuance authorities and read-only authorization facts. Each capability retains its own admission and lifecycle gates. See [Go transport v4 assembly](GO_TRANSPORT_V4.md) for construction and cleanup.

| Symbol | Declaration |
| --- | --- |
| `(*flowersec.ServeHandle).AcceptWebTransport` | method |
| `(*flowersec.V4Session).UnreliableMessages` | method |
| `(*flowersec.V4WebTransportIngress).Close` | method |
| `(*flowersec.V4WebTransportIngress).WaitCleanup` | method |
| `(*flowersec.V4WebTransportServer).Accept` | method |
| `(*flowersec.V4WebTransportServer).Address` | method |
| `(*flowersec.V4WebTransportServer).Close` | method |
| `(*flowersec.V4WebTransportServer).WaitCleanup` | method |
| `flowersec.DefaultV4WebTransportLimits` | func |
| `flowersec.NewV4WebSocketCarrierSet` | func |
| `flowersec.NewV4WebTransportCarrierFactory` | func |
| `flowersec.NewV4WebTransportServer` | func |
| `flowersec.UnreliableMessageReceiveDisabled` | const |
| `flowersec.UnreliableMessageTemporarilyBlocked` | const |
| `flowersec.V4WebSocketCarrierSet` | type |
| `flowersec.V4WebSocketCarrierSetCharge` | func |
| `flowersec.V4WebSocketEndpoint` | type |
| `flowersec.V4WebSocketSetConfig` | type |
| `flowersec.V4WebTransportAcceptOptions` | type |
| `flowersec.V4WebTransportCarrierFactory` | type |
| `flowersec.V4WebTransportCarrierFactoryCharge` | func |
| `flowersec.V4WebTransportFactoryConfig` | type |
| `flowersec.V4WebTransportIngress` | type |
| `flowersec.V4WebTransportLimits` | type |
| `flowersec.V4WebTransportProviderOptions` | type |
| `flowersec.V4WebTransportServer` | type |
| `flowersec.V4WebTransportServerCharge` | func |
| `flowersec.V4WebTransportServerConfig` | type |

## Go v4 owners and control adapters

These entries expose bounded original owners, connection assembly, authenticated control transports, issuance authorities and read-only authorization facts. Each capability retains its own admission and lifecycle gates. See [Go transport v4 assembly](GO_TRANSPORT_V4.md) for construction and cleanup.

| Symbol | Declaration |
| --- | --- |
| `(*controlplane.V4NamespaceHTTPSService).Close` | method |
| `(*controlplane.V4NamespaceHTTPSService).ServeHTTP` | method |
| `(*controlplane.V4NamespaceHTTPSService).WaitCleanup` | method |
| `(*controlplane.V4NamespacePublisher).Close` | method |
| `(*controlplane.V4NamespacePublisher).GoString` | method |
| `(*controlplane.V4NamespacePublisher).Publish` | method |
| `(*controlplane.V4NamespacePublisher).String` | method |
| `(*controlplane.V4NamespacePublisher).WaitCleanup` | method |
| `(*controlplane.V4SQLitePublicationStore).Close` | method |
| `(*controlplane.V4SQLitePublicationStore).GoString` | method |
| `(*controlplane.V4SQLitePublicationStore).ReadPublished` | method |
| `(*controlplane.V4SQLitePublicationStore).ReplaceState` | method |
| `(*controlplane.V4SQLitePublicationStore).Retire` | method |
| `(*controlplane.V4SQLitePublicationStore).String` | method |
| `(*controlplane.V4SQLitePublicationStore).WaitCleanup` | method |
| `controlplane.CreateV4SQLitePublicationStore` | func |
| `controlplane.NewV4NamespaceHTTPSService` | func |
| `controlplane.NewV4NamespacePublisher` | func |
| `controlplane.OpenV4SQLitePublicationStore` | func |
| `controlplane.V4NamespaceHTTPSConfig` | type |
| `controlplane.V4NamespaceHTTPSService` | type |
| `controlplane.V4NamespaceHTTPSServiceCharge` | func |
| `controlplane.V4NamespacePublicationScope` | type |
| `controlplane.V4NamespacePublicationVersion` | type |
| `controlplane.V4NamespacePublisher` | type |
| `controlplane.V4NamespacePublisherCharges` | func |
| `controlplane.V4NamespacePublisherConfig` | type |
| `controlplane.V4PublicationAuthority` | type |
| `controlplane.V4PublicationFailure` | type |
| `controlplane.V4PublicationFailure.Error` | method |
| `controlplane.V4SQLitePublicationConfig` | type |
| `controlplane.V4SQLitePublicationStore` | type |
| `controlplane.V4SQLitePublicationStoreCharges` | func |

## Go v4 owners and control adapters

These entries expose bounded original owners, connection assembly, authenticated control transports, issuance authorities and read-only authorization facts. Each capability retains its own admission and lifecycle gates. See [Go transport v4 assembly](GO_TRANSPORT_V4.md) for construction and cleanup.

| Symbol | Declaration |
| --- | --- |
| `(*flowersec.ProxyServer).V4StreamHandlers` | method |

## Rust carrier binding selection

`V4BindingMode`, `V4BindingMode::DirectExporter` and
`V4BindingMode::AuthenticatedContext` select the signed transport binding.
`V4WssConnectOptions::binding_mode` and `V4WssServeOptions::binding_mode` fix
that choice before the original irreversible admission or spend. Native direct
exporter mode derives its value independently at each actual TLS endpoint.
See [Rust transport v4 assembly](RUST_TRANSPORT_V4.md).

## Go v4 owners and control adapters

These entries expose bounded original owners, connection assembly, authenticated control transports, issuance authorities and read-only authorization facts. Each capability retains its own admission and lifecycle gates. See [Go transport v4 assembly](GO_TRANSPORT_V4.md) for construction and cleanup.

| Symbol | Declaration |
| --- | --- |
| `(*flowersec.NotifyOperationHandle).Close` | method |
| `(*flowersec.NotifyOperationHandle).Reference` | method |
| `(*flowersec.NotifyOperationHandle).Start` | method |
| `(*flowersec.NotifyOperationHandle).SubmissionStatus` | method |
| `(*flowersec.NotifyOperationHandle).WaitCleanup` | method |
| `(*flowersec.NotifyOperationHandle).WaitSubmission` | method |
| `(*flowersec.StreamingOperationHandle).AbandonResult` | method |
| `(*flowersec.StreamingOperationHandle).Close` | method |
| `(*flowersec.StreamingOperationHandle).Items` | method |
| `(*flowersec.StreamingOperationHandle).ReadNext` | method |
| `(*flowersec.StreamingOperationHandle).ReadNextEncoded` | method |
| `(*flowersec.StreamingOperationHandle).Reference` | method |
| `(*flowersec.StreamingOperationHandle).Start` | method |
| `(*flowersec.StreamingOperationHandle).Status` | method |
| `(*flowersec.StreamingOperationHandle).WaitCleanup` | method |
| `(*flowersec.StreamingOperationHandle).WaitStatus` | method |
| `(*flowersec.StreamingStartError).Error` | method |
| `(*flowersec.StreamingStartError).Unwrap` | method |
| `(*flowersec.V4ConnectionController).GoString` | method |
| `(*flowersec.V4ConnectionController).MarshalJSON` | method |
| `(*flowersec.V4ConnectionController).String` | method |
| `(*flowersec.V4ServiceClient).CallMethod` | method |
| `(*flowersec.V4ServiceClient).Contract` | method |
| `(*flowersec.V4ServiceClient).DispatchMethod` | method |
| `(*flowersec.V4ServiceClient).NotifyMethod` | method |
| `(*flowersec.V4ServiceClient).PrepareMethod` | method |
| `(*flowersec.V4ServiceClient).PrepareNotifyMethod` | method |
| `(*flowersec.V4ServiceClient).PrepareStreamingMethod` | method |
| `(*flowersec.V4ServiceClient).Refresh` | method |
| `(*flowersec.V4ServiceClient).StreamMethod` | method |
| `(*flowersec.V4ServiceClient).UpdateContract` | method |
| `(*flowersec.V4Session).BindMethods` | method |
| `(*flowersec.V4Session).BindUnaryService` | method |
| `(*flowersec.V4Session).PrepareNotify` | method |
| `(*flowersec.V4Session).PrepareStreaming` | method |
| `(*flowersec.V4StreamingResponse).SendItemEncoded` | method |
| `flowersec.ErrContractPolicyRejected` | var |
| `flowersec.ErrContractUpdateInProgress` | var |
| `flowersec.NewV4StreamRegistration` | func |
| `flowersec.NotificationResult` | type |
| `flowersec.NotificationSubmission` | type |
| `flowersec.NotifyOperationHandle` | type |
| `flowersec.StreamingItem` | type |
| `flowersec.StreamingOperationHandle` | type |
| `flowersec.StreamingProgress` | type |
| `flowersec.StreamingStartError` | type |
| `flowersec.V4BoundedContractAcceptance` | func |
| `flowersec.V4CallNotify` | const |
| `flowersec.V4CallServerStreaming` | const |
| `flowersec.V4CallUnary` | const |
| `flowersec.V4ContractAcceptance` | type |
| `flowersec.V4ContractBounded` | const |
| `flowersec.V4ContractExact` | const |
| `flowersec.V4ContractRange` | type |
| `flowersec.V4ContractSnapshot` | type |
| `flowersec.V4MethodSelector` | type |
| `flowersec.V4NotifyMethod` | type |
| `flowersec.V4ServiceBindOptions` | type |
| `flowersec.V4ServiceDefinition` | type |
| `flowersec.V4ServiceMethod` | type |
| `flowersec.V4ServiceMethodWorkload` | type |
| `flowersec.V4SessionMethodWorkload` | type |
| `flowersec.V4StreamRegistration` | type |
| `flowersec.V4StreamingMethod` | type |
| `flowersec.V4StreamingRequest` | type |
| `flowersec.V4StreamingResponse` | type |
| `flowersec.V4UnaryServiceDefinition` | type |
| `flowersec.V4UnaryServiceMethod` | type |

## Go v4 owners and control adapters

These entries expose bounded original owners, connection assembly, authenticated control transports, issuance authorities and read-only authorization facts. Each capability retains its own admission and lifecycle gates. See [Go transport v4 assembly](GO_TRANSPORT_V4.md) for construction and cleanup.

| Symbol | Declaration |
| --- | --- |
| `(*flowersec.OperationReferenceCodec).Close` | method |
| `(*flowersec.OperationReferenceCodec).Export` | method |
| `(*flowersec.OperationReferenceCodec).Import` | method |
| `(*flowersec.V4ResumeCodec).Close` | method |
| `(*flowersec.V4ResumeCodec).DecodeResult` | method |
| `(*flowersec.V4ResumeCodec).ImportToken` | method |
| `(*flowersec.V4SQLiteReferenceStore).Binding` | method |
| `(*flowersec.V4SQLiteReferenceStore).Close` | method |
| `(*flowersec.V4SQLiteReferenceStore).SaveOperationReference` | method |
| `(*flowersec.V4SQLiteReferences).Close` | method |
| `(*flowersec.V4SQLiteReferences).Collect` | method |
| `(*flowersec.V4SQLiteReferences).GoString` | method |
| `(*flowersec.V4SQLiteReferences).List` | method |
| `(*flowersec.V4SQLiteReferences).Load` | method |
| `(*flowersec.V4SQLiteReferences).MarshalJSON` | method |
| `(*flowersec.V4SQLiteReferences).Retire` | method |
| `(*flowersec.V4SQLiteReferences).Save` | method |
| `(*flowersec.V4SQLiteReferences).String` | method |
| `(*flowersec.V4SQLiteReferences).WaitCleanup` | method |
| `(*flowersec.V4ServiceClient).PrepareMethodAndSave` | method |
| `(*flowersec.V4ServiceClient).PrepareNotifyMethodAndSave` | method |
| `(*flowersec.V4ServiceClient).PrepareStreamingMethodAndSave` | method |
| `(*flowersec.V4Session).PrepareNotifyAndSave` | method |
| `(*flowersec.V4Session).PrepareResume` | method |
| `(*flowersec.V4Session).PrepareResumeAndSave` | method |
| `(*flowersec.V4Session).PrepareStreamingAndSave` | method |
| `(*flowersec.V4Session).PrepareUnaryAndSave` | method |
| `(*flowersec.V4Session).Resume` | method |
| `flowersec.CreateV4SQLiteReferences` | func |
| `flowersec.ErrOperationReferenceExpired` | var |
| `flowersec.ErrReferenceSaveUnknown` | var |
| `flowersec.NewOperationReferenceCodec` | func |
| `flowersec.NewV4ResumeCodec` | func |
| `flowersec.NewV4SQLiteReferenceStore` | func |
| `flowersec.OpenV4SQLiteReferences` | func |
| `flowersec.OperationReferenceCodec` | type |
| `flowersec.OperationReferenceCodecCharge` | func |
| `flowersec.OperationReferenceSaveResult` | type |
| `flowersec.OperationReferenceStore` | type |
| `flowersec.OperationReferenceStore.SaveOperationReference` | interface_method |
| `flowersec.V4ReferenceSaveConfirmed` | const |
| `flowersec.V4ReferenceSaveOutcome` | type |
| `flowersec.V4ReferenceSaveUnknown` | const |
| `flowersec.V4ReferenceStoreBinding` | type |
| `flowersec.V4ResumeAccepted` | const |
| `flowersec.V4ResumeCheckpoint` | type |
| `flowersec.V4ResumeClaims` | type |
| `flowersec.V4ResumeCodec` | type |
| `flowersec.V4ResumeCodecCharge` | func |
| `flowersec.V4ResumeMACToken` | const |
| `flowersec.V4ResumeMethod` | type |
| `flowersec.V4ResumeRejected` | const |
| `flowersec.V4ResumeResult` | type |
| `flowersec.V4ResumeSignedToken` | const |
| `flowersec.V4ResumeToken` | type |
| `flowersec.V4ResumeUnknown` | const |
| `flowersec.V4SQLiteReferenceConfig` | type |
| `flowersec.V4SQLiteReferenceStore` | type |
| `flowersec.V4SQLiteReferenceStoreCharge` | func |
| `flowersec.V4SQLiteReferences` | type |
| `flowersec.V4SQLiteReferencesCharge` | func |

## Go v4 owners and control adapters

These entries expose bounded original owners, connection assembly, authenticated control transports, issuance authorities and read-only authorization facts. Each capability retains its own admission and lifecycle gates. See [Go transport v4 assembly](GO_TRANSPORT_V4.md) for construction and cleanup.

| Symbol | Declaration |
| --- | --- |
| `(*flowersec.V4ConnectionController).BindMethods` | method |
| `(*flowersec.V4ConnectionController).BindUnaryMethods` | method |
| `(*flowersec.V4RecoveryMACKey).Close` | method |
| `(*flowersec.V4RecoveryMACKey).GoString` | method |
| `(*flowersec.V4RecoveryMACKey).MarshalJSON` | method |
| `(*flowersec.V4RecoveryMACKey).String` | method |
| `(*flowersec.V4RecoveryVerifier).Close` | method |
| `(*flowersec.V4RecoveryVerifier).GoString` | method |
| `(*flowersec.V4RecoveryVerifier).MarshalJSON` | method |
| `(*flowersec.V4RecoveryVerifier).String` | method |
| `(*flowersec.V4ResumeCodec).CaptureCheckpoint` | method |
| `(*flowersec.V4Session).QueryServiceContracts` | method |
| `flowersec.CreateV4SQLiteExecutions` | func |
| `flowersec.ImportV4RecoveryMACKey` | func |
| `flowersec.NewV4DurableExecutions` | func |
| `flowersec.NewV4RecoveryVerifier` | func |
| `flowersec.NewV4ResumeRegistration` | func |
| `flowersec.OpenV4SQLiteExecutions` | func |
| `flowersec.V4AdmissionOfferBounds` | type |
| `flowersec.V4CheckpointIssuanceOptions` | type |
| `flowersec.V4ContractQueryRefusal` | type |
| `flowersec.V4ContractQuerySnapshotInfo` | type |
| `flowersec.V4ContractQuerySnapshots` | type |
| `flowersec.V4DurableExecutionConfig` | type |
| `flowersec.V4DurableExecutions` | type |
| `flowersec.V4DurableExecutionsCharge` | func |
| `flowersec.V4DurableServiceBinding` | func |
| `flowersec.V4ExecutionPrincipal` | type |
| `flowersec.V4ExecutionService` | type |
| `flowersec.V4ExecutionSessionIdentity` | type |
| `flowersec.V4ExecutionTarget` | type |
| `flowersec.V4RecoveryKey` | type |
| `flowersec.V4RecoveryMACKey` | type |
| `flowersec.V4RecoveryMACKeyCharge` | func |
| `flowersec.V4RecoveryVerifier` | type |
| `flowersec.V4RecoveryVerifierCharge` | func |
| `flowersec.V4RecoveryVerifierConfig` | type |
| `flowersec.V4ResumeStreamBinding` | type |
| `flowersec.V4SQLiteExecutionConfig` | type |
| `flowersec.V4SQLiteExecutionContinuity` | type |
| `flowersec.V4SQLiteExecutionMethod` | type |
| `flowersec.V4SQLiteExecutionRegistration` | type |
| `flowersec.V4SQLiteExecutionService` | type |
| `flowersec.V4SQLiteExecutions` | type |
| `flowersec.V4SQLiteExecutionsCharge` | func |
| `flowersec.V4ServiceAuthority` | type |
| `flowersec.V4ServiceContractPolicy` | type |
| `flowersec.V4ServiceContractTarget` | type |

Owned snapshot, checkpoint and execution storage aliases preserve their original methods:

| Symbol | Declaration |
| --- | --- |
| `(*flowersec.V4SQLiteBacking).Limits` | method |
| `(*flowersec.V4UnaryResponse).IssueCheckpoint` | method |
| `(*flowersec.V4ContractQuerySnapshots).Count` | method |
| `(*flowersec.V4ContractQuerySnapshots).Item` | method |
| `(*flowersec.V4ContractQuerySnapshots).CopyCanonical` | method |
| `(*flowersec.V4ContractQuerySnapshots).Close` | method |
| `(*flowersec.V4SQLiteExecutions).InstallContract` | method |
| `(*flowersec.V4SQLiteExecutions).ReadRegistration` | method |
| `(*flowersec.V4SQLiteExecutions).Close` | method |
| `(*flowersec.V4SQLiteExecutions).WaitCleanup` | method |
| `(*flowersec.V4SQLiteExecutions).Retire` | method |
| `(*flowersec.V4SQLiteExecutions).SupportsCheckpoints` | method |
| `(*flowersec.V4SQLiteExecutions).SupportsContent` | method |
| `(*flowersec.V4DurableExecutions).Close` | method |
| `(*flowersec.V4DurableExecutions).CleanupComplete` | method |

## Go v4 owners and control adapters

These entries expose bounded original owners, connection assembly, authenticated control transports, issuance authorities and read-only authorization facts. Each capability retains its own admission and lifecycle gates. See [Go transport v4 assembly](GO_TRANSPORT_V4.md) for construction and cleanup.

| Symbol | Declaration |
| --- | --- |
| `flowersec.V4ServiceContractSource` | type |
| `flowersec.V4ServiceContractsRemote` | const |
| `flowersec.V4ServiceContractsStatic` | const |

## Go v4 owners and control adapters

These entries expose bounded original owners, connection assembly, authenticated control transports, issuance authorities and read-only authorization facts. Each capability retains its own admission and lifecycle gates. See [Go transport v4 assembly](GO_TRANSPORT_V4.md) for construction and cleanup.

| Symbol | Declaration |
| --- | --- |
| `flowersec.ErrV4ContractDenied` | var |
| `flowersec.ErrV4ContractUnavailable` | var |

## Go v4 owners and control adapters

These entries expose bounded original owners, connection assembly, authenticated control transports, issuance authorities and read-only authorization facts. Each capability retains its own admission and lifecycle gates. See [Go transport v4 assembly](GO_TRANSPORT_V4.md) for construction and cleanup.

| Symbol | Declaration |
| --- | --- |
| `flowersec.ErrV4ContractRenewalQualification` | var |
| `flowersec.V4ContractRenewalPolicy` | type |
| `flowersec.V4ServiceOfferRefresh` | type |
| `flowersec.V4ServiceOfferRefreshExplicit` | const |
| `flowersec.V4ServiceOfferRefreshManaged` | const |

## Go v4 owners and control adapters

These entries expose bounded original owners, connection assembly, authenticated control transports, issuance authorities and read-only authorization facts. Each capability retains its own admission and lifecycle gates. See [Go transport v4 assembly](GO_TRANSPORT_V4.md) for construction and cleanup.

| Symbol | Declaration |
| --- | --- |
| `flowersec.NewV4ServiceDependency` | func |
| `flowersec.V4DispatchRequirement` | type |
| `flowersec.V4InvocationService` | type |
| `flowersec.V4InvocationService.CallMethod` | method |
| `flowersec.V4InvocationService.NotifyMethod` | method |
| `flowersec.V4InvocationService.PrepareMethod` | method |
| `flowersec.V4InvocationService.PrepareNotifyMethod` | method |
| `flowersec.V4InvocationService.PrepareStreamingMethod` | method |
| `flowersec.V4InvocationService.StreamMethod` | method |
| `flowersec.V4InvocationServiceFromContext` | func |
| `flowersec.V4OnUse` | const |
| `flowersec.V4RequiredForDispatch` | const |
| `flowersec.V4ServiceDependency` | type |
| `flowersec.V4ServiceDependencyMethod` | type |

Go ordinary stream metadata preserves the exact v4 application namespace,
version and byte map. `flowersec.NewStreamMetadataEnvelope` captures opaque
application bytes; `flowersec.StreamMetadata.Namespace`,
`flowersec.StreamMetadata.Version`, and `flowersec.StreamMetadata.ByteValues`
return detached projections. `flowersec.StreamMetadata.JSONValues` recognizes
only the optional `application/json` version 1 convenience codec. Nonempty
metadata is canonical CBOR; an empty metadata value uses zero bytes.
