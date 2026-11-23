# Flowersec Swift

The Swift SDK provides end-to-end encrypted Flowersec sessions, RPC,
notifications, and reliable byte streams on macOS and iOS.

## Install

Add `https://github.com/floegence/flowersec.git` as a Swift Package dependency,
then select the `Flowersec` library product.

## Public API

Parse an opaque `Artifact` with `parseArtifact(...)`, bind it to a single-use
`ArtifactLease`, and call `connect(lease:options:)` with `ConnectorOptions`.
The Apple WebSocket runtime requires an explicit absolute HTTP(S) `origin` in
`ConnectorOptions`; there is no implicit origin because it is part of the
server's admission policy.
The SDK accepts `flowersec/5`. On a tunnel, use `ConnectorOptions.tunnelIngress`
to select the local authorized entry. Each endpoint selects from its own artifact;
an unmatched entry fails before dialing or spending the lease.
The returned `Session` exposes `RPCPeer`, `ByteStream`, `IncomingStream`,
validated `StreamMetadata`, liveness, rekeying, termination, and close.
`close()` starts a shared shutdown. Canceling a caller's wait does not cancel
cleanup. Observe `waitTermination()` outside the session's own RPC callbacks:
it completes only after those callbacks exit.

If spending also reserves a host resource, construct `ArtifactLease(reservingFor:)`
or return `DirectAdmissionGrant(reservingFor:handlers:)` from the listener.
Inside the closure, atomically commit the spend and reservation, then return
`ConnectionLease { try await store.release(reservationID) }`. Use the identity of
that reservation. A rejection or uncertain commit must throw; the host must keep
the credential spent on an uncertain outcome and reconcile its own storage.
A host that stores only spend receipts can use `commitSpend:` or `consume:`.

After a confirmed acquisition, the SDK waits for release if setup fails, on
local close, and on peer termination. The callback must only release the
reservation and must leave the spend receipt intact. A canceled close waiter can
rejoin with `waitTermination()`. A failed release makes `close()` throw
`ArtifactLeaseError.releaseFailed`; `SessionTermination.leaseReleaseFailed`
reports that failure alongside the original termination reason. Before a session
exists, check `ConnectError.leaseReleaseFailed` on the dialing side. On the
listener, `waitClosedAndCheckReleases()` drains all workers and reports release
failures, including failures before `onSession` received a session. Release
callbacks must not wait for the session's termination or for listener shutdown.

`StreamHandlers` registers bounded application stream handlers on any
established Session. `RPCPeer.subscribeNotification(_:as:handler:)` validates
each payload before delivery and returns an async, idempotent subscription.
Handler and decoder failures stay isolated from unrelated work.
Register unary handlers in `RPCHandlers` before connecting or accepting. Use
`bound(to:)` to share a method table while giving each session its own state.
Use `registerNotification` for a notification-only method that must be ready
before the first message; a unary request cannot invoke that registration.
Unary and notification registrations share one nonzero method ID namespace.
Set `acceptsNotifications: false` on a unary registration if only requests
with a reply should invoke it. Independent notification subscriptions still work.
`RPCFrameLimits` defaults to a 1 MiB encoded envelope, including JSON overhead;
configure both endpoints explicitly when larger messages are required.
The call timeout includes waiting for the first outbound RPC stream to open.
Canceling or timing out one caller does not cancel another caller's wait.

For long-lived connections, `ConnectionController` is the only reconnect
scheduler. Each attempt acquires a fresh lease and creates a new Session.
Terminated Session work is never migrated or replayed. Retry decisions are
`terminal`, `retryable`, or `retryAfter(UInt64)` with an absolute Unix
millisecond boundary.

`ConnectError`, `SessionError`, and controller diagnostics are closed and
redacted. Candidate selection, credentials, peer details, and cryptographic
state are not public.

## Supported Connections

Swift supports direct and relayed TLS 1.3 WebSocket sessions on macOS and iOS.
CA mode uses system trust or explicit PEM roots; pin mode verifies only the
artifact-bound active pin set and never falls back to CA. To accept Direct WSS,
use `DirectWebSocketListener.listen` with a certificate, origin policy and an
authorization callback. Return only an independently authorized artifact; its
spend callback must enforce the host's current grant and single-use transaction.
Raw QUIC, WebTransport, unreliable messages and ProxyServer are not part of
the Apple SDK profile.

## Run a WSS tunnel relay

Call `WebSocketRelay.listen(ingresses:authorize:)` to bind one or more
`WebSocketRelayIngress` listeners. Each has its own TLS certificate and origin
policy. Its optional `endpoint` is the canonical public WSS URL mapped to that
listener; omitting it uses the actual local socket address. Static TCP forwarding
can deliver traffic for different public entrances to distinct listeners on this
relay. `ports` lists their bound ports in configuration order.

At the trusted issuer, project each tunnel invitation to a `RelayAdmissionRecord`
with the authenticated issuer/pairing scope. Persist or send only this `Codable`
record to the relay via a trusted channel. In `authorize`, fetch the record by
`request.lookupKey` and return a `RelayAdmissionGrant`. The relay verifies the
exact admission and its selected entrance before invoking `consume` or
`acquireConnectionLease`. That callback must atomically verify current authority
and expiry and durably spend the credential once across all entrances. An
uncertain commit must throw and leave the credential spent. Releasing a
connection lease never restores the credential.

The two legs can have disjoint candidate sets. Only a matching complementary
pair receives admission success. The relay then copies the binary WebSocket
traffic in each direction; Yamux streams and the encrypted session run between
the endpoints. The relay has no session keys or RPC handlers. Connection,
pending-leg and active-pair limits apply across all listeners. `close()` waits
for physical connections, callbacks and lease releases; use
`waitClosedAndCheckReleases()` to surface a release failure after shutdown.

## Explicit HTTP Direct

`parseHTTPDirectArtifactV1(...)` and `HTTPDirectArtifactLeaseV1` consume an
explicit `flowersec-http-direct/1` envelope. `connectHTTPDirectV1(lease:options:)`
connects to its exact HTTP origin over WS and returns the same opaque `Session`.
The origin must equal the envelope's origin; only canonical IP addresses and
localhost are accepted. The ordinary `parseArtifact` / `connect` path remains
TLS-only and rejects HTTP envelopes. HTTP has no transport confidentiality
before the authenticated Flowersec session is established; applications must
select it explicitly and authorize their public HTTP endpoint independently.
The lease retains the ordinary atomic spend and retirement semantics.

## Cookbook

The [Swift cookbook](../examples/swift/README.md) establishes a WSS session,
performs typed RPC and notification exchange, completes a reliable stream, and
closes the Session.

See the [API contract](../docs/API_CONTRACT.md),
[Transport v5 architecture](../docs/TRANSPORT_V5_ARCHITECTURE.md),
[wire contract](../docs/TRANSPORT_V5_WIRE.md), and
[error model](../docs/ERROR_MODEL.md).

## Application-owned HTTPDirect channels

`connectHTTPDirectV1` accepts an optional `HTTPDirectChannelProvider` for an
explicit authenticated outer transport. Its endpoint must exactly match the
HTTPDirect envelope. The provider initializes a NIO byte channel before delivery,
honors cancellation, and closes partial opens. Flowersec owns WebSocket upgrade,
admission, lease spending, framing and session lifetime. Closing that channel
must release only its byte stream. This does not change ordinary TLS connectors
or permit endpoint rewriting, fallback, or transport-security downgrades.

## Application-owned TLS channels

`connect(lease:options:channelProvider:)` accepts a `TLSChannelProvider` bound to
one canonical HTTPS origin. Each candidate must retain that origin; the provider
opens only the application's byte transport and Flowersec installs TLS 1.3,
verifies the artifact's CA or pin policy, and performs WebSocket negotiation and
admission. Origin headers, subprotocols, lease spending, cancellation and session
semantics remain unchanged. A rejected or unavailable channel never falls back
to a direct connection or plaintext.

`TLSChannelProvider.openChannel(trustRootsPEM:initializer:)` uses the same byte
transport with CA-verified TLS for application HTTP requests before a session
exists. Its initializer installs application handlers after TLS and before
channel activation. Requests must retain the bound origin. The application owns
request timeouts and cancellation and closes each channel after use. The
provider must honor cancellation and close partial opens. Empty PEM roots use
platform trust; supplied roots replace it. Certificate errors are delivered
through the channel pipeline and must never trigger plaintext retries.
