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
The returned `Session` exposes `RPCPeer`, `ByteStream`, `IncomingStream`,
validated `StreamMetadata`, liveness, rekeying, termination, and close.

`StreamHandlers` registers bounded application stream handlers on any
established Session. `RPCPeer.subscribeNotification(_:as:handler:)` validates
each payload before delivery and returns an async, idempotent subscription.
Handler and decoder failures stay isolated from unrelated work.

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
artifact-bound active pin set and never falls back to CA. Raw QUIC,
WebTransport, unreliable messages, server acceptance, tunnel relay, and
ProxyServer are not part of the Apple SDK profile.

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
[Transport v3 architecture](../docs/TRANSPORT_V3_ARCHITECTURE.md),
[wire contract](../docs/TRANSPORT_V3_WIRE.md), and
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
