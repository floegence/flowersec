# Flowersec Swift

The Swift SDK provides end-to-end encrypted Flowersec sessions, RPC,
notifications, and reliable byte streams on macOS and iOS.

## Install

Add `https://github.com/floegence/flowersec.git` as a Swift Package dependency,
then select the `Flowersec` library product.

## Public API

The native v4 client starts with `TransportEnvironment(configuration:)` and
explicit trusted time, pinned namespace roots, numerical endpoints and durable
SQLite pool history. It verifies a `TransportV4PoolCredential`, binds it to an
original `TransportV4ApplicationIdentity`, and connects with
`connectMaterial(_:requirements:)` or `connect(source:requirements:)`.
See [Swift transport v4](../docs/SWIFT_TRANSPORT_V4.md) for configuration,
host adapter obligations, metadata and cleanup.

The separate transport v3 entrance provides RPC and notifications:
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

The v4 entrance supports direct preauthorized-pool TLS 1.3 WebSocket sessions,
both Noise profiles, CA and signed leaf-DER pin policies, and bounded binary
stream metadata. It exposes reliable byte streams, rekey, liveness and close;
its `Session.rpc` operations are unavailable. Live authority, services,
notifications, resume and a v4 reconnect controller are not implemented.

Swift supports direct and relayed TLS 1.3 WebSocket sessions on macOS and iOS.
The v3 entrance supports direct and relayed TLS 1.3 WebSocket sessions.
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
closes the Session through the v3 entrance. The
[v4 guide](../docs/SWIFT_TRANSPORT_V4.md) covers the configured v4 lifecycle.

See the [API contract](../docs/API_CONTRACT.md),
[Transport v3 architecture](../docs/TRANSPORT_V3_ARCHITECTURE.md),
[wire contract](../docs/TRANSPORT_V3_WIRE.md), and
[error model](../docs/ERROR_MODEL.md).
