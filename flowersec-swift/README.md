# Flowersec Swift

The Swift SDK provides end-to-end encrypted Flowersec sessions, RPC,
notifications, and reliable byte streams on macOS and iOS.

## Install

Add `https://github.com/floegence/flowersec.git` as a Swift Package dependency,
then select the `Flowersec` library product.

## Public API

Parse an opaque `Artifact` with `parseArtifact(...)`, bind it to a single-use
`ArtifactLease`, and call `connect(lease:options:)` with `ConnectorOptions`.
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

## Cookbook

The [Swift cookbook](../examples/swift/README.md) establishes a WSS session,
performs typed RPC and notification exchange, completes a reliable stream, and
closes the Session.

See the [API contract](../docs/API_CONTRACT.md),
[Transport v3 architecture](../docs/TRANSPORT_V3_ARCHITECTURE.md),
[wire contract](../docs/TRANSPORT_V3_WIRE.md), and
[error model](../docs/ERROR_MODEL.md).
