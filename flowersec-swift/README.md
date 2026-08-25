# Flowersec Swift

The native Swift SDK for end-to-end encrypted Flowersec sessions on macOS and
iOS, with RPC, notifications, and reliable byte streams.

## Install

Add `https://github.com/floegence/flowersec.git` as a Swift Package dependency
in Xcode or `Package.swift`, then select the `Flowersec` library product.

## Public Contract

Parse an opaque `Artifact` with `parseArtifact(...)`, bind it to a single-use `ArtifactLease`, and call `connect(lease:options:)` with `ConnectorOptions`. This one-shot connector creates exactly one `Session`; a terminated session never reconnects, migrates its streams, or replays its RPCs and writes. Applications use the same `Session`, `RPCPeer`, `ByteStream`, `IncomingStream`, and bounded `StreamMetadata` contracts as the other Flowersec SDKs. `StreamMetadata` validates during initialization and is the same value type used for outgoing and incoming stream metadata.

These unversioned names are the recommended strict-v3 API. The
v3-suffixed artifact, lease, parser, connector, and error names are
deprecated aliases. The v2 retry enum is `RetryDispositionV2`; deprecated
`RetryDisposition` aliases it, while strict v3 uses `RetryDispositionV3`.

`StreamHandlers` registers bounded application stream handlers and serves them
on any established `Session`. It freezes on first use, accepts only the exact
1-through-128-byte canonical OPEN kind contract, resets unknown, excess, and
failed streams, and waits for active handler tasks during shutdown. The Apple
profile does not expose a server `ProxyServer` or registrar.

`RPCPeer.subscribeNotification(_:as:handler:)` registers before it returns and decodes every peer notification as the requested `Decodable & Sendable` type. The handler receives `.failure(.invalidPayload)` for invalid payloads, never unvalidated data. Throwing handlers are isolated from the RPC stream. The returned `RPCNotificationSubscription` has an async, idempotent `cancel()` operation, and closing the Session removes every remaining subscription.

`ConnectError` and `SessionError` are closed redacted error sets. A remote application RPC failure is `RPCError` with only its semantic code and sanitized message. Connection selection, credentials, endpoint details, and cryptographic state are not public.

v3 `ConnectError` and `SessionError` expose a structured `RetryDispositionV3`: `terminal`, `retryable`, or `retryAfter(UInt64)` carrying an exact absolute Unix-millisecond not-before deadline. Controller retry timing uses the shared fixed defaults; only `maximumAttempts` is public. `ConnectorOptions` uses the shared ten-second connection timeout when the caller omits it. Apple CA mode uses the system trust store when `trustRootsPEM` is empty and accepts explicit PEM roots for private trust profiles. Pin mode verifies only the complete active artifact-bound pin set and never falls back to CA. Production v3 accepts only TLS-protected candidates.

For a long-lived connection, provide a refreshable `ArtifactSource` to `ConnectionController`. The controller is the sole Flowersec reconnect scheduler. Every attempt acquires a new single-use `ArtifactLease` and invokes the same one-shot connector to create a new session. Its public `idle`, `connecting`, `connected`, `waiting`, `failed`, and `closed` states expose the current session, attempt number, and last real attempt failure through snapshots and an update stream. `waitForSession()` is passive and returns a structured failed, closed, or canceled error; `ConnectionSnapshot.diagnostic` contains only state, attempt, failure phase/code, and retry disposition. `attempt` is the 1-based ordinal for the active connection cycle. A connected snapshot retains the successful ordinal; session termination begins a fresh cycle at attempt 0, and the first subsequent Acquire advances it to 1. Backoff is deterministic (250 ms initial delay, multiplier 2, 30 s maximum, no jitter), attempts are unlimited by default, and a finite maximum is always explicit. Reaching that maximum stops the controller without replacing the owning acquisition, connection, or session failure with a policy wrapper. A `retryAfter` deadline and backoff both apply, so retry starts at the later instant; `retryNow()` returns whether it woke the current wait and never crosses that deadline. `close()` is idempotent, waits for controller-owned cleanup, and ignores subordinate session close failures. Applications provide artifacts, restore application authentication and subscriptions after a new session appears, and display state; they must not run a second Flowersec retry loop or infer retry behavior from error text.

## Supported Connections

The Swift SDK supports direct and relayed WebSocket sessions on macOS and iOS.
It uses Swift-native async APIs and typed values around `Data`, `Duration`, and
`StreamMetadata`. Unreliable messages are not available in the Apple profile.

## Connection Notes

`connect(lease:options:)` establishes direct and relayed WebSocket sessions.
WSS requires TLS 1.3 and exact v3 subprotocol negotiation. Raw QUIC and
WebTransport are not implemented by the Swift runtime; their candidates are
filtered as unsupported before a lease is spent.

See the [Transport v3 architecture](../docs/TRANSPORT_V3_ARCHITECTURE.md) and
[v3 wire contract](../docs/TRANSPORT_V3_WIRE.md) for the internal carrier and
security contract.

## Cookbook

The [Swift cookbook](https://github.com/floegence/flowersec/tree/main/examples/swift) establishes a macOS WSS session from a fresh artifact, performs typed RPC and notification exchange, completes a reliable stream through FIN, and closes the Session.

Review the shared [API contract](../docs/API_CONTRACT.md), [threat model](../docs/THREAT_MODEL.md), and [error model](../docs/ERROR_MODEL.md).
