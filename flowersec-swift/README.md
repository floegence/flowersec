# Flowersec Swift

The native Swift SDK for Flowersec v2 end-to-end encrypted sessions on Apple platforms.

Flowersec 2.2.0 is the coordinated SwiftPM release.

## Install

The repository root exposes the Swift package through the following version range:

```swift
.package(url: "https://github.com/floegence/flowersec.git", from: "2.2.0")
```

Use the `Flowersec` library product.

## Public Contract

Parse an opaque `Artifact` with `parseArtifact(...)`, bind it to a single-use `ArtifactLease`, and call `connect(lease:options:)` with `ConnectorOptions`. This one-shot connector creates exactly one `Session`; a terminated session never reconnects, migrates its streams, or replays its RPCs and writes. Applications receive only the carrier-neutral `Session`, `RPCPeer`, `ByteStream`, `IncomingStream`, and bounded `StreamMetadata` contracts. `StreamMetadata` validates during initialization and is the same value type used for outgoing and incoming stream metadata.

`ConnectError` and `SessionError` are closed redacted error sets. A remote application RPC failure is `RPCError` with only its semantic code and sanitized message. Candidate credentials, carrier choice, admission reasons, path, endpoint identities, logical stream IDs, wire state, cryptographic keys, and Yamux are not public.

`ConnectError` and `SessionError` expose a structured `RetryDisposition`: `terminal`, `retryable`, or `retryAfter(Date)` with an absolute not-before time. Controller retry timing uses the shared fixed defaults; only `maximumAttempts` is public. `ConnectorOptions` uses the shared ten-second connection timeout when the caller omits it. Apple TLS uses the system trust store when `trustRootsPEM` is empty and accepts explicit PEM roots for private trust profiles.

For a long-lived connection, provide a refreshable `ArtifactSource` to `ConnectionController`. The controller is the sole Flowersec reconnect scheduler. Every attempt acquires a new single-use `ArtifactLease` and invokes the same one-shot connector to create a new session. Its public `idle`, `connecting`, `connected`, `waiting`, `failed`, and `closed` states expose the current session, attempt number, and last real attempt failure through snapshots and an update stream. `attempt` is the 1-based ordinal for the active connection cycle, so connected and waiting snapshots retain the ordinal of their successful session; it resets after the wait completes, immediately before the next cycle starts at 1. Backoff is deterministic (250 ms initial delay, multiplier 2, 30 s maximum, no jitter), attempts are unlimited by default, and a finite maximum is always explicit. Reaching that maximum stops the controller without replacing the owning acquisition, connection, or session failure with a policy wrapper. A `retryAfter` deadline and backoff both apply, so retry starts at the later instant; `retryNow()` returns whether it woke the current wait and never crosses that deadline. `close()` is idempotent, waits for controller-owned cleanup, and ignores subordinate session close failures. Applications provide artifacts, restore application authentication and subscriptions after a new session appears, and display state; they must not run a second Flowersec retry loop or infer retry behavior from error text.

## Capability Layers

The portable core is the same application model used by every Flowersec SDK:
opaque artifact parsing, a durable single-use lease, one-shot connection, an optional
single-owner connection controller,
carrier-neutral sessions, RPC, reliable streams, redacted public errors, and
structured retry dispositions. Callers should not compare raw Swift error cases with
other SDKs.

Portable core, connection control, session/RPC/stream lifecycle, accepted-session
workflows, and published consumer workflows align across every applicable SDK.
Platform-limited profiles are unsupported only with an explicit alternative
boundary and executable test ID in `stability/language_capabilities.json`.

The Swift SDK profile is Apple-platform WebSocket dialing. Runtime, carrier,
direct/tunnel topology, network mode, and client/server session role are independent
capability dimensions; the SDK reports only combinations implemented by its adapter.
Its language convenience
is the Swift-native async and typed value surface around `Data`,
`Duration`, and bounded `StreamMetadata`. Swift does not expose an unreliable
message channel in the current SDK profile, and that absence does not narrow the
portable core.

## Production Support

WebSocket, raw QUIC, and WebTransport are equal carrier candidates. The support below is the Apple SDK profile, not the portable API.

Raw QUIC and WebTransport preserve native FIN, RESET_STREAM, STOP_SENDING, flow control, and migration behavior. The Swift SDK support below is narrower than the protocol carrier set.

`connect(lease:options:)` establishes direct and tunneled WebSocket sessions on macOS and iOS. It validates TLS and the exact Flowersec v2 WebSocket subprotocol before durable spend and admission. WebSocket keeps Yamux internal to its adapter. Raw QUIC and WebTransport are explicitly unsupported because the Swift SDK does not implement those runtime adapters.

Transport v2 production carrier support: macOS and iOS support WebSocket direct and tunnel dial sessions.

Flowersec disables application 0-RTT. Reliable streams never use QUIC DATAGRAM; runtimes with negotiated native DATAGRAM expose it only through carrier-neutral unreliable messages.

WebSocket connections require TLS 1.3 and exact Flowersec v2 subprotocol negotiation. See the [Transport v2 architecture](../docs/TRANSPORT_V2_ARCHITECTURE.md) for the internal carrier contract.

## Cookbook

The [Swift cookbook](https://github.com/floegence/flowersec/tree/main/examples/swift) prints the opaque public contract marker and can establish a macOS WSS session from a fresh artifact.

Review the shared [API contract](../docs/API_CONTRACT.md), [threat model](../docs/THREAT_MODEL.md), and [error model](../docs/ERROR_MODEL.md).
