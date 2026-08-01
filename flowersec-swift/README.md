# Flowersec Swift

The native Swift SDK for Flowersec v2 end-to-end encrypted sessions on Apple platforms.

The current source is a Flowersec 2.0 release candidate. No `2.0.0` SwiftPM tag has been published yet; use an existing release tag until the coordinated 2.0 release.

## Install

After the 2.0 release, the repository root exposes the Swift package through the following version range:

```swift
.package(url: "https://github.com/floegence/flowersec.git", from: "2.0.0")
```

Use the `Flowersec` library product.

## Public Contract

Parse an opaque `Artifact` with `parseArtifact(...)`, bind it to a single-use `ArtifactLease`, and call `connect(lease:options:)` with `ConnectorOptions`. Applications receive only the carrier-neutral `Session`, `RPCPeer`, `ByteStream`, `IncomingStream`, and bounded `StreamMetadata` contracts.

`ConnectError` and `SessionError` are closed redacted error sets. A remote application RPC failure is `RPCError` with only its semantic code and sanitized message. Candidate credentials, carrier choice, admission reasons, path, endpoint identities, logical stream IDs, wire state, cryptographic keys, and Yamux are not public.

`classifyConnectError(_:)` and `classifySessionError(_:)` return `ErrorRetryClassification` with a `RetryAction`. The actions distinguish retrying the current operation, acquiring a fresh artifact and session, and stopping. `ConnectorOptions` uses the shared ten-second connection timeout when the caller omits it. Apple TLS uses the system trust store when `trustRootsPEM` is empty and accepts explicit PEM roots for private trust profiles.

## Production Support

WebSocket, raw QUIC, and WebTransport are equal carrier candidates. The support below is the Apple SDK profile, not the portable API.

Raw QUIC and WebTransport preserve native FIN, RESET_STREAM, STOP_SENDING, flow control, and migration behavior. The Swift SDK support below is narrower than the protocol carrier set.

`connect(lease:options:)` establishes direct and tunneled WebSocket sessions on macOS and iOS. It validates TLS and the exact Flowersec v2 WebSocket subprotocol before durable spend and admission. WebSocket keeps Yamux internal to its hop. Raw QUIC and WebTransport are not exposed by the current Swift connector.

Transport v2 production carrier support: macOS and iOS support WebSocket direct and tunnel dial sessions.

Flowersec disables application 0-RTT. Reliable streams never use QUIC DATAGRAM; runtimes with negotiated native DATAGRAM expose it only through carrier-neutral unreliable messages.

WebSocket connections require TLS 1.3 and exact Flowersec v2 subprotocol negotiation. See the [Transport v2 architecture](../docs/TRANSPORT_V2_ARCHITECTURE.md) for the internal carrier contract.

## Cookbook

The [Swift cookbook](https://github.com/floegence/flowersec/tree/main/examples/swift) prints the opaque public contract marker and can establish a macOS WSS session from a fresh artifact.

Review the shared [API contract](../docs/API_CONTRACT.md), [threat model](../docs/THREAT_MODEL.md), and [error model](../docs/ERROR_MODEL.md).
