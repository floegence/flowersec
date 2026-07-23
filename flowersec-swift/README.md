# Flowersec Swift

The native Swift SDK for Flowersec v2 end-to-end encrypted sessions on Apple platforms.

## Install

The repository root exposes the Swift package:

```swift
.package(url: "https://github.com/floegence/flowersec.git", from: "2.0.0")
```

Use the `Flowersec` library product.

## Public Contract

Parse an opaque `ArtifactV2` with `parseArtifactV2(...)`, bind it to a single-use `ArtifactLeaseV2`, initialize `ConnectorV2` with `ConnectorOptionsV2`, and call `ConnectorV2.connect()`. Applications receive only the carrier-neutral `SessionV2`, `RPCPeerV2`, `ByteStreamV2`, `IncomingStreamV2`, and bounded `StreamMetadataV2` contracts.

`ConnectErrorV2` and `SessionErrorV2` are closed redacted error sets. A remote application RPC failure is `RPCErrorV2` with only its semantic code and sanitized message. Candidate credentials, carrier choice, admission reasons, path, endpoint identities, logical stream IDs, wire state, cryptographic keys, and Yamux are not public.

## Production Support

WebSocket, raw QUIC, and WebTransport are equal carrier candidates.

Raw QUIC and WebTransport preserve native FIN, RESET_STREAM, STOP_SENDING, flow control, and migration behavior. The Swift SDK support below is narrower than the protocol carrier set.

`ConnectorV2` establishes direct and tunneled WebSocket sessions on macOS. It validates TLS and the exact Flowersec v2 WebSocket subprotocol before durable spend and admission. WebSocket keeps Yamux internal to its hop. Raw QUIC and WebTransport are not exposed by the current Swift connector.

Transport v2 production carrier support: macOS supports WebSocket direct and tunnel dial sessions; iOS advertises no production carrier.

Flowersec disables application 0-RTT and does not use QUIC DATAGRAM.

WebSocket connections require TLS 1.3 and exact Flowersec v2 subprotocol negotiation. See the [Transport v2 architecture](../docs/TRANSPORT_V2_ARCHITECTURE.md) for the internal carrier contract.

## Cookbook

The [Swift cookbook](https://github.com/floegence/flowersec/tree/main/examples/swift) prints the opaque public contract marker and can establish a macOS WSS session from a fresh artifact.

Review the shared [API contract](../docs/API_CONTRACT.md), [threat model](../docs/THREAT_MODEL.md), and [error model](../docs/ERROR_MODEL.md).
