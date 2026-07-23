# Flowersec for Rust

The `flowersec` crate is the Tokio-native Rust SDK for Flowersec v2 end-to-end encrypted direct and tunneled sessions. Its maintained public entrypoints use opaque artifacts, the carrier-neutral Connector, and Session; the legacy v1 facade has been removed.

The crate targets Rust 1.85 or newer on Linux, macOS, and Windows, uses rustls by default, and contains no Flowersec-authored `unsafe`.

## Install

```bash
cargo add flowersec
```

The default feature uses native root certificates. Use `default-features = false, features = ["rustls-webpki-roots"]` for an embedded WebPKI root set.

## Transport v2 Support

Rust publishes Transport v2 protocol/session primitives and a public raw QUIC adapter built on Quinn. The adapter uses native bidirectional QUIC streams without Yamux, requires caller-provided trust/certificate material, and disables 0-RTT and QUIC DATAGRAM. It is covered by Go interoperability tests.

WebSocket, raw QUIC, and WebTransport are equal carrier candidates.
QUIC-family carriers use native QUIC streams and never Yamux.
Flowersec application 0-RTT is disabled.
Flowersec does not use QUIC DATAGRAM frames.

Transport v2 production carrier support: raw QUIC client dialing for direct and tunnel paths.

Rust advertises the two raw QUIC client-dial tuples proven by the public `Connector`: direct/client and tunnel/client. The connector consumes an opaque `ArtifactLease`, races compatible candidates, durably spends before FSB2 credentials are written, and returns only the carrier-neutral `Session` contract. Raw QUIC listener/server roles, WebSocket, and WebTransport remain unavailable.

## Entrypoints

- Parse an opaque artifact with `artifact_v2::Artifact::parse` and bind its durable single-use callback with `artifact_v2::ArtifactLease`.
- Configure trust and the connection deadline with `ConnectorOptions`, then establish through `Connector`.
- Use the carrier-neutral `Session` API for streams, RPC, rekey, liveness, termination, and bounded close.
- Runtime capability inspection is available through `transport_v2::native_rust_capability_descriptor_v2`.

## Runtime Boundaries

Rust owns the native Tokio implementation of the portable contract. Browser runtime APIs remain TypeScript-owned, while shared tunnel, gateway, and helper binaries remain Go-owned.

Review the shared [API contract](../docs/API_CONTRACT.md), [protocol](../docs/PROTOCOL.md), [threat model](../docs/THREAT_MODEL.md), and [error model](../docs/ERROR_MODEL.md).
