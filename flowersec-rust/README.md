# Flowersec for Rust

The `flowersec` crate is the Tokio-native Rust SDK for Flowersec v2 end-to-end
encrypted sessions. Its maintained public entrypoints use opaque artifacts, the
carrier-neutral `Connector`, and `Session`; the legacy v1 facade has been
removed.

The crate targets Rust 1.85 or newer on Linux, macOS, and Windows, uses rustls
by default, and contains no Flowersec-authored `unsafe`.

## Install

```bash
cargo add flowersec
```

The default feature uses native root certificates. Use
`default-features = false, features = ["rustls-webpki-roots"]` for an embedded
WebPKI root set.

## Transport v2 Support

WebSocket, raw QUIC, and WebTransport are equal carrier candidates.

Raw QUIC and WebTransport preserve native FIN, RESET_STREAM, STOP_SENDING, flow control, and migration behavior.

Rust publishes an opaque Transport v2 connector and a carrier-neutral session
contract. Transport selection, topology, candidates, wire state, credentials,
keys, and endpoint identities are unavailable to crate consumers.

The current production connector implements raw QUIC dialing internally. It
uses native bidirectional QUIC streams without Yamux, requires caller-provided
trust material, disables 0-RTT and QUIC DATAGRAM, and is covered by Go
interoperability tests. Those implementation details do not change the public
connector or session contract.

Transport v2 production carrier support: raw QUIC client dialing for direct and tunnel paths.

Flowersec disables application 0-RTT and does not use QUIC DATAGRAM.

## Public API

The crate root exports only these public categories:

- opaque artifact lifecycle: `Artifact`, `ArtifactError`, `ArtifactLease`, and
  `ArtifactSpendError`;
- connection lifecycle: `ConnectorOptions`, `Connector`, `ConnectError`, and
  `ConnectErrorCode`;
- carrier-neutral session behavior: `Session`, `RpcPeer`, `ByteStream`,
  `IncomingStream`, and `JsonObject`;
- closed operation failures: `SessionError` and `StreamTerminalError`.

Parse an opaque artifact with `Artifact::parse`, bind its durable single-use
callback with `ArtifactLease`, and establish a session through `Connector`.
`Session` exposes RPC, logical streams, rekey, liveness, termination waiting,
and bounded close. It does not expose route or carrier selection, endpoint
identity, stream identifiers, candidates, wire data, keys, or transport
diagnostics.

`ConnectErrorCode`, `SessionError`, and `StreamTerminalError` are closed,
redacted failure sets. Public errors do not retain peer payloads, carrier
diagnostics, credentials, or cryptographic material.

## Runtime Boundaries

Rust owns the native Tokio implementation of the portable contract. Browser
runtime APIs remain TypeScript-owned, while shared tunnel, gateway, and helper
binaries remain Go-owned.
