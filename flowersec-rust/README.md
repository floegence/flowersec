# Flowersec for Rust

The `flowersec` crate is the Tokio-native Rust SDK for Flowersec v2 end-to-end
encrypted sessions. Its maintained public entrypoints use opaque artifacts, the
carrier-neutral one-shot `connect(...)` function, and `Session`; the legacy v1 facade has been
removed.

The current source is a Flowersec 2.0 release candidate and has not yet been
published as the coordinated 2.0 crate release. Verify the registry version
before depending on source-only 2.0 APIs.

The crate targets Rust 1.88 or newer on Linux, macOS, and Windows, uses rustls
by default, and contains no Flowersec-authored `unsafe`.

## Install

```bash
cargo add flowersec
```

The production raw QUIC connection profile requires explicit DER trust roots.
`ConnectorOptions::new(...)` rejects empty roots and creates a valid option value
with the shared ten-second connection timeout.

```rust
let options = flowersec::ConnectorOptions::new(vec![root_der])?;
let session = flowersec::connect(&mut lease, options, cancellation).await?;
```

## Transport v2 Support

WebSocket, raw QUIC, and WebTransport are equal carrier candidates. The support below is the native Rust SDK profile, not the portable API.

Raw QUIC and WebTransport preserve native FIN, RESET_STREAM, STOP_SENDING, flow control, and migration behavior.

Rust publishes an opaque Transport v2 connector and a carrier-neutral session
contract. Transport selection, topology, candidates, wire state, credentials,
keys, and endpoint identities are unavailable to crate consumers.

The current production connector implements raw QUIC dialing internally. It
uses native bidirectional QUIC streams without Yamux, requires caller-provided
trust material, disables 0-RTT, and is covered by Go interoperability tests.
Negotiated native DATAGRAM is used only by the separately encrypted,
carrier-neutral unreliable-message channel. Those implementation details do
not change the public connector or session contract.

Transport v2 production carrier support: raw QUIC direct client dialing and runtime-owned direct server listening, plus tunnel dialing for both session roles.

Flowersec disables application 0-RTT. Reliable streams never use QUIC DATAGRAM; runtimes with negotiated native DATAGRAM expose it only through carrier-neutral unreliable messages.

## Public API

The crate root exports only these public categories:

- opaque artifact lifecycle: `Artifact`, `ArtifactError`, `ArtifactLease`, and
  `ArtifactSpendError`;
- connection lifecycle: `ConnectorOptions`, `connect(...)`, `ConnectError`, and
  `ConnectErrorCode`;
- recovery policy: `ErrorRetryAction`, `ErrorRetryClassification`,
  `classify_connect_error(...)`, and `classify_session_error(...)`;
- runtime-owned direct acceptance: `AcceptorOptions`, `Acceptor`,
  `AcceptError`, and `AcceptErrorCode`;
- carrier-neutral session behavior: `Session`, `SessionTermination`, `RpcPeer`, `ByteStream`,
  `IncomingStream`, and `JsonObject`;
- negotiated unreliable messages: `UnreliableMessageChannel`,
  `UnreliableMessageError`, and `UnreliableSendOutcome`;
- closed operation failures: `SessionError` and `StreamTerminalError`;
- bounded remote application failures: `RpcError`, `RpcCallError`, and typed
  `RpcPeerExt::call_typed(...)` convenience over the object-safe JSON core.

Parse an opaque artifact with `Artifact::parse`, bind its durable single-use
callback with `ArtifactLease`, and establish a session through `connect(...)`.
Native server runtimes bind `Acceptor` with explicit TLS and resource policy,
then pass an opaque `Artifact` to `accept`; successful acceptance returns the
same carrier-neutral `Session` interface. Duplicate concurrent registration of
one artifact fails closed, and cancellation and artifact expiry bound the
complete accept operation. One `Acceptor` admits one pending artifact at a
time; runtimes use independent acceptors when sessions must wait concurrently.
`Session` exposes RPC, logical streams, rekey, liveness, `wait_termination`,
which returns a stable `SessionTermination`, and bounded close. It does not
expose route or carrier selection, endpoint identity, stream identifiers,
candidates, wire data, keys, or transport diagnostics.

When negotiated, `UnreliableMessageChannel::send(...)` returns
`UnreliableSendOutcome::Accepted`, `DroppedExpired`, `DroppedBudget`, or
`DroppedCarrier`. Invalid payloads, unavailable channels, oversized messages,
cancellation, closure, and internal failures remain public operation errors.

`ConnectErrorCode`, `AcceptErrorCode`, `SessionError`, and
`StreamTerminalError` are closed, redacted failure sets. `ConnectErrorCode::as_str()`
and `AcceptErrorCode::as_str()` return stable snake_case public code strings.
`RpcCallError` keeps a bounded remote `RpcError` separate from session failure;
its generic display omits the sanitized application message unless the caller
explicitly requests it. Public errors do not retain peer payloads, carrier
diagnostics, credentials, or cryptographic material. `SessionError` uses the
portable terminal-state names consumed by the shared recovery classifier and
does not retain overlapping generic compatibility variants.

The recovery classifiers distinguish retrying an operation on the current
session from acquiring a fresh artifact and session. They never authorize reuse
of a durably committed lease or credential.

## Capability Layers

The portable core is the same application model used by every Flowersec SDK:
opaque artifact parsing, a durable single-use lease, one-shot connection,
carrier-neutral sessions, RPC, reliable streams, redacted public errors, and
error classifiers. `classify_connect_error(...)` and
`classify_session_error(...)` return the stable cross-language recovery decision;
callers should not compare raw Rust error variants with other SDKs.

The Rust SDK profile owns native raw QUIC dialing and runtime-owned direct
acceptance through `Acceptor`. Its language convenience is `RpcPeerExt`, which
adds typed JSON encoding and decoding over the object-safe RPC core without
making that exact method shape part of the portable core.

## Runtime Boundaries

Rust owns the native Tokio implementation of the portable contract. Browser
runtime APIs remain TypeScript-owned, while shared tunnel, gateway, and helper
binaries remain Go-owned.
