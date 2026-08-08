# Flowersec for Rust

The `flowersec` crate is the Tokio-native Rust SDK for Flowersec v2 end-to-end
encrypted sessions. Its maintained public entrypoints use opaque artifacts, the
carrier-neutral one-shot `connect(...)` function, and `Session`.

Flowersec 2.1.0 is the coordinated Rust crate release.

The crate targets Rust 1.88 or newer on Linux, macOS, and Windows, uses rustls
by default, and contains no Flowersec-authored `unsafe`.

## Install

```bash
cargo add flowersec@2.1.0
```

The production raw QUIC connection profile requires explicit DER trust roots.
`ConnectorOptions::new(...)` rejects empty roots and creates a valid option value
with the shared ten-second connection timeout.

```rust
let options = flowersec::ConnectorOptions::new(vec![root_der])?;
let session = flowersec::connect(&mut lease, options).await?;
```

## Transport v2 Support

WebSocket, raw QUIC, and WebTransport are equal carrier candidates.
Raw QUIC and WebTransport preserve native FIN, RESET_STREAM, STOP_SENDING, flow control, and migration behavior.

The native Rust runtime implements raw QUIC only. WebSocket and WebTransport
are explicitly unsupported; parsing their carrier kinds does not advertise a
runtime implementation. Runtime, carrier, direct/tunnel topology, network
mode, session role, reliable streams, DATAGRAM, and migration are independent
capability dimensions.

Raw QUIC preserves native FIN, RESET_STREAM, STOP_SENDING, flow control,
DATAGRAM, and client-owned active migration behavior.

Rust publishes an opaque Transport v2 connector and a carrier-neutral session
contract. Transport selection, topology, candidates, wire state, credentials,
keys, and endpoint identities are unavailable to crate consumers.

The production runtime adapter implements raw QUIC dialing internally. It
uses native bidirectional QUIC streams without Yamux, requires caller-provided
trust material, disables 0-RTT, and is covered by Go interoperability tests.
Negotiated native DATAGRAM is used only by the separately encrypted,
carrier-neutral unreliable-message channel. Those implementation details do
not change the public connector or session contract.

Transport v2 production carrier support: raw QUIC direct client dialing, runtime-owned direct server listening, and tunnel dialing for both session roles. Unsupported carrier artifacts return `runtime_unsupported` before any credential is committed.

Flowersec disables application 0-RTT. Reliable streams never use QUIC DATAGRAM; runtimes with negotiated native DATAGRAM expose it only through carrier-neutral unreliable messages.

## Public API

The crate root exports only these public categories:

- opaque artifact lifecycle: `Artifact`, `ArtifactError`, `ArtifactLease`, and
  `ArtifactSpendError`;
- connection lifecycle: `ConnectorOptions`, `connect(...)`, `ConnectError`, and
  `ConnectErrorCode`;
- long-lived connection ownership: `ConnectionController`,
  `ConnectionControllerOptions`, `ArtifactSource`, `ArtifactSourceError`,
  `ConnectionState`, `ConnectionFailure`, `ConnectionSnapshot`, and
  `RetryDisposition`;
- runtime-owned direct acceptance: `AcceptorOptions`, `Acceptor`,
  `AcceptError`, and `AcceptErrorCode`;
- carrier-neutral session behavior: `Session`, `SessionTermination`, `RpcPeer`, `ByteStream`,
  `IncomingStream`, `JsonObject`, `StreamMetadata`, and `StreamMetadataError`;
- negotiated unreliable messages: `UnreliableMessageChannel`,
  `UnreliableMessageError`, and `UnreliableSendOutcome`;
- closed operation failures: `SessionError`, including byte-stream terminal state;
- bounded remote application failures: `RpcError`, `RpcCallError`, and typed
  `RpcPeerExt::call_typed(...)` convenience over the object-safe JSON core.

Parse an opaque artifact with `Artifact::parse`, bind its durable single-use
callback with `ArtifactLease`, and establish a session through `connect(...)`.
Construct application stream metadata with `StreamMetadata::try_from(...)`, or
use `StreamMetadata::empty()`; invalid values fail before `Session::open_stream`.
The lease deliberately exposes no connector-owned committed-state accessor.
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

`ConnectErrorCode`, `AcceptErrorCode`, and `SessionError` are closed, redacted
failure sets. `ConnectErrorCode::as_str()`
and `AcceptErrorCode::as_str()` return stable snake_case public code strings.
`RpcCallError` keeps a bounded remote `RpcError` separate from session failure;
its generic display omits the sanitized application message unless the caller
explicitly requests it. Public errors do not retain peer payloads, carrier
diagnostics, credentials, or cryptographic material. `SessionError` uses the
portable terminal-state names consumed by the connection controller and does
not retain overlapping generic variants. Controller retry ownership is private:
public error codes remain stable descriptions and do not authorize credential
reuse or another connection attempt.

## Long-Lived Connections

`ConnectionController` is the optional single owner of long-lived connection
intent above the one-shot `connect(...)` API. A refreshable `ArtifactSource`
returns a new independently spendable `ArtifactLease` for every attempt. The
controller exposes `idle`, `connecting`, `connected`, `waiting`, `failed`, and
`closed` states, runs one scheduler and one attempt at a time, and uses only
structured terminal, retryable, or retry-after decisions. An artifact source
must explicitly return one of those decisions; unclassified source failures are
terminal and are never interpreted from error text.

The default deterministic exponential retry policy starts at 250 milliseconds,
doubles without jitter, caps at 30 seconds, and has no attempt limit. A finite
attempt limit is available only through `ConnectionControllerOptions::with_maximum_attempts`.
`retry_now()` wakes only a waiting controller and never overrides a supplied
retry-after deadline. `close()` cancels artifact acquisition, connection, and
waiting, then closes the current session.

Every successful replacement establishes a new `Session` from a fresh artifact.
A terminated session is removed before retry begins, and the next session is
published only after it establishes. Old streams, RPCs, and writes fail with
their old session and are never migrated or replayed by the controller.

## Capability Layers

The portable core is the same application model used by every Flowersec SDK:
opaque artifact parsing, a durable single-use lease, one-shot connection,
carrier-neutral sessions, RPC, reliable streams, redacted public errors, and
structured controller retry decisions. The controller owns the mapping from
connection and session failures to terminal, retryable, or absolute
`retry_after` behavior; callers do not infer policy from error text.

Only this portable core is required to align across languages. Complete SDK
profiles and language conveniences intentionally differ by runtime.

The Rust SDK profile owns native raw QUIC dialing and runtime-owned direct
acceptance through `Acceptor`. Candidate admission is carrier-neutral and
advances through attempt, ready, winner, admitted, established, and terminated;
the raw QUIC adapter owns only UDP, TLS/ALPN, native streams, DATAGRAM,
migration, and transport close. Its language convenience is `RpcPeerExt`,
which adds typed JSON encoding and decoding over the object-safe RPC core.

## Runtime Boundaries

Rust owns the native Tokio implementation of the portable contract. Browser
runtime APIs remain TypeScript-owned, while shared tunnel, gateway, and helper
binaries remain Go-owned.
