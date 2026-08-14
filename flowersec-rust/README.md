# Flowersec for Rust

The `flowersec` crate is the Tokio-native Rust SDK for end-to-end encrypted
sessions, RPC, notifications, and reliable byte streams.

The crate targets Rust 1.88 or newer on Linux, macOS, and Windows, uses rustls
by default, and contains no Flowersec-authored `unsafe`.

## Install

```bash
cargo add flowersec
```

TLS connection candidates require explicit, non-empty DER trust roots. Exact-loopback
plaintext direct WebSocket candidates do not require trust roots; no system trust
store is selected implicitly:

```rust,no_run
# async fn connect_example(
#     lease: flowersec::ArtifactLease,
#     root_der: Vec<u8>,
# ) -> Result<(), Box<dyn std::error::Error>> {
let options = flowersec::ConnectorOptions::new()
    .with_trust_roots_der(vec![root_der])?;
let session = flowersec::connect(lease, options).await?;
# session.close().await?;
# Ok(())
# }
```

## Supported Connections

The native Rust runtime uses WebSocket and raw QUIC for direct and relayed client sessions,
accepts both carriers for direct server sessions, and
provides opaque tunnel listeners for both carriers. WebTransport is an optional
adapter profile and the Rust runtime does not currently expose a production
adapter. Connection selection, credentials, and protocol
state stay inside the crate.

## Public API

The crate gives applications these building blocks:

- `Artifact` and `ArtifactLease` for a short-lived, single-use connection invitation;
- `connect(...)`, `ConnectError`, and `ConnectorOptions` for opening a session;
- `Session`, `RpcPeer`, `ByteStream`, `IncomingStream`, and `StreamMetadata` for application traffic;
- `ConnectionController` for reconnecting with a fresh invitation after a session ends;
- `Acceptor`, `AcceptedSession`, and `SessionHandlers` for server-side sessions;
- `TunnelRuntime` for authorized opaque relay pairing without application Session access;
- `controlplane::Issuer`, `AuthorizationRecord`, and runtime authorization types;
- `ProxyServer` for bounded HTTP and WebSocket forwarding over application Sessions;
- `UnreliableMessageChannel` when the negotiated connection supports it;
- typed RPC helpers through `RpcPeerExt::call_typed(...)`.

Parse an invitation with `Artifact::parse`, bind its durable single-use callback
with `ArtifactLease`, and establish a session through `connect(...)`. A
terminated session is never silently migrated or replayed; the controller
creates a new session from a new invitation.

### One-shot client

```rust,no_run
# async fn run(lease: flowersec::ArtifactLease, roots: Vec<Vec<u8>>) -> Result<(), Box<dyn std::error::Error>> {
let options = flowersec::ConnectorOptions::new()
    .with_trust_roots_der(roots)?;
let session = flowersec::connect(lease, options).await?;
# Ok(()) }
```

### Long-lived client

```rust,no_run
# fn build(source: std::sync::Arc<dyn flowersec::ArtifactSource>, roots: Vec<Vec<u8>>) {
let connector = flowersec::ConnectorOptions::new()
    .with_trust_roots_der(roots).unwrap();
let controller = flowersec::ConnectionController::new(
    source,
    flowersec::ConnectionControllerOptions::new(connector),
);
controller.start();
# }
```

Every Controller generation uses the same immutable callback definition and a
fresh router. Work from a terminated Session is not migrated or replayed.

For the complete durable `ArtifactLease` spend workflow, see the
[Rust cookbook](../examples/rust/README.md). The spend record must be committed
before the connector can send connection credentials.

### Accepted server Session

```rust,no_run
# async fn serve(acceptor: flowersec::Acceptor, artifact: flowersec::Artifact) -> Result<(), Box<dyn std::error::Error>> {
let handlers = flowersec::SessionHandlers::new(Default::default())?;
let accepted = acceptor.accept_with_handlers(
    &artifact,
    handlers,
    tokio_util::sync::CancellationToken::new(),
).await?;
accepted.serve(tokio_util::sync::CancellationToken::new()).await?;
# Ok(()) }
```

`RpcHandlers` is client-only and has no stream API. `SessionHandlers` belongs
to accepted server Sessions and keeps stream dispatch under `AcceptedSession`.

Reliable stream shutdown is explicit: `close_write()` sends a graceful FIN and
keeps the receive direction available, while `reset()` and `close()` abort both
directions and release local stream capacity. A stream failure remains isolated
from unrelated streams in the same Session.

`Acceptor` accepts one pending invitation at a time. Use
`accept_with_handlers(...)` when the server owns inbound RPC and stream
dispatch. A handler error affects only that stream, while unrelated streams
continue to be served.

## Long-Lived Connections

`ConnectionController` is the single owner of reconnect behavior. Every attempt
gets a fresh `ArtifactLease`, and callers receive clear `idle`, `connecting`,
`connected`, `waiting`, `failed`, and `closed` states. Retry decisions are
structured; applications do not need to infer policy from error text or run a
second retry loop.

## Security

Artifacts are opaque and single-use. Public connection and session errors are
bounded and redacted, and relays forward encrypted traffic without reading
application data.

See the [API contract](../docs/API_CONTRACT.md), [transport architecture](../docs/TRANSPORT_V2_ARCHITECTURE.md),
[threat model](../docs/THREAT_MODEL.md), and [error model](../docs/ERROR_MODEL.md).
