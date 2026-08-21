# Flowersec for Rust

The `flowersec` crate is the Tokio-native Rust SDK for end-to-end encrypted
sessions, RPC, notifications, and reliable byte streams.

The crate targets Rust 1.88 or newer on Linux, macOS, and Windows, uses rustls
by default, and contains no Flowersec-authored `unsafe`.

## Install

```bash
cargo add flowersec
```

CA candidates use platform trust roots by default and may use explicit,
non-empty DER roots for a deployment-provided private CA. Pin candidates use
only the active leaf-certificate SHA-256 pins carried by the opaque artifact;
they never fall back to CA verification. No system trust store is selected
implicitly outside the explicit CA policy:

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
under the strict v3 profile, and also exposes the v3 direct `Acceptor` plus opaque `TunnelRuntime` server
boundaries. It does not expose an artifact issuer or a WebTransport adapter. Deployments issue
v3 artifacts through an application-owned control plane, such as the Go control-plane package;
the Rust server runtimes accept only opaque validated authorization responses. The explicit
`flowersec::v2` namespace contains the legacy v2 client, acceptor, issuer, and tunnel runtime.
Connection selection, credentials, and protocol state stay inside the crate.

## Public API

The crate gives applications these building blocks:

- `Artifact` and `ArtifactLease` for a short-lived, single-use connection invitation;
- `connect(...)`, `ConnectError`, and `ConnectorOptions` for opening a session;
- `Session`, `RpcPeer`, `ByteStream`, `IncomingStream`, and `StreamMetadata` for application traffic;
- `StreamHandlers` for bounded application-stream dispatch on any established Session;
- `ConnectionController` for reconnecting with a fresh invitation after a session ends;
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

### Application streams on any Session

```rust,no_run
# async fn serve(session: &dyn flowersec::Session) -> Result<(), Box<dyn std::error::Error>> {
let mut handlers = flowersec::StreamHandlers::new(Default::default())?;
handlers.handle_stream("files/read", MyStreamHandler)?;
handlers
    .serve(session, tokio_util::sync::CancellationToken::new())
    .await?;
# Ok(()) }
# struct MyStreamHandler;
# #[async_trait::async_trait]
# impl flowersec::StreamHandler for MyStreamHandler {
#   async fn handle(&self, _: &flowersec::IncomingStream, _: tokio_util::sync::CancellationToken) -> Result<(), flowersec::SessionError> { Ok(()) }
# }
```

Application stream kinds contain 1 through 128 canonical UTF-8 bytes and
exclude the package-owned `flowersec.rpc.v2` and `flowersec.rpc.v3` kinds.
Unknown, excess, failed, and
panicked handler streams are reset without terminating unrelated dispatch.

For the complete durable `ArtifactLease` spend workflow, see the
[Rust cookbook](../examples/rust/README.md). The spend record must be committed
before the connector can send connection credentials.

### Explicit v2 server Session

```rust,no_run
# async fn serve(acceptor: flowersec::v2::Acceptor, artifact: flowersec::v2::Artifact) -> Result<(), Box<dyn std::error::Error>> {
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
to accepted server Sessions and composes the same stream dispatcher under
`AcceptedSession`.

Reliable stream shutdown is explicit: `close_write()` sends a graceful FIN and
keeps the receive direction available, while `reset()` and `close()` abort both
directions and release local stream capacity. A stream failure remains isolated
from unrelated streams in the same Session.

`flowersec::v2::Acceptor` accepts one pending v2 invitation at a time. Use
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

See the [API contract](../docs/API_CONTRACT.md), [transport architecture](../docs/TRANSPORT_V3_ARCHITECTURE.md), [v3 wire contract](../docs/TRANSPORT_V3_WIRE.md),
[threat model](../docs/THREAT_MODEL.md), and [error model](../docs/ERROR_MODEL.md).
