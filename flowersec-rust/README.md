# Flowersec for Rust

The `flowersec` crate is the Tokio-native SDK for end-to-end encrypted
sessions, RPC, notifications, and reliable byte streams. It supports Rust 1.88
or newer on Linux, macOS, and Windows and contains no Flowersec-authored
`unsafe`.

## Install

```bash
cargo add flowersec
```

## Public API

Parse an invitation with `Artifact::parse`, bind its durable single-use spend
callback with `ArtifactLease`, and establish a Session through `connect(...)`.
The public application surface includes `Session`, `RpcPeer`, `ByteStream`,
`IncomingStream`, `StreamMetadata`, `StreamHandlers`, negotiated
`UnreliableMessageChannel`, and typed RPC through `RpcPeerExt::call_typed(...)`.

```rust,no_run
# async fn run(lease: flowersec::ArtifactLease, roots: Vec<Vec<u8>>) -> Result<(), Box<dyn std::error::Error>> {
let options = flowersec::ConnectorOptions::new()
    .with_trust_roots_der(roots)?;
let session = flowersec::connect(lease, options).await?;
session.probe_liveness(tokio_util::sync::CancellationToken::new()).await?;
session.close().await?;
# Ok(()) }
```

`ConnectionController` owns long-lived reconnection. Each attempt acquires a
fresh lease and creates a new Session; it never migrates or replays work from a
terminated Session.

`StreamHandlers` serves bounded application stream handlers on any established
Session. `RpcHandlers` configures client RPC and notification callbacks.
`SessionHandlers` configures accepted server Sessions and composes the same
stream dispatcher.

## Server APIs

Rust exposes the direct `Acceptor`, opaque `TunnelRuntime`, and carrier-neutral
`ProxyServer`. The proxy implements the bounded HTTP and WebSocket application
wire shared with the TypeScript browser runtime.

Reliable stream shutdown is explicit: `close_write()` sends a graceful FIN and
keeps reads available, while `reset()` and `close()` abort both directions.
Handler failures reset only their stream.

## Supported Connections

Rust supports direct and relayed WebSocket and raw QUIC client connections,
direct server acceptance, and opaque relay listeners. It does not provide an
artifact issuer or WebTransport adapter. Deployments issue artifacts through
an application control plane such as the Go control-plane package.

CA candidates use platform or explicit DER trust roots. Pin candidates use only
the active artifact-bound leaf-certificate SHA-256 pins and never fall back to
CA verification. No system trust store is selected implicitly outside the
explicit CA policy. Public errors are closed and redacted; credentials,
candidate selection, and protocol state remain private.

See the [Rust cookbook](../examples/rust/README.md),
[API contract](../docs/API_CONTRACT.md),
[Transport v3 architecture](../docs/TRANSPORT_V3_ARCHITECTURE.md),
[wire contract](../docs/TRANSPORT_V3_WIRE.md), and
[error model](../docs/ERROR_MODEL.md).
