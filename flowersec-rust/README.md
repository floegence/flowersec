# Flowersec for Rust

The `flowersec` crate is the Tokio-native SDK for end-to-end encrypted
sessions, RPC, notifications, and reliable byte streams. It supports Rust 1.88
or newer on Linux, macOS, and Windows and contains no Flowersec-authored
`unsafe`.

## Install

```bash
cargo add flowersec
```

## Explicit transport v4 WSS

`V4TransportEnvironment::connect_pool_wss` establishes one direct network WSS
candidate from a preauthorized pool with the transport application profile.
The caller supplies an original trusted-time Environment, verified namespace
handles, generated identity keys, exact signed material, independent SQLite
continuity and one fixed numeric address. CA verification uses explicit roots;
DER pin verification uses only the signed active leaf certificates. Both modes
require and check TLS 1.3. The caller runs a Tokio multithread runtime.

The resulting `V4Session` supports reliable streams, rekey, authenticated
liveness, Drain and physical cleanup observation. Fixed handshake, record,
stream and rekey backing is reserved before irreversible SQLite consumption.
`V4ConnectError::Spent` explicitly identifies later connection failures.
`connect_pool_wss_with_handler_plan` captures the same immutable
`V4HandlerPlan` used by Serve before pool consumption. Its caller supplies
`V4ApplicationLimits`; registered raw-stream handlers or explicit manual
acceptance are ready at READY, and their work remains charged through actual
Session and callback cleanup.

`V4TransportEnvironment::serve_pool_wss` also accepts direct pool WSS Sessions
through original trusted material and durable ParentWinner/AdmissionLedger
owners. `V4ServeHandle` owns bounded acceptance, Drain, Close and cleanup.
`V4WssServeOptions` fixes the five `V4ServeCallbacks`, application callback
budgets and parent cancellation. Application authorization reserves its original
lease after FSB authentication and before durable admission. Immutable
`V4HandlerPlan` declarations support registered raw-stream handlers or explicit
manual Stream acceptance. READY publication, callback exit, lease cleanup and
provider cleanup retain their original owners and resource charges.

These entrances do not provide candidate racing, live-authority activation,
relay/QUIC/WebTransport, datagrams or v4 application RPC/controller
assembly. Its resource ledger separately bounds all eleven SDK/provider/disk,
item, work, task, timer, connection, handshake, Session and native-handle
dimensions. Full provider/deployment qualification remains unfinished.
See [Rust transport v4](../docs/RUST_TRANSPORT_V4.md) for composition and bounds.

## Strict-v3 public API

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
session.probe_liveness().await?;
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

## Strict-v3 server APIs

Rust exposes the direct `Acceptor`, opaque `TunnelRuntime`, and carrier-neutral
`ProxyServer`. The proxy implements the bounded HTTP and WebSocket application
wire shared with the TypeScript browser runtime.

Reliable stream shutdown is explicit: `close_write()` sends a graceful FIN and
keeps reads available, while `reset()` and `close()` abort both directions.
Handler failures reset only their stream.

## Supported Connections

### Transport v3

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
