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

Clone `RpcHandlers` to share an immutable method table across listeners and connecting sessions. Adding a handler to one clone creates a separate definition without changing sessions that already use it. Notification subscriptions, outstanding requests and waiters belong to each session. `with_rpc_concurrency` limits live calls and running handlers, not registrations or lifetime calls. The first outbound call or notification opens the RPC stream for that direction; subsequent messages reuse it. Exhausting the wire request-ID space returns `rpc_request_ids_exhausted` before the call is sent.

Each tunnel credential contains only that endpoint's authorized ingress candidates and TLS policies. Use `ConnectorOptions::with_tunnel_ingress` to select a particular local address; an unmatched selection fails before dialing or spending. Without an explicit selection, the connector races supported candidates in its own credential. On the relay, `with_public_ingress` binds a configured public address to its listener, and `add_ingress` adds another independently routed socket to the same pairing authority. Deliver a `TunnelVerificationRecord` to the relay separately from the endpoint invitations; the record contains candidate admission hashes, expected peer identity, scope and expiry, and no session key.

RPC encodes a complete JSON envelope with a four-byte length prefix. Both `ConnectorOptions` and `Acceptor` accept `with_rpc_frame_limit(RpcFrameLimit)`. The default is 1 MiB of encoded JSON; configure both peers to send larger messages. This is separate from the reliable byte stream and the proxy's `max_websocket_frame_bytes` payload limit.

## Server APIs

For direct listeners behind a port forward or using a multi-name certificate, `Acceptor::with_public_endpoint` binds admission to the trusted external direct URL. The presented certificate must still satisfy the invitation's TLS policy.

Buffered HTTP uploads share a per-`ProxyServer` memory budget of 64 MiB or the configured `max_body_bytes`, whichever is greater. Requests that exceed the available budget receive `resource_exhausted` without contacting the upstream.

Rust exposes the direct `Acceptor`, opaque `TunnelRuntime`, and carrier-neutral
`ProxyServer`. The proxy implements the bounded HTTP and WebSocket application
wire shared with the TypeScript browser runtime.

`Acceptor::serve` starts with zero invitations. Its `DirectAuthorizer` looks up the presented channel in the host store and returns a single-use `ArtifactLease` with the handlers authorized for it. The SDK verifies the complete presented admission and awaits durable spend before acknowledging. The optional `connected` callback can initiate outbound work; incoming RPC never waits for the application to take a session. Live permissions at business effects, durable anti-rollback storage and writer fencing belong to the deployment. A policy requiring fresh designated-peer proof of possession on this leg cannot be served by this protocol.

`Acceptor::accept` and `accept_with_handlers` also require an `ArtifactLease`. For Direct and either Tunnel endpoint, bind the spend callback to an atomic operation in your own store; it may return success only after durable commit. A missing record, replay, or uncertain commit must fail closed, including after restart. If the transaction also creates a connection reservation, `ArtifactLease::new_with_release` attaches its release to session cleanup. Release the reservation by its unique ID and keep the spent credential spent. The relay uses `TunnelAuthorizer::authorize` and `release` for the same two distinct operations. The core crate does not require SQLite or a database driver.

Reliable stream shutdown is explicit: `close_write()` sends a graceful FIN and
keeps reads available, while `reset()` and `close()` abort both directions.
Handler failures reset only their stream.

## Supported Connections

Rust supports direct and relayed WebSocket and raw QUIC connections. To dial a
signed HTTPS WebTransport candidate, pass an exact Origin with
`ConnectorOptions::with_webtransport_origin`. For a direct server, use
`Acceptor::bind_webtransport`; for relay ingress, use `TunnelRuntime::bind_webtransport`.
Both accept `WebTransportListenerPolicy::new(host, origins)` and have an
`_on_socket` variant for deployments that issue routes against a bound UDP socket.
The dedicated CONNECT connection carries reliable streams and negotiated native
datagrams using draft02. Go clients dialing these listeners require an explicit raw QUIC route instead. Deployments issue artifacts through an application control plane
such as the Go control-plane package.

CA candidates use platform or explicit DER trust roots. Pin candidates use only
the active artifact-bound leaf-certificate SHA-256 pins and never fall back to
CA verification. No system trust store is selected implicitly outside the
explicit CA policy. Public errors are closed and redacted; credentials,
candidate selection, and protocol state remain private.

See the [Rust cookbook](../examples/rust/README.md),
[API contract](../docs/API_CONTRACT.md),
[Transport v5 architecture](../docs/TRANSPORT_V5_ARCHITECTURE.md),
[wire contract](../docs/TRANSPORT_V5_WIRE.md), and
[error model](../docs/ERROR_MODEL.md).
