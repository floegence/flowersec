# Flowersec for Rust

The `flowersec` crate is the Tokio-native Rust SDK for end-to-end encrypted
sessions, RPC, notifications, and reliable byte streams.

The crate targets Rust 1.88 or newer on Linux, macOS, and Windows, uses rustls
by default, and contains no Flowersec-authored `unsafe`.

## Install

```bash
cargo add flowersec
```

The raw QUIC connection profile requires explicit DER trust roots and rejects empty roots:

```rust
let options = flowersec::ConnectorOptions::new(vec![root_der])?;
let session = flowersec::connect(&mut lease, options).await?;
```

## Supported Connections

The native Rust runtime uses WebSocket and raw QUIC for direct and relayed client sessions,
accepts both carriers for direct server sessions, and
provides opaque tunnel listeners for both carriers. WebTransport is
unsupported because no Rust driver has passed Flowersec's strict draft-15 and
cross-runtime contracts. Connection selection, credentials, and protocol
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
