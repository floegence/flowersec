# Flowersec for Rust

The Tokio-native Rust SDK for Flowersec end-to-end encrypted direct and tunneled sessions. It implements the legacy v1 portable stack plus Transport v2 wire/session primitives and a tested raw QUIC adapter.

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
`flowersec-tunnel` remains a v1 WebSocket/Yamux CLI.

Transport v2 production carrier support: none; raw QUIC remains public and tested but is not a production capability tuple.

Rust currently advertises no production Transport v2 carrier tuple: complete `ArtifactV2` acquisition, equal-candidate durable-spend connection ownership, and server admission are not yet committed as one production connector. Existing `connect`, controlplane, proxy, and Yamux examples remain v1. See the [Transport v2 architecture](../docs/TRANSPORT_V2_ARCHITECTURE.md) and [migration guide](../docs/MIGRATION_TRANSPORT_V2.md).

## Cookbook

Start with the [Rust cookbook](https://github.com/floegence/flowersec/tree/main/examples/rust). Its runnable client covers artifact fetch, tunnel connect, typed RPC, custom streams, liveness, HTTP proxy, and WebSocket proxy. Crate tests provide executable endpoint, reconnect, controlplane, and policy references.

## Entrypoints

- Client connect: `connect`, `connect_direct`, and `connect_tunnel`
- Endpoint sessions: `endpoint::{accept_direct, accept_direct_resolved, connect_tunnel}`
- RPC: `rpc::{RpcClient, Router, Server}`
- Streams: `yamux::YamuxStream`
- Controlplane: `controlplane`
- Reconnect: `reconnect::ReconnectManager`
- Proxy: `proxy::{ProxyClient, ProxyServer}`
- Diagnostics: `observability`
- Transport v2 protocol/session: `protocol_v2`, `session_v2`, and `transport_v2`
- Tested non-advertised raw QUIC adapter: `raw_quic_v2`

High-level WebSocket connections require TLS by default. Use `TransportSecurityPolicy::allow_plaintext_for_loopback()` only for literal local development targets.

Endpoint servers should accept raw async streams with `TungsteniteTransport::accept(...)`; it applies Flowersec's encrypted-record message and frame limits and bounds the HTTP WebSocket upgrade with the default handshake timeout. Use `accept_with_timeout(...)` to select a different upgrade deadline. `TungsteniteTransport::new(...)` returns `io::Result` and rejects a supplied `WebSocketStream` unless it already enforces equivalent or stricter message and frame limits.

## Proxy Server

`ProxyServer` streams HTTP request and response chunks directly between the Flowersec stream and reqwest. `ServerOptions.max_concurrent_streams` independently caps active HTTP and WebSocket proxy streams; use `flowersec::defaults::PROXY_MAX_CONCURRENT_STREAMS` for the shared default of 64. Excess streams are reset immediately.

## Liveness

Client and endpoint options expose `yamux::LivenessOptions`:

- `PathDefault` disables automatic probes for direct sessions and derives tunnel probes from the grant idle timeout.
- `Disabled` disables automatic probes for either path.
- `Enabled { interval, timeout }` uses explicit positive durations.

The path-default tunnel interval is half the idle timeout with a 500 ms minimum; the probe timeout is the smaller of 10 seconds and that interval. Existing manual `probe_liveness(...)` methods remain available independently of automatic probes. A manual probe timeout is terminal: it closes the session because transport liveness can no longer be established safely.

The release introducing these public option fields is a pre-1.0 source change. Consumers that construct `ConnectOptions`, `EndpointOptions`, or `DirectAcceptOptions` with exhaustive struct literals must set `liveness` or use `..Default::default()`. The same release changes `TungsteniteTransport::new(...)` to return `io::Result` so an unbounded injected stream cannot silently bypass the encrypted-record transport limit.

## Runtime Boundaries

Rust owns the native Tokio implementation of the portable contract. Browser runtime APIs remain TypeScript-owned, while shared tunnel, gateway, and helper binaries remain Go-owned.

Review the shared [API contract](../docs/API_CONTRACT.md), [protocol](../docs/PROTOCOL.md), [threat model](../docs/THREAT_MODEL.md), and [error model](../docs/ERROR_MODEL.md).
