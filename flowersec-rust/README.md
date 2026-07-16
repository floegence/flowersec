# Flowersec for Rust

The Tokio-native Rust SDK for Flowersec end-to-end encrypted direct and tunneled sessions. It implements the portable client, endpoint, RPC, stream, controlplane, reconnect, proxy, and observability contract.

The crate targets Rust 1.85 or newer on Linux, macOS, and Windows, uses rustls by default, and contains no Flowersec-authored `unsafe`.

## Install

```bash
cargo add flowersec
```

The default feature uses native root certificates. Use `default-features = false, features = ["rustls-webpki-roots"]` for an embedded WebPKI root set.

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

High-level WebSocket connections require TLS by default. Use `TransportSecurityPolicy::allow_plaintext_for_loopback()` only for literal local development targets.

## Runtime Boundaries

Rust owns the native Tokio implementation of the portable contract. Browser runtime APIs remain TypeScript-owned, while shared tunnel, gateway, and helper binaries remain Go-owned.

Review the shared [API contract](../docs/API_CONTRACT.md), [protocol](../docs/PROTOCOL.md), [threat model](../docs/THREAT_MODEL.md), and [error model](../docs/ERROR_MODEL.md).
