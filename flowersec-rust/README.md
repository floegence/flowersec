# Flowersec for Rust

`flowersec` is the native Tokio SDK for Flowersec direct and tunneled end-to-end encrypted sessions. It implements the same portable wire, security, session, RPC, endpoint, controlplane, reconnect, proxy, and observability contract as the Go, TypeScript, and Swift SDKs.

The crate targets Rust 1.85 or newer on Linux, macOS, and Windows. It uses rustls by default, contains no Flowersec-authored `unsafe`, and keeps endpoint APIs independent of Axum, Actix, or another web framework.

## Install

```bash
cargo add flowersec@0.22.0
```

The default feature uses native root certificates. Use `default-features = false, features = ["rustls-webpki-roots"]` when an embedded WebPKI root set is preferred.

## Artifact-first connect

```rust
use flowersec::{ConnectOptions, connect};
use flowersec::controlplane::client::{
    ConnectArtifactRequestConfig,
    request_connect_artifact,
};

let mut request = ConnectArtifactRequestConfig::new("endpoint-123");
request.base_url = "https://controlplane.example.com".to_owned();
let artifact = request_connect_artifact(request).await?;
let client = connect(artifact, ConnectOptions::default()).await?;
```

`connect_direct(...)` and `connect_tunnel(...)` accept the corresponding generated wire value directly. High-level connections reject plaintext by default; local `ws://` development requires `TransportSecurityPolicy::allow_plaintext_for_loopback()`.

## RPC and streams

```rust
#[derive(serde::Serialize)]
struct PingRequest {}

#[derive(serde::Deserialize)]
struct PingResponse { ok: bool }

let response: PingResponse = client.rpc().call_typed(1, &PingRequest {}).await?;
assert!(response.ok);

let stream = client.open_stream("logs").await?;
stream.write(b"follow").await?;
let reply = stream.read_exact(2).await?;
```

IDL-generated clients and handlers build on `rpc::RpcClient`, `rpc::Router`, and `rpc::Server`. Calls, notifications, timeouts, cancellation, concurrency, and queues use bounded defaults from `stability/sdk_defaults.json`.

## Endpoint server

Use `endpoint::accept_direct(...)` with any `WebSocketTransport`, or use `endpoint::connect_tunnel(...)` with a server-role grant. The returned `endpoint::Session` accepts typed RPC and custom streams without binding the SDK to a web framework. `transport::TungsteniteTransport` is provided for accepted or connected tungstenite streams.

## Reconnect and proxy

`reconnect::ReconnectManager` accepts one-shot, refreshable, and controlplane artifact sources. Automatic reconnect requires a refreshable source and stops on terminal validation or authentication failures.

`proxy::ProxyClient` and `proxy::ProxyServer` implement the stable HTTP/1 and WebSocket stream protocols, including fixed upstream targets, loopback-only defaults, Origin policy, header filtering, cookie isolation, and body/frame limits.

## Runtime ownership

The Rust SDK intentionally does not duplicate browser Service Worker APIs or deployable tunnel/proxy gateway binaries. Browser runtime ownership remains with TypeScript; shared deployables and CLIs remain Go-owned.
