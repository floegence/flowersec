# Flowersec Swift

The native Swift SDK for Flowersec end-to-end encrypted direct and tunneled sessions. It implements the portable client, endpoint, RPC, stream, controlplane, reconnect, proxy, and observability contract for Apple platforms.

## Install

The repository root exposes the Swift package:

```swift
.package(url: "https://github.com/floegence/flowersec.git", from: "0.24.0")
```

Use the `Flowersec` library product.

## Cookbook

Start with the [Swift cookbook](https://github.com/floegence/flowersec/tree/main/examples/swift). Its runnable client covers artifact fetch, tunnel connect, typed RPC, custom streams, liveness, HTTP proxy, and WebSocket proxy. Focused SDK tests provide executable endpoint, reconnect, controlplane, and security-policy references.

## Entrypoints

- Client connect: `Flowersec.connect`, `connectDirect`, and `connectTunnel`
- Endpoint sessions: `Endpoint.acceptDirect` and `Endpoint.connectTunnel`
- RPC: `RPCRouter`, `RPCServer`, and the connected client RPC surface
- Streams: `FlowersecByteStream`
- Controlplane: `Controlplane` and `ChannelInitService`
- Reconnect: `ReconnectManager`
- Proxy: `ProxyClient` and `ProxyServer`
- Diagnostics: `ConnectOptions.onDiagnosticEvent`

High-level WebSocket connections require TLS by default. Use `.allowPlaintextForLoopback` only for literal local development targets.

## Proxy Server

`ProxyServer` streams HTTP request and response chunks directly between the Flowersec stream and AsyncHTTPClient. `ProxyServerOptions.maxConcurrentStreams` defaults to 64 and independently caps active HTTP and WebSocket proxy streams; excess streams are reset immediately.

## Runtime Boundaries

Swift owns the native Apple-platform implementation of the portable contract. Browser Service Worker runtime APIs remain TypeScript-owned, while shared tunnel, gateway, and helper binaries remain Go-owned.

Review the shared [API contract](../docs/API_CONTRACT.md), [protocol](../docs/PROTOCOL.md), [threat model](../docs/THREAT_MODEL.md), and [error model](../docs/ERROR_MODEL.md).
