# Flowersec Swift

The native Swift SDK for Flowersec end-to-end encrypted direct and tunneled sessions. It implements the legacy v1 portable stack plus Transport v2 wire, cryptographic, and session primitives for Apple platforms.

## Install

The repository root exposes the Swift package:

```swift
.package(url: "https://github.com/floegence/flowersec.git", from: "0.28.0")
```

Use the `Flowersec` library product.

## Transport v2 Support

Swift publishes the portable Transport v2 artifact, wire, cryptographic, session, stream, FIN/reset, and asynchronous close contracts. The Apple runtime currently advertises no production Transport v2 network-carrier tuple: a production WebSocket admission adapter is not committed, and raw QUIC/WebTransport remain outside the registered Network.framework contract.

WebSocket, raw QUIC, and WebTransport are equal carrier candidates.
QUIC-family carriers use native QUIC streams and never Yamux.
Flowersec application 0-RTT is disabled.
Flowersec does not use QUIC DATAGRAM frames.
`flowersec-tunnel` remains a v1 WebSocket/Yamux CLI.

Transport v2 production carrier support: none; the package provides portable protocol and session code only.

Do not treat the v1 `ConnectArtifact`, `ReconnectManager`, `FlowersecByteStream`, or Yamux options as v2 substitutes. Transport v2 defines WebSocket, raw QUIC, and WebTransport as equal carrier classes, keeps Yamux only on WebSocket hops, and disables 0-RTT and QUIC DATAGRAM. See the [Transport v2 architecture](../docs/TRANSPORT_V2_ARCHITECTURE.md) and [migration guide](../docs/MIGRATION_TRANSPORT_V2.md).

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
