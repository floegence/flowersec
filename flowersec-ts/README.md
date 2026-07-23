# @floegence/flowersec-core

The TypeScript SDK for Flowersec end-to-end encrypted direct and tunneled Transport v2 sessions in browsers and Node.js.

## Install

```bash
npm install @floegence/flowersec-core
```

The package is ESM-only and exposes environment-specific entrypoints for browser and Node.js applications.

## Transport v2 Support

The browser entrypoint advertises production WebSocket and WebTransport Transport v2 tuples when the corresponding browser constructors are available. They are equal carrier classes; WebSocket uses hop-local Yamux, while WebTransport maps logical streams to native HTTP/3 bidirectional streams without Yamux. Browser v2 disables 0-RTT and QUIC DATAGRAM.

WebSocket, raw QUIC, and WebTransport are equal carrier candidates.
QUIC-family carriers use native QUIC streams and never Yamux.
Flowersec application 0-RTT is disabled.
Flowersec does not use QUIC DATAGRAM frames.
`flowersec-tunnel` remains a v1 WebSocket/Yamux CLI.

Transport v2 production carrier support: browsers support WebSocket and WebTransport; Node.js supports WebSocket dialing for direct clients and both tunnel roles.

Use `connectBrowserSessionV2(...)` with an `ArtifactSourceV2`, await the ready `SessionV2` before attaching RPC, use `ByteStreamV2` FIN/reset semantics, and await asynchronous disconnect. `SessionReconnectManagerV2` reacquires a fresh durable artifact lease for every attempt and never recycles a serialized one-time artifact.

The Node.js entrypoint exports `connectNodeSessionV2(...)` and advertises WebSocket dial tuples for direct clients and tunnel client/server roles. Node.js raw QUIC and WebTransport remain typed unavailable. Raw QUIC is unavailable in browser JavaScript, and the package does not cast a v1 `ConnectArtifact` into `ArtifactV2`. See the [Transport v2 architecture](../docs/TRANSPORT_V2_ARCHITECTURE.md) and [migration guide](../docs/MIGRATION_TRANSPORT_V2.md).

## Cookbook

Start with the [TypeScript Transport v2 guide](https://github.com/floegence/flowersec/tree/main/examples/ts), which uses only opaque artifact leases and the public browser or Node.js v2 session connector.

## Entrypoints

- Browser client: `@floegence/flowersec-core/browser`
- Node.js Transport v2 session dialing: `@floegence/flowersec-core/node`
- Controlplane artifact helpers: `@floegence/flowersec-core/controlplane`
- Endpoint session serving: `@floegence/flowersec-core/endpoint`
- RPC: `@floegence/flowersec-core/rpc`
- Reconnect: `@floegence/flowersec-core/reconnect`
- HTTP/WebSocket proxy and browser runtime: `@floegence/flowersec-core/proxy`
- Observability: `@floegence/flowersec-core/observability`
- Transport v2 browser session: `connectBrowserSessionV2`, `SessionV2`, `ByteStreamV2`
- Transport v2 Node.js WebSocket session: `connectNodeSessionV2`, `NodeSessionConnectorV2Options`
- Transport v2 artifact/reconnect: `ArtifactSourceV2`, `ArtifactLeaseV2`, `SessionReconnectManagerV2`

High-level WebSocket connections require TLS by default. Use `AllowPlaintextForLoopback` only for literal local development targets.

## Node Proxy Server

The proxy entrypoint exports `serveProxySession(...)`, `serveProxyStream(...)`, and `ProxyServerOptions`. HTTP request and response bodies stream between Flowersec chunk frames and the upstream fetch while remaining bounded per request by `maxBodyBytes`. Proxy sessions admit at most `maxConcurrentStreams` HTTP/WebSocket streams, with a shared default of 64; RPC serving has its own concurrency controls. WebSocket frames remain bounded by `maxWsFrameBytes`; `maxWsQueuedBytes` additionally caps upstream-to-Yamux queued bytes per connection, while the reverse direction waits for each Node `ws` send callback.

The defaults keep one queued WebSocket frame plus its proxy header. Raise body, concurrency, or queue limits only when the deployment has matching upstream and memory capacity.

## Runtime Boundaries

TypeScript owns browser and Service Worker integration. Shared tunnel, proxy gateway, and helper binaries remain Go-owned.

Review the shared [API contract](../docs/API_CONTRACT.md), [protocol](../docs/PROTOCOL.md), [threat model](../docs/THREAT_MODEL.md), and [error model](../docs/ERROR_MODEL.md).
