# @floegence/flowersec-core

The TypeScript SDK for Flowersec end-to-end encrypted direct and tunneled sessions. It implements the portable Node.js client and endpoint contract plus the browser and Service Worker runtime owned by TypeScript.

## Install

```bash
npm install @floegence/flowersec-core
```

The package is ESM-only and exposes environment-specific entrypoints for browser and Node.js applications.

## Cookbook

Start with the [TypeScript cookbook](https://github.com/floegence/flowersec/tree/main/examples/ts). It contains runnable browser direct/tunnel pages, Node.js clients, the shared demo server, the Service Worker proxy runtime, and manual protocol-stack references.

## Entrypoints

- Browser client: `@floegence/flowersec-core/browser`
- Node.js client and endpoint transport: `@floegence/flowersec-core/node`
- Controlplane artifact helpers: `@floegence/flowersec-core/controlplane`
- Endpoint session serving: `@floegence/flowersec-core/endpoint`
- RPC: `@floegence/flowersec-core/rpc`
- Reconnect: `@floegence/flowersec-core/reconnect`
- HTTP/WebSocket proxy and browser runtime: `@floegence/flowersec-core/proxy`
- Observability: `@floegence/flowersec-core/observability`

High-level WebSocket connections require TLS by default. Use `AllowPlaintextForLoopback` only for literal local development targets.

## Node Proxy Server

The Node entrypoint exports `serveProxySession(...)`, `serveProxyStream(...)`, and `ProxyServerOptions`. HTTP request and response bodies stream between Flowersec chunk frames and the upstream fetch while remaining bounded per request by `maxBodyBytes`. Proxy sessions admit at most `maxConcurrentStreams` HTTP/WebSocket streams, with a shared default of 64; RPC serving has its own concurrency controls. WebSocket frames remain bounded by `maxWsFrameBytes`; `maxWsQueuedBytes` additionally caps upstream-to-Yamux queued bytes per connection, while the reverse direction waits for each Node `ws` send callback.

The defaults keep one queued WebSocket frame plus its proxy header. Raise body, concurrency, or queue limits only when the deployment has matching upstream and memory capacity.

## Runtime Boundaries

TypeScript owns browser and Service Worker integration. Shared tunnel, proxy gateway, and helper binaries remain Go-owned.

Review the shared [API contract](../docs/API_CONTRACT.md), [protocol](../docs/PROTOCOL.md), [threat model](../docs/THREAT_MODEL.md), and [error model](../docs/ERROR_MODEL.md).
