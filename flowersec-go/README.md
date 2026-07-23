# flowersec-go

The Go SDK for Flowersec end-to-end encrypted direct and tunneled sessions. It implements the legacy v1 stack and the production Transport v2 carrier/session library, and owns the shared deployable services and CLIs.

## Install

Library:

```bash
go get github.com/floegence/flowersec/flowersec-go@latest
```

Deployable services:

```bash
go install github.com/floegence/flowersec/flowersec-go/cmd/flowersec-tunnel@latest
go install github.com/floegence/flowersec/flowersec-go/cmd/flowersec-proxy-gateway@latest
```

Go module tags use the `flowersec-go/vX.Y.Z` repository prefix.

## Transport v2 Support

Go advertises production Transport v2 tuples for WebSocket, raw QUIC, and WebTransport. These are equal carrier classes selected from exact artifact and runtime capability tuples; none is a permanent primary or fallback. WebSocket uses hop-local Yamux, while raw QUIC and WebTransport use native bidirectional streams and never run Yamux over QUIC. QUIC requires TLS 1.3, strict Flowersec ALPN, explicit trust roots, and disables 0-RTT and QUIC DATAGRAM.

WebSocket, raw QUIC, and WebTransport are equal carrier candidates.
QUIC-family carriers use native QUIC streams and never Yamux.
Flowersec application 0-RTT is disabled.
Flowersec does not use QUIC DATAGRAM frames.
`flowersec-tunnel` remains a v1 WebSocket/Yamux CLI.

Transport v2 production carrier support: WebSocket, raw QUIC, and WebTransport.

The v2 library entrypoints are `artifactv2`, `admissionv2`, `connectv2`, `carrier`, `carrier/websocket`, `carrier/rawquic`, `carrier/webtransport`, `endpointsetv2`, `session`, and `tunnelv2`. Applications must durably spend an `ArtifactLease` before the first FSB2 credential byte, wait for `SessionV2` readiness before attaching RPC, and use carrier-neutral streams instead of Yamux types.

The published `flowersec-tunnel` command remains the v1 WebSocket tunnel in this release. Transport v2 listeners and `tunnelv2` coordination are library surfaces that require explicit downstream endpoint, certificate, listener, and controlplane wiring. See the [Transport v2 architecture](../docs/TRANSPORT_V2_ARCHITECTURE.md) and [migration guide](../docs/MIGRATION_TRANSPORT_V2.md).

## Cookbook

Start with the [Go cookbook](https://github.com/floegence/flowersec/tree/main/examples/go). It contains runnable direct and tunnel clients, endpoint and controlplane services, proxy serving, tunnel sharding, and manual protocol-stack references.

## Entrypoints

- Client: `github.com/floegence/flowersec/flowersec-go/client`
- Endpoint: `github.com/floegence/flowersec/flowersec-go/endpoint`
- Endpoint serving: `github.com/floegence/flowersec/flowersec-go/endpoint/serve`
- RPC: `github.com/floegence/flowersec/flowersec-go/rpc`
- Reconnect: `github.com/floegence/flowersec/flowersec-go/reconnect`
- Proxy: `github.com/floegence/flowersec/flowersec-go/proxy`
- Controlplane: `github.com/floegence/flowersec/flowersec-go/controlplane`
- Observability: `github.com/floegence/flowersec/flowersec-go/observability`
- Transport v2 connect: `github.com/floegence/flowersec/flowersec-go/connectv2`
- Transport v2 carriers: `github.com/floegence/flowersec/flowersec-go/carrier/{websocket,rawquic,webtransport}`
- Transport v2 session and tunnel: `github.com/floegence/flowersec/flowersec-go/session` and `github.com/floegence/flowersec/flowersec-go/tunnelv2`

High-level WebSocket connections require TLS by default. Use `AllowPlaintextForLoopback` only for literal local development targets.

## Runtime Boundaries

Go owns the open-source tunnel, proxy gateway, artifact/grant helper CLIs, and shared demo services. Browser and Service Worker runtime APIs remain TypeScript-owned.

Review the shared [API contract](../docs/API_CONTRACT.md), [protocol](../docs/PROTOCOL.md), [threat model](../docs/THREAT_MODEL.md), and [error model](../docs/ERROR_MODEL.md).
