# flowersec-go

The Go SDK for Flowersec end-to-end encrypted direct and tunneled sessions. It implements the portable client, endpoint, RPC, stream, controlplane, reconnect, proxy, and observability contract, and owns the shared deployable services and CLIs.

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

High-level WebSocket connections require TLS by default. Use `AllowPlaintextForLoopback` only for literal local development targets.

## Runtime Boundaries

Go owns the open-source tunnel, proxy gateway, artifact/grant helper CLIs, and shared demo services. Browser and Service Worker runtime APIs remain TypeScript-owned.

Review the shared [API contract](../docs/API_CONTRACT.md), [protocol](../docs/PROTOCOL.md), [threat model](../docs/THREAT_MODEL.md), and [error model](../docs/ERROR_MODEL.md).
