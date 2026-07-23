# TypeScript Cookbook

Use the TypeScript examples for Transport v1 browser, Service Worker, Node.js, direct, tunnel, and proxy runtime workflows. The shared demo stack uses v1 `ConnectArtifact`, WebSocket, E2EE, and Yamux.

## Run

Requirements: Node.js 24+ and Go 1.26.5+ when running from a source checkout.

Build the package and start the shared stack:

```bash
make ts-ensure-deps ts-build
node ./examples/ts/dev-server.mjs | tee dev.json
```

In another terminal, run the recommended artifact-first Node client:

```bash
FSEC_CONTROLPLANE_BASE_URL="$(jq -r '.controlplane_http_url' dev.json)" \
  node ./examples/ts/node-artifact-client.mjs
```

Expected output:

```text
ok
```

Open the URLs in `dev.json` to run the browser direct, tunnel, and proxy runtime examples.

## Examples

| Scenario | Source | Run or verify |
| --- | --- | --- |
| Artifact-first Node client | [`node-artifact-client.mjs`](node-artifact-client.mjs) | Recommended command above |
| Browser direct | [`browser-direct`](browser-direct/index.html) | Open `browser_direct_url` |
| Browser tunnel | [`browser-tunnel`](browser-tunnel/index.html) | Open `browser_tunnel_url` |
| Node direct with RPC and streams | [`node-direct-client.mjs`](node-direct-client.mjs) | Fetch `/__demo/direct/artifact` and pipe its artifact into the program |
| Node tunnel with RPC and streams | [`node-tunnel-client.mjs`](node-tunnel-client.mjs) | Fetch a fresh controlplane artifact and pipe it into the program |
| HTTP/WebSocket proxy runtime | [`proxy-sandbox`](proxy-sandbox/index.html) | Open `browser_proxy_sandbox_url` |
| Liveness and reconnect | [`Go integration tests`](../../flowersec-ts/src/e2e/go_integration.test.ts) | `make ts-test` |
| Tunnel sharding | [`node-tunnel-sharding.mjs`](node-tunnel-sharding.mjs) | `node ./examples/ts/node-tunnel-sharding.mjs` |

## Source Map

- `node-artifact-client.mjs`, `node-direct-client.mjs`, `node-tunnel-client.mjs`, and the default browser pages use high-level connection APIs.
- Files named `advanced` manually assemble WebSocket, E2EE, Yamux, StreamHello, and RPC. They are protocol references, not the recommended application integration.
- `proxy-sandbox` owns the browser Service Worker runtime example and exercises both HTTP and WebSocket proxy streams.
- `dev-server.mjs` starts the Go reference services and serves the browser assets; it is the common entrypoint for all four language cookbooks.

## Runtime Boundaries

TypeScript owns Browser and Service Worker integration in addition to the portable Node client, endpoint, RPC, reconnect, controlplane, and proxy APIs. Shared tunnel and gateway binaries remain Go-owned.

## Transport v2 Boundary

The browser package advertises equal WebSocket and WebTransport v2 tuples when those constructors exist. WebSocket keeps hop-local Yamux; WebTransport uses native HTTP/3 bidirectional streams without Yamux, 0-RTT, or QUIC DATAGRAM. Node.js advertises no production v2 carrier tuple, and browsers cannot use raw QUIC.

The current pages remain v1 until the demo controlplane can issue a real `ArtifactV2` and a real HTTP/3 edge is available. `flowersec-ts/src/browser/connectV2.test.ts` and `make transport-browser-smoke` are executable adapter references, not production browser evidence. Applications migrate through `ArtifactSourceV2`, `connectBrowserSessionV2`, `SessionReconnectManagerV2`, ready `SessionV2`, carrier-neutral `ByteStreamV2`, and awaited disconnect as described in the [migration guide](../../docs/MIGRATION_TRANSPORT_V2.md).

## Troubleshooting

- `token_replay`: request a fresh artifact before reconnecting.
- Origin rejection: use the origin printed by the dev server, normally `http://127.0.0.1:5173`.
- Module not found under `flowersec-ts/dist`: run `make ts-ensure-deps ts-build`.
- Local `ws://` rejection: use `AllowPlaintextForLoopback` only for literal loopback development targets.
