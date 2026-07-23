# Swift Cookbook

The Swift example is a single production-shaped Transport v1 client that exercises artifact fetch, tunnel connect, typed RPC, custom streams, liveness, HTTP proxy, and WebSocket proxy.

## Run

Requirements: macOS 15+, Swift 6.1+, Node.js 24+, and Go 1.26.5+.

Start the shared stack from the repository root:

```bash
make ts-ensure-deps ts-build
node ./examples/ts/dev-server.mjs | tee dev.json
```

In another terminal:

```bash
FSEC_CONTROLPLANE_BASE_URL="$(jq -r '.controlplane_http_url' dev.json)" \
  swift run --package-path ./examples/swift
```

Expected output includes these signals:

```text
stream=flowersec-swift-example
http_status=200
websocket=
```

## Examples

| Scenario | Source | Run or verify |
| --- | --- | --- |
| Artifact-first tunnel connect | [`main.swift`](Sources/FlowersecSwiftClientExample/main.swift) | Recommended command above |
| Typed RPC and custom stream | [`main.swift`](Sources/FlowersecSwiftClientExample/main.swift) | Included in the recommended run |
| Liveness probe | [`main.swift`](Sources/FlowersecSwiftClientExample/main.swift) | Included in the recommended run |
| HTTP/WebSocket proxy client | [`main.swift`](Sources/FlowersecSwiftClientExample/main.swift) | Included in the recommended run |
| Direct and tunnel interoperability | [`GoInteropTests.swift`](../../flowersec-swift/Tests/FlowersecTests/GoInteropTests.swift) | `swift test` |
| Endpoint and RPC server | [`EndpointTests.swift`](../../flowersec-swift/Tests/FlowersecTests/EndpointTests.swift) | `swift test --filter EndpointTests` |
| Reconnect | [`ReconnectTests.swift`](../../flowersec-swift/Tests/FlowersecTests/ReconnectTests.swift) | `swift test --filter ReconnectTests` |
| Controlplane issuance and fetch | [`ControlplaneTests.swift`](../../flowersec-swift/Tests/FlowersecTests/ControlplaneTests.swift) | `swift test --filter ControlplaneTests` |

## Source Map

- `main.swift` is the application-facing example. It uses only the high-level public package surface.
- `GoInteropTests.swift` is the executable compatibility reference for direct/tunnel sessions and proxy traffic against the Go reference peer.
- Focused SDK tests are the cookbook for endpoint, reconnect, proxy policy, resource limits, and protocol edge cases. They are compiled on every local quality-gate run.

## Runtime Boundaries

Swift implements the complete portable client and endpoint contract for Apple platforms. Browser Service Worker runtime APIs remain TypeScript-owned, while shared tunnel, gateway, and helper binaries remain Go-owned.

## Transport v2 Boundary

Swift includes portable Transport v2 wire, cryptographic, session, stream, and asynchronous lifecycle code but advertises no production v2 network-carrier tuple. WebSocket, raw QUIC, and WebTransport remain equal carrier classes in the contract; Yamux is WebSocket-only and v2 disables 0-RTT and QUIC DATAGRAM. The runnable example above remains v1. Use `swift test --filter TransportV2` as the executable portable-contract reference and follow the [migration guide](../../docs/MIGRATION_TRANSPORT_V2.md).

## Troubleshooting

- Missing `FSEC_CONTROLPLANE_BASE_URL`: keep the shared stack running and read `controlplane_http_url` from `dev.json`.
- `token_replay`: rerun the client so it fetches a fresh artifact.
- Local `ws://` rejection: the example explicitly uses `.allowPlaintextForLoopback`; production deployments should use `wss://`.
- Dependency resolution failure: run `swift package resolve --package-path ./examples/swift` and retry.
