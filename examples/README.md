# Flowersec Cookbooks

The cookbooks are the source-first guide to Flowersec. Each language page points to runnable programs, exact commands, expected output, and the tests that cover advanced behavior. The packaged demo stack is a Transport v1 WebSocket/Yamux stack; it must not be used as evidence that a runtime advertises Transport v2.

| Language | Cookbook | Primary runtime |
| --- | --- | --- |
| Go | [examples/go](go/README.md) | Services, endpoints, controlplanes, and CLIs |
| TypeScript | [examples/ts](ts/README.md) | Browser, Service Worker, and Node.js |
| Swift | [examples/swift](swift/README.md) | Native Apple platform clients and endpoints |
| Rust | [examples/rust](rust/README.md) | Tokio-native clients and endpoints |

## Start the Shared Demo Stack

From a source checkout:

```bash
make ts-ensure-deps ts-build
node ./examples/ts/dev-server.mjs | tee dev.json
```

From a release demo bundle, the TypeScript package and service binaries are already built:

```bash
node ./examples/ts/dev-server.mjs | tee dev.json
```

The process prints one ready JSON object. Keep it running while using another terminal for a cookbook command.

Important fields:

- `controlplane_http_url`: artifact endpoint used by Node, Go, Swift, and Rust examples
- `browser_direct_url`: direct browser session
- `browser_tunnel_url`: tunneled browser session
- `browser_proxy_sandbox_url`: browser HTTP/WebSocket proxy runtime

## Recommended Path

The runnable demo examples use the Transport v1 `ConnectArtifact` bootstrap value:

```text
controlplane -> ConnectArtifact -> high-level connect -> RPC / stream / proxy
```

Raw grants and manually assembled protocol stacks remain available only as advanced implementation references.

## Transport v2 References

Transport v2 uses `ArtifactV2`, exact runtime capability tuples, equal WebSocket/raw QUIC/WebTransport candidate selection, durable spend, and an authenticated `SessionV2`. WebSocket keeps hop-local Yamux; raw QUIC and WebTransport use native bidirectional streams without Yamux. 0-RTT and QUIC DATAGRAM are disabled.

WebSocket, raw QUIC, and WebTransport are equal carrier candidates. QUIC-family carriers use native QUIC streams and never Yamux. Flowersec application 0-RTT is disabled. Flowersec does not use QUIC DATAGRAM frames. `flowersec-tunnel` remains a v1 WebSocket/Yamux CLI.

Transport v2 example support: none; the runnable examples remain v1 WebSocket/Yamux examples.

The current executable references are verification programs rather than packaged demos:

| Runtime | Current v2 status | Executable reference |
| --- | --- | --- |
| Go | Production WebSocket, raw QUIC, and WebTransport library carriers; CLI remains v1 | `go test ./flowersec-go/connectv2 ./flowersec-go/carrier/... ./flowersec-go/tunnelv2` |
| TypeScript browser | Production WebSocket/WebTransport adapter; no raw QUIC | `make transport-browser-smoke` and `flowersec-ts/src/browser/connectV2.test.ts` |
| TypeScript Node.js | No production v2 carrier tuple | Portable type/codec tests only |
| Rust | Tested raw QUIC adapter; no advertised production v2 connector | `cargo test --manifest-path flowersec-rust/Cargo.toml --test raw_quic_v2` |
| Swift | Portable v2 protocol/session only; no network carrier tuple | `swift test --filter TransportV2` |

Local smoke does not replace the signed real-browser, weak-network, qlog, migration, and performance evidence required for release. See the [Transport v2 architecture](../docs/TRANSPORT_V2_ARCHITECTURE.md) and [migration guide](../docs/MIGRATION_TRANSPORT_V2.md).

## Shared Environment

The native examples accept these variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `FSEC_CONTROLPLANE_BASE_URL` | Required by Swift/Rust; printed in `dev.json` | Fetches a fresh artifact |
| `FSEC_ENDPOINT_ID` | `server-1` | Selects the demo endpoint |
| `FSEC_ORIGIN` | `http://127.0.0.1:5173` | Matches the local tunnel allow-list |

Tunnel tokens are one-time use. Run the artifact request again for every new tunnel connection.

## Verification

Build all cookbook entrypoints with:

```bash
make example-check
```

The repository-wide `make check` gate includes this target and the cross-language interoperability suite.
