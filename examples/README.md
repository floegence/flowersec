# Flowersec Cookbooks

The cookbooks are the source-first guide to Flowersec. Each language page points to runnable programs, exact commands, expected output, and the tests that cover advanced behavior.

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

New examples use `ConnectArtifact` as the client bootstrap value:

```text
controlplane -> ConnectArtifact -> high-level connect -> RPC / stream / proxy
```

Raw grants and manually assembled protocol stacks remain available only as advanced implementation references.

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
