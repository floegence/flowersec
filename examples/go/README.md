# Go Cookbook

Use the Go examples for clients, endpoints, controlplane integration, deployment helpers, and manual protocol-stack references.

## Run

Requirements: Go 1.26.5+, Node.js 24+, and `jq`.

Start the shared stack from the repository root:

```bash
make ts-ensure-deps ts-build
node ./examples/ts/dev-server.mjs | tee dev.json
```

In another terminal, fetch a fresh tunnel artifact and run the recommended high-level Go client:

```bash
curl -sS -X POST \
  "$(jq -r '.controlplane_http_url' dev.json)/v1/connect/artifact" \
  -H 'content-type: application/json' \
  -d '{"endpoint_id":"server-1"}' \
  | jq -c '.connect_artifact' \
  | (cd examples && FSEC_ORIGIN=http://127.0.0.1:5173 go run ./go/go_client_tunnel_simple)
```

Expected output includes an RPC response, an RPC notification, and an echoed custom stream payload.

## Examples

| Scenario | Source | Run or verify |
| --- | --- | --- |
| Artifact-first tunnel client | [`go_client_tunnel_simple`](go_client_tunnel_simple/main.go) | Recommended command above |
| Artifact-first direct client | [`go_client_direct_simple`](go_client_direct_simple/main.go) | Pipe `http://127.0.0.1:5173/__demo/direct/artifact` into `go run ./go/go_client_direct_simple` from `examples/` |
| RPC and custom streams | [`go_client_tunnel_simple`](go_client_tunnel_simple/main.go) | Included in the recommended run |
| Endpoint and HTTP/WebSocket proxy server | [`server_endpoint`](server_endpoint/main.go) | Started by `dev-server.mjs`; open `browser_proxy_sandbox_url` |
| Controlplane artifact issuance | [`controlplane_demo`](controlplane_demo/main.go) | Started by `dev-server.mjs` |
| Liveness and limits | [`client` tests](../../flowersec-go/client/keepalive_defaults_test.go) | `cd flowersec-go && go test ./client` |
| Reconnect | [`reconnect` tests](../../flowersec-go/reconnect/reconnect_test.go) | `cd flowersec-go && go test ./reconnect` |
| Tunnel sharding | [`tunnel_sharding`](tunnel_sharding/pick_tunnel_url.go) | `cd examples && go test ./go/tunnel_sharding` |

## Source Map

- `*_simple` programs use the high-level `client.Connect` path and should be copied for application integrations.
- `go_client_direct` and `go_client_tunnel` manually assemble WebSocket, E2EE, Yamux, StreamHello, and RPC. Use them only when implementing a custom transport or studying the stack.
- `server_endpoint` demonstrates a long-lived endpoint registration channel, fresh server grants, RPC handlers, custom streams, and proxy serving.
- `controlplane_demo` is a local reference service, not a production identity or authorization system.

## Runtime Boundaries

Go owns the shared deployable tunnel, proxy gateway, key/grant helper CLIs, and the demo controlplane services. Browser and Service Worker runtime APIs remain TypeScript-owned.

## Troubleshooting

- `token_replay`: fetch a new artifact; tunnel grants cannot be reused.
- Origin rejection: keep `FSEC_ORIGIN` aligned with the dev server and tunnel allow-list.
- Local `ws://` rejection: examples opt into `AllowPlaintextForLoopback`; remote deployments should use `wss://`.
- Missing generated packages: run `make gen-check` from the repository root.
