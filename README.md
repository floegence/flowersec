# flowersec

Flowersec is a Go + TypeScript data-plane library for building an end-to-end encrypted, multiplexed connection over WebSocket.

It provides a consistent protocol stack across Go and TypeScript (browser-friendly):

- Tunnel attach: authenticate + pair endpoints (`channel_id` + `role`) and then blindly forward bytes
- E2EE record layer: PSK-authenticated handshake and encrypted records (`FSEH` / `FSEC` framing)
- Multiplexing: Yamux over the encrypted byte stream (server endpoint is Yamux server)
- RPC/events: typed `type_id` routing on a dedicated `rpc` stream

Status: experimental; not audited.

Security note: in any non-local deployment, use `wss://` (or terminate TLS at a reverse proxy). `ws://` exposes bearer tokens and metadata on the wire.

## Repository Layout

- Go library and binaries: `flowersec-go/`
- TypeScript library (ESM, browser-friendly): `flowersec-ts/`
- Single-source IDL and codegen: `idl/`, `tools/idlgen/`
- Demos + scenario cookbook: `examples/README.md`
  - Includes both high-level client helpers and manual stack examples (Go + TS).

## Quickstart

The recommended hands-on entrypoint is the scenario cookbook:

```bash
open examples/README.md
```

If you are integrating Flowersec into your own codebase (not just running the demos), start here:

- `docs/INTEGRATION_GUIDE.md`

If you want a "from zero" guided path (copy/paste friendly), follow the section below.

## Install (no clone)

This section is for users who want to install Flowersec tools without cloning this repository.

### Tunnel server (deployable)

**Option A: `go install`**

```bash
go install github.com/floegence/flowersec/flowersec-go/cmd/flowersec-tunnel@latest
flowersec-tunnel --version
```

**Option B: GitHub Releases**

Download prebuilt binaries (and `checksums.txt`) from the GitHub Releases page.

**Option C: Docker image (recommended for deployments)**

The tunnel CLI supports `FSEC_TUNNEL_*` environment variables as defaults (flags override env). Minimal example:

```bash
docker run --rm \
  -p 8080:8080 \
  -v "$PWD/issuer_keys.json:/etc/flowersec/issuer_keys.json:ro" \
  -e FSEC_TUNNEL_LISTEN=0.0.0.0:8080 \
  -e FSEC_TUNNEL_WS_PATH=/ws \
  -e FSEC_TUNNEL_ISSUER_KEYS_FILE=/etc/flowersec/issuer_keys.json \
  -e FSEC_TUNNEL_AUD=flowersec-tunnel:prod \
  -e FSEC_TUNNEL_ISS=issuer-prod \
  -e FSEC_TUNNEL_ALLOW_ORIGIN=https://your-web-origin.example \
  ghcr.io/floegence/flowersec-tunnel:latest
```

- `issuer_keys.json` is the issuer **public keyset** owned by your controlplane (the tunnel uses it to verify tokens). Keep `aud`/`iss` consistent with the controlplane-issued token payload.
- Health check: `GET /healthz` on the tunnel HTTP server.
- Metrics: set `FSEC_TUNNEL_METRICS_LISTEN=0.0.0.0:9090` and expose `-p 9090:9090`.

Full deployment notes: `docs/TUNNEL_DEPLOYMENT.md`.

## Getting started (from zero, local)

This section is a nanny-style walkthrough to get a working end-to-end session on your machine.

### 0) Prerequisites

- Go (same major as `flowersec-go/go.mod`)
- Node.js 22 LTS (see `.nvmrc`)
- Optional: `jq` (makes copying values from JSON outputs easier)

### 1) Build the TypeScript bundle once (required for TS examples)

The TS example scripts import from `flowersec-ts/dist/`, so build it once:

```bash
cd flowersec-ts
npm ci
npm run build
cd ..
```

### 2) Run your first end-to-end session (direct path, no tunnel)

This is the simplest path: a single direct WebSocket server endpoint that immediately runs E2EE + Yamux + RPC.

Terminal 1 (start the direct server demo):

```bash
cd examples
go run ./go/direct_demo --allow-origin http://127.0.0.1:5173 | tee /tmp/fsec-direct.json
```

Terminal 2 (run a Node.js client against it):

```bash
FSEC_ORIGIN=http://127.0.0.1:5173 node ./examples/ts/node-direct-client.mjs < /tmp/fsec-direct.json
```

Alternative (Go client):

```bash
cd examples
go run ./go/go_client_direct_simple --origin http://127.0.0.1:5173 < /tmp/fsec-direct.json
```

### 3) Run the full stack (controlplane + tunnel)

This is the recommended architecture when you need an untrusted public rendezvous (the tunnel) while keeping E2EE end-to-end.

Terminal 1 (start the controlplane demo; it prints a JSON line with params):

```bash
CP_JSON="$(mktemp -t fsec-controlplane.XXXXXX.json)"
./examples/run-controlplane-demo.sh | tee "$CP_JSON"
```

Terminal 2 (start the deployable tunnel service using the params from Terminal 1):

```bash
FSEC_TUNNEL_ALLOW_ORIGIN=http://127.0.0.1:5173 \
FSEC_TUNNEL_ISSUER_KEYS_FILE="$(jq -r '.issuer_keys_file' "$CP_JSON")" \
FSEC_TUNNEL_AUD="$(jq -r '.tunnel_audience' "$CP_JSON")" \
FSEC_TUNNEL_ISS="$(jq -r '.tunnel_issuer' "$CP_JSON")" \
FSEC_TUNNEL_LISTEN="$(jq -r '.tunnel_listen' "$CP_JSON")" \
FSEC_TUNNEL_WS_PATH="$(jq -r '.tunnel_ws_path' "$CP_JSON")" \
./examples/run-tunnel-server.sh
```

Terminal 3 (start a server endpoint; it receives `grant_server` over a control channel and attaches as role=server):

```bash
FSEC_ORIGIN=http://127.0.0.1:5173 ./examples/run-server-endpoint.sh "$CP_JSON"
```

Terminal 4 (mint a channel init and run a client):

```bash
CHANNEL_JSON="$(mktemp -t fsec-channel.XXXXXX.json)"
CP_URL="$(jq -r '.controlplane_http_url' "$CP_JSON")"
curl -sS -X POST "$CP_URL/v1/channel/init" | tee "$CHANNEL_JSON"
FSEC_ORIGIN=http://127.0.0.1:5173 node ./examples/ts/node-tunnel-client.mjs < "$CHANNEL_JSON"
```

If you refresh/reconnect: mint a new channel again (tunnel attach tokens are one-time use).

High-level client entrypoints:

Install the Go module:

```bash
go get github.com/floegence/flowersec/flowersec-go@latest
# Or pin a version:
go get github.com/floegence/flowersec/flowersec-go@v0.1.0
```

Versioning note: Go module tags are prefixed with `flowersec-go/` (for example, `flowersec-go/v0.1.0`).

- Go (client): `github.com/floegence/flowersec/flowersec-go/client` (`client.ConnectTunnel(ctx, grant, origin, ...opts)`, `client.ConnectDirect(ctx, info, origin, ...opts)`)
- Go (server endpoint): `github.com/floegence/flowersec/flowersec-go/endpoint` (accept/dial `role=server` endpoints)
- Go (server stream runtime): `github.com/floegence/flowersec/flowersec-go/endpoint/serve` (default stream dispatch + RPC stream handler)
- Go (input JSON helpers): `github.com/floegence/flowersec/flowersec-go/protocolio` (`DecodeGrantClientJSON`, `DecodeDirectConnectInfoJSON`)
- TS (stable): `@flowersec/core` (`connectTunnel`, `connectDirect`)
- TS (Node): `@flowersec/core/node` (`connectTunnelNode`, `connectDirectNode`, `createNodeWsFactory`)
- TS (browser): `@flowersec/core/browser` (`connectTunnelBrowser`, `connectDirectBrowser`)
- TS (building blocks): `@flowersec/core/rpc`, `@flowersec/core/yamux`, `@flowersec/core/e2ee`, `@flowersec/core/ws`, `@flowersec/core/observability`, `@flowersec/core/streamhello`
- TS (generated protocol stubs): `@flowersec/core/gen/flowersec/{controlplane,direct,e2ee,rpc,tunnel}/*`
- TS (unstable): `@flowersec/core/internal` (internal glue; not recommended as a stable dependency)

Note: the `demo` IDL used by the cookbook/examples is intentionally NOT part of the public API surface.
The generated demo stubs live under `examples/gen/` (Go examples module) and `flowersec-ts/src/_examples/` (TS repo-only), and are not exported via `@flowersec/core`.

It includes:

- Running the deployable tunnel server as an unmodified service
- Starting a minimal controlplane demo (issuer keys + grant minting)
- Starting a demo server endpoint (`role=server`) and connecting via TS/Go clients

## Key Concepts

- Endpoint roles: `client` vs `server` are protocol roles.
- One-time tokens: tunnel attach tokens are single-use; mint a fresh channel init for each attempt.
- Untrusted tunnel: the tunnel cannot decrypt or interpret application data after attach.
- Single-instance tunnel: token replay protection is in-memory. To scale without shared state, shard channels across multiple tunnel endpoints at the control plane layer (set different `tunnel_url` values per channel).
- Idle timeout: the tunnel closes channels that are idle beyond `idle_timeout_seconds` (enforced from the signed token claim). High-level connect helpers send encrypted keepalive pings by default.
- Handshake init_exp: `channel_init_expire_at` (init_exp) must be a non-zero Unix timestamp.
- Handshake confirmation: after `E2EE_Ack`, the server sends an encrypted ping record (`FSEC`, `flags=ping`, `seq=1`). Clients wait for this server-finished proof before returning.

## Communication Scenarios

The examples in `examples/README.md` cover two common paths. The diagrams below mirror those scenarios.

### Tunnel path (controlplane + tunnel)

![Tunnel path (controlplane + tunnel)](docs/tunnel-path.svg)

### Direct path (no tunnel)

![Direct path (no tunnel)](docs/direct-path.svg)

## Development

Generate code from IDL:

```bash
make gen
```

Codegen is split into:

- `make gen-core`: stable protocol IDLs (public API surface)
- `make gen-examples`: example/test-only IDLs (not exported as a public API)
- `make gen`: both

Go workspace:

- Go code lives in the `flowersec-go/` module; examples live in the `examples/` module. Run Go commands from those directories (or use `make go-test`).

## Tunnel defaults (important for deployment)

The deployable tunnel binary is `flowersec-go/cmd/flowersec-tunnel/`.

- TLS is **disabled by default**. For any non-local deployment, use `wss://` (either enable `--tls-cert-file/--tls-key-file` or terminate TLS at a reverse proxy).
- Origin checks are **enabled by default** and require an explicit allow-list:
  - `--allow-origin` accepts:
    - full Origin values (e.g. `https://example.com` or `http://127.0.0.1:5173`)
    - hostname entries (e.g. `example.com`, port ignored)
    - hostname:port entries (e.g. `example.com:5173`)
    - wildcard hostnames (e.g. `*.example.com`)
    - exact non-standard values (e.g. `null`)
  - Requests without `Origin` are **rejected by default**; `--allow-no-origin` is intended for non-browser clients (discouraged).
  - Client helpers:
    - Go: pass an explicit `origin` string to `client.ConnectTunnel` / `client.ConnectDirect`.
    - TS browser: use `connectTunnelBrowser` / `connectDirectBrowser` from `@flowersec/core/browser` (uses `window.location.origin`).
    - TS Node: use `connectTunnelNode` / `connectDirectNode` from `@flowersec/core/node` (auto-injects a `wsFactory` that sets the `Origin` header), or pass `wsFactory` manually.
- Token issuer (`iss`) is **required**: pass `--iss` and ensure it matches the token payload `iss` minted by your controlplane.

Node.js version:

- Recommended: Node.js 22 (LTS). See `.nvmrc`.
- CI uses Node.js 22 (see `.github/workflows/ci.yml`).

Run formatting/lint and tests:

```bash
make lint
make test
```

## Observability

The tunnel binary exposes Prometheus metrics on a dedicated metrics server. The metrics server is disabled by default (empty `--metrics-listen`).

When `--metrics-listen` is set, `GET /metrics` is served immediately.
You can toggle metrics at runtime:

- Disable metrics: send `SIGUSR2`
- Re-enable metrics: send `SIGUSR1`

Example:

```bash
# run tunnel
cd flowersec-go
go run ./cmd/flowersec-tunnel \
  --listen 127.0.0.1:8080 \
  --metrics-listen 127.0.0.1:9090 \
  --issuer-keys-file /path/to/keys.json \
  --aud your-audience \
  --iss your-issuer \
  --allow-origin http://127.0.0.1:5173

# scrape metrics
curl http://127.0.0.1:9090/metrics
```

Library integrations:

- Go tunnel: set `server.Config.Observer` if you run the server directly.
- Go RPC: attach an observer via `rpc.Server.SetObserver(...)` or `rpc.Client.SetObserver(...)`.
- TS client: pass `observer` into `connectTunnel(...)` / `connectDirect(...)`, `WebSocketBinaryTransport`, or `RpcClient`.

## Binaries

- Tunnel server (deployable): `flowersec-go/cmd/flowersec-tunnel/`
  - flags: `--listen`, `--ws-path`, `--issuer-keys-file`, `--aud`, `--iss`, `--allow-origin`, `--allow-no-origin`, `--tls-cert-file`, `--tls-key-file`, `--metrics-listen`, `--max-conns`, `--max-channels`, `--max-total-pending-bytes`, `--write-timeout`, `--max-write-queue-bytes` (see `--help` for full details)
