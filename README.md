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

## Quickstart (no clone)

- Demos: download the `flowersec-demos` bundle from GitHub Releases and follow `examples/README.md` (works from the extracted bundle root).
- Integration: `docs/INTEGRATION_GUIDE.md`.
- API surface: `docs/API_SURFACE.md`.
- Threat model: `docs/THREAT_MODEL.md`.
- Protocol contracts: `docs/PROTOCOL.md`.
- Error model: `docs/ERROR_MODEL.md`.

## CLI conventions

All user-facing Flowersec CLIs (`flowersec-tunnel`, `flowersec-issuer-keygen`, `flowersec-channelinit`, `flowersec-directinit`, `idlgen`) follow these conventions:

- `--help` includes copy/paste examples and the output contract.
- Exit codes: `0` success, `2` usage/flag error, `1` runtime error.
- For JSON-producing tools, stdout is machine-readable JSON; stderr is logs/errors.
- Many flags support `FSEC_*` environment variable defaults (flags override env).

## Install (no clone)

This section is for users who want to install Flowersec tools without cloning this repository.

### Tunnel server (deployable)

**Option A: `go install`**

```bash
go install github.com/floegence/flowersec/flowersec-go/cmd/flowersec-tunnel@latest
flowersec-tunnel --version
```

Note: `go install` requires Go 1.25.x and installs into `$(go env GOBIN)` (or `$(go env GOPATH)/bin`).

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

### Helper tools (optional, local/dev)

These tools help you generate an issuer keypair, mint `ChannelInitGrant` pairs, and generate `DirectConnectInfo` JSON for direct (no tunnel) demos:

**Option A: `go install`**

```bash
go install github.com/floegence/flowersec/flowersec-go/cmd/flowersec-issuer-keygen@latest
go install github.com/floegence/flowersec/flowersec-go/cmd/flowersec-channelinit@latest
go install github.com/floegence/flowersec/flowersec-go/cmd/flowersec-directinit@latest
```

- `flowersec-issuer-keygen` writes `issuer_key.json` (private key; keep it secret) and `issuer_keys.json` (public keyset for the tunnel).
- `flowersec-channelinit` outputs a JSON object containing `grant_client`/`grant_server` (plus version metadata) to stdout (redirect to a file if needed).
- `flowersec-directinit` outputs a `DirectConnectInfo` JSON object (includes PSK; keep it secret) to stdout (redirect to a file if needed).

Flags override env. For scripting, all tools support env defaults:

```bash
# Generate issuer keys (private + public keyset for the tunnel).
export FSEC_ISSUER_OUT_DIR=./keys
flowersec-issuer-keygen

# Mint a one-time ChannelInitGrant pair (client/server).
export FSEC_ISSUER_PRIVATE_KEY_FILE=./keys/issuer_key.json
export FSEC_TUNNEL_URL=ws://127.0.0.1:8080/ws
export FSEC_TUNNEL_AUD=flowersec-tunnel:dev
export FSEC_TUNNEL_ISS=issuer-dev
flowersec-channelinit > channel.json

# Tip: use --pretty for human-readable JSON.
# flowersec-channelinit --pretty > channel.json

# Generate a DirectConnectInfo JSON object for a direct server.
export FSEC_DIRECT_WS_URL=ws://127.0.0.1:8080/ws
flowersec-directinit > direct.json
```

**Option B: GitHub Releases (no Go)**

Download `flowersec-tools_X.Y.Z_<os>_<arch>.tar.gz` (or `.zip` on Windows) from the same GitHub Release tag (`flowersec-go/vX.Y.Z`).

The tools bundle includes:

- `bin/flowersec-issuer-keygen`
- `bin/flowersec-channelinit`
- `bin/flowersec-directinit`

Note: the `flowersec-demos` bundle also includes these binaries under `bin/` for convenience.

## Getting started (no clone, local)

The recommended hands-on entrypoint is the demo bundle shipped in GitHub Releases:

- Download `flowersec-demos_X.Y.Z_<os>_<arch>.tar.gz` (or `.zip`) from the `flowersec-go/vX.Y.Z` release.
- Follow `examples/README.md` (copy/paste friendly; does not require a repository checkout).

High-level client entrypoints:

Install the Go module:

```bash
go get github.com/floegence/flowersec/flowersec-go@latest
# Or pin a version:
go get github.com/floegence/flowersec/flowersec-go@v0.1.0
```

Versioning note: Go module tags are prefixed with `flowersec-go/` (for example, `flowersec-go/v0.1.0`).

- TypeScript install (no clone): download `flowersec-core-X.Y.Z.tgz` from the same GitHub Release and install with `npm i ./flowersec-core-X.Y.Z.tgz`.
- Go (client): `github.com/floegence/flowersec/flowersec-go/client` (`client.Connect(ctx, input, ...opts)`, `client.ConnectTunnel(ctx, grant, ...opts)`, `client.ConnectDirect(ctx, info, ...opts)`; set Origin via `client.WithOrigin(origin)`)
- Go (server endpoint): `github.com/floegence/flowersec/flowersec-go/endpoint` (accept/dial `role=server` endpoints)
- Go (server stream runtime): `github.com/floegence/flowersec/flowersec-go/endpoint/serve` (default stream dispatch + RPC stream handler)
- Go (input JSON helpers): `github.com/floegence/flowersec/flowersec-go/protocolio` (`DecodeGrantClientJSON`, `DecodeDirectConnectInfoJSON`)
- Go (RPC): `github.com/floegence/flowersec/flowersec-go/rpc` (router, server, client)
- TS (stable): `@flowersec/core` (`connect`, `connectTunnel`, `connectDirect`)
- TS (Node): `@flowersec/core/node` (`connectNode`, `connectTunnelNode`, `connectDirectNode`, `createNodeWsFactory`)
- TS (browser): `@flowersec/core/browser` (`connectBrowser`, `connectTunnelBrowser`, `connectDirectBrowser`)
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
- Idle timeout: the tunnel closes channels that are idle beyond `idle_timeout_seconds` (enforced from the signed token claim). High-level connect helpers enable encrypted keepalive pings by default for tunnel connects (direct connects are opt-in).
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
    - Go: set an explicit Origin value via `client.WithOrigin(origin)` (for example `client.ConnectTunnel(ctx, grant, client.WithOrigin(origin))`).
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
- Helper tools (local/dev): `flowersec-go/cmd/flowersec-issuer-keygen/`, `flowersec-go/cmd/flowersec-channelinit/`, `flowersec-go/cmd/flowersec-directinit/`
- Internal tooling (not a supported public CLI surface): `flowersec-go/internal/cmd/*` (interop harnesses, load generator)
