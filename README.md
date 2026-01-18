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

- Go library and binaries: `go/`
- TypeScript library (ESM, browser-friendly): `ts/`
- Single-source IDL and codegen: `idl/`, `tools/idlgen/`
- Demos + scenario cookbook: `examples/README.md`
  - Includes both high-level client helpers and manual stack examples (Go + TS).

## Quickstart

The recommended hands-on entrypoint is the scenario cookbook:

```bash
open examples/README.md
```

High-level client entrypoints:

- Go (client): `github.com/floegence/flowersec/client` (`client.ConnectTunnel`, `client.ConnectDirect`)
- Go (server endpoint): `github.com/floegence/flowersec/endpoint` (accept/dial `role=server` endpoints)
- TS (stable): `@flowersec/core` (`connectTunnel`, `connectDirect`)
- TS (advanced): `@flowersec/core/internal` (E2EE/Yamux/RPC/WebSocket building blocks)

It includes:

- Running the deployable tunnel server as an unmodified service
- Starting a minimal controlplane demo (issuer keys + grant minting)
- Starting a demo server endpoint (`role=server`) and connecting via TS/Go clients

## Key Concepts

- Endpoint roles: `client` vs `server` are protocol roles.
- One-time tokens: tunnel attach tokens are single-use; mint a fresh channel init for each attempt.
- Untrusted tunnel: the tunnel cannot decrypt or interpret application data after attach.
- Single-instance tunnel: token replay protection is in-memory. To scale without shared state, shard channels across multiple tunnel endpoints at the control plane layer (set different `tunnel_url` values per channel).
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

Go workspace:

- The repo includes a root `go.work`, so you can run Go commands from the repo root (e.g. `go run ./examples/...` or `go test ./go/... ./examples/...`).

## Tunnel defaults (important for deployment)

The deployable tunnel binary is `go/cmd/flowersec-tunnel/`.

- TLS is **disabled by default**. For any non-local deployment, use `wss://` (either enable `--tls-cert-file/--tls-key-file` or terminate TLS at a reverse proxy).
- Origin checks are **enabled by default** and require an explicit allow-list:
  - `--allow-origin` accepts either a hostname (e.g. `example.com`) or a full Origin value (e.g. `https://example.com` or `http://127.0.0.1:5173`).
  - Requests without `Origin` are **rejected by default**; `--allow-no-origin` is intended for non-browser clients (discouraged).
  - Client helpers require an explicit origin: in browsers pass `window.location.origin`; in Node pass `origin` and a `wsFactory` that sets the `Origin` header (use `createNodeWsFactory` from `@flowersec/core/node`).
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

The tunnel binary exposes Prometheus metrics on a dedicated metrics server. Metrics are disabled by default and `/metrics` returns 404 until enabled.

- Enable metrics: send `SIGUSR1`
- Disable metrics: send `SIGUSR2`
- Endpoint: `GET /metrics` on the metrics server (`--metrics-listen`)

Example:

```bash
# run tunnel
go run ./go/cmd/flowersec-tunnel \
  --listen 127.0.0.1:8080 \
  --metrics-listen 127.0.0.1:9090 \
  --issuer-keys-file /path/to/keys.json \
  --aud your-audience \
  --iss your-issuer \
  --allow-origin http://127.0.0.1:5173

# enable metrics
kill -USR1 <pid>

# scrape metrics
curl http://127.0.0.1:9090/metrics
```

Library integrations:

- Go tunnel: set `server.Config.Observer` if you run the server directly.
- Go RPC: attach an observer via `rpc.Server.SetObserver(...)` or `rpc.Client.SetObserver(...)`.
- TS client: pass `observer` into `connectTunnel(...)` / `connectDirect(...)`, `WebSocketBinaryTransport`, or `RpcClient`.

## Binaries

- Tunnel server (deployable): `go/cmd/flowersec-tunnel/`
  - flags: `--listen`, `--ws-path`, `--issuer-keys-file`, `--aud`, `--iss`, `--allow-origin`, `--allow-no-origin`, `--tls-cert-file`, `--tls-key-file`, `--metrics-listen`
