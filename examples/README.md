# Examples

This folder is a hands-on cookbook for running Flowersec end-to-end using the real protocol stack:

- Tunnel path: WS Attach (text) + E2EE (FSEH/FSEC) + Yamux + RPC + extra `echo` stream
- Direct path (no tunnel): WS + E2EE + Yamux + RPC + extra `echo` stream

## Components (what each demo is)

- Tunnel server (deliverable): `flowersec-go/cmd/flowersec-tunnel/` (blind forwarder; verifies tokens; pairs by `channel_id` + `role`)
- Controlplane demo: `examples/go/controlplane_demo/` (owns issuer keys; mints `ChannelInitGrant` pairs)
- Go server endpoint demo: `examples/go/server_endpoint/` (acts as the endpoint with `role=server`; built on `flowersec-go/endpoint`)
- Clients:
  - Go:
    - Simple (uses `flowersec-go/client` helpers): `examples/go/go_client_tunnel_simple/`, `examples/go/go_client_direct_simple/`
    - Advanced (manual stack): `examples/go/go_client_tunnel/`, `examples/go/go_client_direct/`
  - TS (Node):
    - Simple (high-level helpers): `examples/ts/node-tunnel-client.mjs`, `examples/ts/node-direct-client.mjs`
    - Advanced (manual stack): `examples/ts/node-tunnel-client-advanced.mjs`, `examples/ts/node-direct-client-advanced.mjs`
  - TS (Browser):
    - Simple: `examples/ts/browser-tunnel/index.html`, `examples/ts/browser-direct/index.html`
    - Advanced: `examples/ts/browser-tunnel/advanced.html`, `examples/ts/browser-direct/advanced.html`

## Prerequisites

- Go (same major as `flowersec-go/go.mod`)
- Node.js (for TypeScript clients; recommended: Node.js 22 LTS)
- Optional: `jq` (to parse the JSON "ready" lines; you can also copy/paste manually)
  - Run Go commands from `examples/` (examples module) or `flowersec-go/` (library module). `make go-test` runs both.

## Build the TypeScript bundle (required for TS clients)

TS examples import from `flowersec-ts/dist/`, so build it once:

```bash
cd flowersec-ts
npm run build
```

## Important notes (read before running scenarios)

- Transport security: the attach layer is plaintext by design, so use `wss://` (or TLS terminated by a reverse proxy) in any non-local deployment. The tunnel binary supports optional TLS via `--tls-cert-file/--tls-key-file` (disabled by default).
- Token issuer (`iss`): the tunnel requires `--iss` and will reject tokens whose payload `iss` does not match. Keep your controlplane `--issuer-id` and tunnel `--iss` consistent.
- One-time tokens: tunnel enforces `token_id` single-use. If you re-run a client with the same `grant_client`/`grant_server`, you will hit token replay and the tunnel will close the connection.
  - Practical rule: mint a fresh channel (`POST /v1/channel/init`) for every new connection attempt.
- Role pairing: a tunnel channel requires exactly one `role=client` and one `role=server`.
  - TS tunnel client and Go tunnel client are both `role=client` and cannot talk to each other directly.
  - Use the server endpoint demo (`role=server`) as the peer for any tunnel client.
- Origin policy (required): the tunnel validates the WebSocket `Origin` header and requires an explicit allow-list.
  - Start the tunnel with `FSEC_TUNNEL_ALLOW_ORIGIN=<your-origin>` (required by `./examples/run-tunnel-server.sh`).
  - All clients must explicitly send an Origin header. The TS/Go client helpers require an explicit `origin` value.
  - Example (local): `FSEC_TUNNEL_ALLOW_ORIGIN=http://127.0.0.1:5173`

## Scenario A: TS client (Node) ↔ Go server endpoint (role=server) through tunnel

Terminal 1: start controlplane demo (default tunnel URL hint is `ws://127.0.0.1:8080/ws`)

```bash
CP_JSON="$(mktemp -t fsec-controlplane.XXXXXX.json)"
./examples/run-controlplane-demo.sh | tee "$CP_JSON"
```

It prints a first JSON line including `controlplane_http_url`, `issuer_keys_file`, and the tunnel params needed to start the deployable tunnel server (including `tunnel_issuer`).

Terminal 2: start tunnel server (deployable service, no code changes)

```bash
FSEC_TUNNEL_ALLOW_ORIGIN=http://127.0.0.1:5173 \
FSEC_TUNNEL_ISSUER_KEYS_FILE="$(jq -r '.issuer_keys_file' "$CP_JSON")" \
FSEC_TUNNEL_AUD="$(jq -r '.tunnel_audience' "$CP_JSON")" \
FSEC_TUNNEL_ISS="$(jq -r '.tunnel_issuer' "$CP_JSON")" \
FSEC_TUNNEL_LISTEN="$(jq -r '.tunnel_listen' "$CP_JSON")" \
FSEC_TUNNEL_WS_PATH="$(jq -r '.tunnel_ws_path' "$CP_JSON")" \
./examples/run-tunnel-server.sh
```

Optional TLS (disabled by default):

```bash
# If you export the TLS env vars before starting the controlplane demo,
# it automatically switches the issued tunnel_url to wss://.
FSEC_TUNNEL_TLS_CERT_FILE=/path/to/cert.pem \
FSEC_TUNNEL_TLS_KEY_FILE=/path/to/key.pem \
./examples/run-tunnel-server.sh
```

Terminal 3: mint a channel (grants) and start the server endpoint (server-side grant)

```bash
CHANNEL_JSON="$(mktemp -t fsec-channel.XXXXXX.json)"
CP_URL="$(jq -r '.controlplane_http_url' "$CP_JSON")"
curl -sS -X POST "$CP_URL/v1/channel/init" | tee "$CHANNEL_JSON"
FSEC_ORIGIN=http://127.0.0.1:5173 ./examples/run-server-endpoint.sh "$CHANNEL_JSON"
```

Terminal 4: run the TS tunnel client (client-side grant)

```bash
FSEC_ORIGIN=http://127.0.0.1:5173 node ./examples/ts/node-tunnel-client.mjs < "$CHANNEL_JSON"
```

Advanced variant (manual stack):

```bash
FSEC_ORIGIN=http://127.0.0.1:5173 node ./examples/ts/node-tunnel-client-advanced.mjs < "$CHANNEL_JSON"
```

Expected: one RPC response + one RPC notify + one `echo` stream roundtrip.

## Scenario B: TS client (Browser) ↔ Go server endpoint (role=server) through tunnel

Reuse Scenario A terminals 1-3 (controlplane + tunnel + server endpoint).

Then serve the repo root:

```bash
python3 -m http.server 5173
```

Open `http://127.0.0.1:5173/examples/ts/browser-tunnel/` and paste the channel JSON (the same file you wrote in Terminal 3, e.g. `$CHANNEL_JSON`).

Tip: if you refresh/reconnect, mint a new channel again (one-time token rule).

## Scenario C: Go client ↔ Go server endpoint (role=server) through tunnel

Reuse Scenario A terminals 1-3 (controlplane + tunnel + server endpoint), then:

```bash
cd examples
go run ./go/go_client_tunnel --origin http://127.0.0.1:5173 < "$CHANNEL_JSON"
```

Simple variant (uses `flowersec-go/client`):

```bash
cd examples
go run ./go/go_client_tunnel_simple --origin http://127.0.0.1:5173 < "$CHANNEL_JSON"
```

## Scenario D: TS client (Node) ↔ Go direct server (no tunnel)

Terminal 1: start the direct server (no Attach; WS immediately runs E2EE server + Yamux server)

```bash
cd examples
go run ./go/direct_demo --allow-origin http://127.0.0.1:5173 | tee /tmp/fsec-direct.json
```

Terminal 2: run the TS direct client

```bash
FSEC_ORIGIN=http://127.0.0.1:5173 node ./examples/ts/node-direct-client.mjs < /tmp/fsec-direct.json
```

Advanced variant (manual stack):

```bash
FSEC_ORIGIN=http://127.0.0.1:5173 node ./examples/ts/node-direct-client-advanced.mjs < /tmp/fsec-direct.json
```

## Scenario E: Go client ↔ Go direct server (no tunnel)

Reuse Scenario D terminal 1, then:

```bash
cd examples
go run ./go/go_client_direct --origin http://127.0.0.1:5173 < /tmp/fsec-direct.json
```

Simple variant (uses `flowersec-go/client`):

```bash
cd examples
go run ./go/go_client_direct_simple --origin http://127.0.0.1:5173 < /tmp/fsec-direct.json
```

## Troubleshooting

- Tunnel fails with "token replay": you reused the same channel JSON (e.g. `$CHANNEL_JSON`). Mint a new one via `POST /v1/channel/init`.
- Nothing can connect: check that `FSEC_TUNNEL_URL` in `./examples/run-controlplane-demo.sh` matches the tunnel listen/ws-path you actually started.
