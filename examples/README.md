# Examples

This folder is a hands-on cookbook for running Flowersec end-to-end using the real protocol stack:

- Tunnel path: WS Attach (text) + E2EE (FSEH/FSEC) + Yamux + RPC + extra `echo` stream
- Direct path (no tunnel): WS + E2EE + Yamux + RPC + extra `echo` stream

## Components (what each demo is)

- Tunnel server (deliverable): `go/cmd/flowersec-tunnel/` (blind forwarder; verifies tokens; pairs by `channel_id` + `role`)
- Controlplane demo: `examples/go/controlplane_demo/` (owns issuer keys; mints `ChannelInitGrant` pairs)
- Go server endpoint demo: `examples/go/server_endpoint/` (acts as the endpoint with `role=server`; runs E2EE server + Yamux server)
- Clients:
  - Go: `examples/go/go_client_tunnel/`, `examples/go/go_client_direct/`
  - TS (Node): `examples/ts/node-tunnel-client.mjs`, `examples/ts/node-direct-client.mjs`
  - TS (Browser): `examples/ts/browser-tunnel/`, `examples/ts/browser-direct/`

## Prerequisites

- Go (same major as `go/go.mod`)
- Node.js (for TypeScript clients)
- Optional: `jq` (to parse the JSON "ready" lines; you can also copy/paste manually)

## Build the TypeScript bundle (required for TS clients)

TS examples import from `ts/dist/`, so build it once:

```bash
cd ts
npm run build
```

## Important notes (read before running scenarios)

- One-time tokens: tunnel enforces `token_id` single-use. If you re-run a client with the same `grant_client`/`grant_server`, you will hit token replay and the tunnel will close the connection.
  - Practical rule: mint a fresh channel (`POST /v1/channel/init`) for every new connection attempt.
- Role pairing: a tunnel channel requires exactly one `role=client` and one `role=server`.
  - TS tunnel client and Go tunnel client are both `role=client` and cannot talk to each other directly.
  - Use the server endpoint demo (`role=server`) as the peer for any tunnel client.
- Browser Origin: the tunnel validates the WebSocket `Origin` header. For browser scenarios you must allow your page origin.
  - Example: `FSEC_TUNNEL_ALLOW_ORIGIN=http://127.0.0.1:5173 ./examples/run-tunnel-server.sh`

## Scenario A: TS client (Node) ↔ Go server endpoint (role=server) through tunnel

Terminal 1: start controlplane demo (default tunnel URL hint is `ws://127.0.0.1:8080/ws`)

```bash
./examples/run-controlplane-demo.sh | tee /tmp/fsec-controlplane.json
```

It prints a first JSON line including `controlplane_http_url` and a copy-pastable `tunnel_start_cmd`.

Terminal 2: start tunnel server (deployable service, no code changes)

```bash
eval "$(jq -r '.tunnel_start_cmd' /tmp/fsec-controlplane.json)"
```

Terminal 3: mint a channel (grants) and start the server endpoint (server-side grant)

```bash
CP_URL="$(jq -r '.controlplane_http_url' /tmp/fsec-controlplane.json)"
curl -sS -X POST "$CP_URL/v1/channel/init" | tee /tmp/fsec-channel.json
./examples/run-server-endpoint.sh /tmp/fsec-channel.json
```

Terminal 4: run the TS tunnel client (client-side grant)

```bash
node ./examples/ts/node-tunnel-client.mjs < /tmp/fsec-channel.json
```

Expected: one RPC response + one RPC notify + one `echo` stream roundtrip.

## Scenario B: TS client (Browser) ↔ Go server endpoint (role=server) through tunnel

Reuse Scenario A terminals 1-3 (controlplane + tunnel + server endpoint).

If you started the tunnel server without an allow-list, restart it with an allowed Origin (Terminal 2):

```bash
FSEC_TUNNEL_ALLOW_ORIGIN=http://127.0.0.1:5173 eval "$(jq -r '.tunnel_start_cmd' /tmp/fsec-controlplane.json)"
```

Then serve the repo root:

```bash
python3 -m http.server 5173
```

Open `http://127.0.0.1:5173/examples/ts/browser-tunnel/` and paste `/tmp/fsec-channel.json`.

Tip: if you refresh/reconnect, mint a new channel again (one-time token rule).

## Scenario C: Go client ↔ Go server endpoint (role=server) through tunnel

Reuse Scenario A terminals 1-3 (controlplane + tunnel + server endpoint), then:

```bash
go run ./examples/go/go_client_tunnel < /tmp/fsec-channel.json
```

## Scenario D: TS client (Node) ↔ Go direct server (no tunnel)

Terminal 1: start the direct server (no Attach; WS immediately runs E2EE server + Yamux server)

```bash
go run ./examples/go/direct_demo | tee /tmp/fsec-direct.json
```

Terminal 2: run the TS direct client

```bash
node ./examples/ts/node-direct-client.mjs < /tmp/fsec-direct.json
```

## Scenario E: Go client ↔ Go direct server (no tunnel)

Reuse Scenario D terminal 1, then:

```bash
go run ./examples/go/go_client_direct < /tmp/fsec-direct.json
```

## Troubleshooting

- Tunnel fails with "token replay": you reused `/tmp/fsec-channel.json`. Mint a new one via `POST /v1/channel/init`.
- Nothing can connect: check that `FSEC_TUNNEL_URL` in `./examples/run-controlplane-demo.sh` matches the tunnel listen/ws-path you actually started.
