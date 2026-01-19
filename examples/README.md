# Flowersec demos (no clone)

This folder is a hands-on cookbook for running Flowersec end-to-end using the real protocol stack:

- Tunnel path: WS Attach (text) + E2EE (FSEH/FSEC) + Yamux + RPC + extra `echo` stream
- Direct path (no tunnel): WS + E2EE + Yamux + RPC + extra `echo` stream

This guide assumes you are **not** cloning the repository. Clone is only for contributors.

## Get the demo bundle (recommended)

Download a prebuilt demo bundle from GitHub Releases (tag format: `flowersec-go/vX.Y.Z`).

Assets:

- `flowersec-demos_X.Y.Z_<os>_<arch>.tar.gz` (Linux/macOS) or `.zip` (Windows)
- `checksums.txt`

Supported `<os>_<arch>` values match the tunnel binaries:

- `linux_amd64`, `linux_arm64`
- `darwin_amd64`, `darwin_arm64`
- `windows_amd64`

After extracting, you should have:

- `bin/` (prebuilt Go binaries)
  - `flowersec-tunnel`
  - `flowersec-issuer-keygen`
  - `flowersec-channelinit`
  - `flowersec-controlplane-demo`
  - `flowersec-server-endpoint-demo`
  - `flowersec-direct-demo`
  - `flowersec-go-client-tunnel`
  - `flowersec-go-client-direct`
- `examples/ts/` (Node + Browser clients)
- `flowersec-ts/dist/` (prebuilt TS dist imported by the demo clients)

## Prerequisites

- Optional (Node demos): Node.js 22 LTS
- Optional (browser demos): `python3` or any static file server
- Optional: `jq` (makes JSON value extraction easy)

## Important notes

- Transport security: the attach layer is plaintext by design, so use `wss://` (or TLS terminated at a reverse proxy) in any non-local deployment.
- One-time tokens: tunnel enforces `token_id` single-use. Mint a new channel init (`POST /v1/channel/init`) for every new connection attempt.
- Origin policy (required): the tunnel validates the WebSocket `Origin` header and requires an explicit allow-list.
  - Allowed entries support full Origins (`http://127.0.0.1:5173`), hostname (`example.com`), hostname:port (`example.com:5173`), wildcard hostnames (`*.example.com`), and exact non-standard values (`null`).

## Quickstart: direct path (no tunnel)

Terminal 1: start the direct demo server (prints a JSON "ready" line):

```bash
./bin/flowersec-direct-demo --allow-origin http://127.0.0.1:5173 | tee direct.json
```

Terminal 2: run a Go direct client (reads the JSON from stdin):

```bash
FSEC_ORIGIN=http://127.0.0.1:5173 ./bin/flowersec-go-client-direct < direct.json
```

Terminal 2 (alternative): Node direct client:

```bash
FSEC_ORIGIN=http://127.0.0.1:5173 node ./examples/ts/node-direct-client.mjs < direct.json
```

## Full stack: tunnel path (controlplane + tunnel + server endpoint)

Terminal 1: start the controlplane demo (prints a JSON "ready" line):

```bash
./bin/flowersec-controlplane-demo | tee controlplane.json
```

Terminal 2: start the deployable tunnel server (required config: issuer keys + aud/iss + origin allow-list):

```bash
CP_JSON=controlplane.json
FSEC_TUNNEL_ALLOW_ORIGIN=http://127.0.0.1:5173 \
FSEC_TUNNEL_ISSUER_KEYS_FILE="$(jq -r '.issuer_keys_file' "$CP_JSON")" \
FSEC_TUNNEL_AUD="$(jq -r '.tunnel_audience' "$CP_JSON")" \
FSEC_TUNNEL_ISS="$(jq -r '.tunnel_issuer' "$CP_JSON")" \
FSEC_TUNNEL_LISTEN="$(jq -r '.tunnel_listen' "$CP_JSON")" \
FSEC_TUNNEL_WS_PATH="$(jq -r '.tunnel_ws_path' "$CP_JSON")" \
./bin/flowersec-tunnel | tee tunnel.json
```

Terminal 3: start the server endpoint demo (role=server; control-connected):

```bash
FSEC_ORIGIN=http://127.0.0.1:5173 ./bin/flowersec-server-endpoint-demo --control "$CP_JSON"
```

Terminal 4: mint a channel (grant_client) and run a client:

```bash
CHANNEL_JSON=channel.json
CP_URL="$(jq -r '.controlplane_http_url' "$CP_JSON")"
curl -sS -X POST "$CP_URL/v1/channel/init" | tee "$CHANNEL_JSON"
FSEC_ORIGIN=http://127.0.0.1:5173 node ./examples/ts/node-tunnel-client.mjs < "$CHANNEL_JSON"
```

Terminal 4 (alternative): Go tunnel client:

```bash
FSEC_ORIGIN=http://127.0.0.1:5173 ./bin/flowersec-go-client-tunnel < "$CHANNEL_JSON"
```

Expected: one RPC response + one RPC notify + one `echo` stream roundtrip.

## Browser demos

Reuse the running servers from the scenarios above, then serve the demo bundle root:

```bash
python3 -m http.server 5173
```

- Tunnel demo: open `http://127.0.0.1:5173/examples/ts/browser-tunnel/` and paste the channel JSON (the `channel.json` you minted).
- Direct demo: open `http://127.0.0.1:5173/examples/ts/browser-direct/` and paste `direct.json`.

Tip: if you refresh/reconnect in the tunnel demo, mint a new channel init again (one-time token rule).

## Troubleshooting

- Tunnel fails with "token replay": you reused the same channel JSON. Mint a new one via `POST /v1/channel/init`.
- Browser cannot connect: ensure `FSEC_TUNNEL_ALLOW_ORIGIN` includes your page Origin (for example `http://127.0.0.1:5173`).
- Go binaries not found: ensure you extracted the demo bundle and run from its root (it contains `bin/`).
