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
  - Allowed entries support full Origins (`http://127.0.0.1:5173`), hostname (`example.com`), hostname:port (`example.com:5173`), wildcard hostnames (`*.example.com`, subdomains only), and exact non-standard values (`null`).

## Demo CLI conventions

The demo bundle includes three long-running demo binaries that print a single "ready" JSON line to stdout:

- `flowersec-controlplane-demo`
- `flowersec-direct-demo`
- `flowersec-server-endpoint-demo`

They follow these conventions:

- `--help` includes copy/paste examples and documents stdout/stderr behavior and exit codes.
- stdout: a single JSON ready object (script-friendly)
- stderr: logs and errors
- Exit codes: `0` success, `2` usage error, `1` runtime error
- `--version` prints build info (in GitHub Release bundles it matches the bundle version)

## One-command dev server (recommended for browser demos)

If you have Node.js installed, the easiest way to run the full demo stack (no copy/paste, no extra terminals) is:

```bash
node ./examples/ts/dev-server.mjs | tee dev.json
```

- stdout: a single JSON `{"status":"ready", ...}` line (script-friendly)
- stderr: progress logs from the dev server and the spawned Go demos

Then open the URLs from `dev.json`:

- Tunnel demo: `browser_tunnel_url`
- Direct demo: `browser_direct_url`
- Proxy sandbox demo: `browser_proxy_sandbox_url`

Notes:

- The browser demos can now click "Fetch Grant" / "Fetch DirectConnectInfo" (served from the dev server under `/__demo/*`).
- Stop everything with Ctrl+C (the dev server shuts down child processes).

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

## Custom stream example: meta + bytes (direct path)

The direct demo server also exposes a custom stream kind `meta_bytes` to demonstrate the recommended
"JSON meta frame + raw bytes" pattern (see `docs/STREAMS.md`).

Terminal 2: run the Node client for the custom stream:

```bash
FSEC_ORIGIN=http://127.0.0.1:5173 node ./examples/ts/stream-meta-bytes/node-direct-client.mjs < direct.json
```

Optional env vars:

```bash
FSEC_META_BYTES=65536 FSEC_META_FILL_BYTE=97 \
  FSEC_ORIGIN=http://127.0.0.1:5173 node ./examples/ts/stream-meta-bytes/node-direct-client.mjs < direct.json
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

Terminal 3: start the server endpoint demo (role=server; control-connected). It prints a JSON "ready" line to stdout and logs to stderr:

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

Option A (recommended): use the dev server above (`node ./examples/ts/dev-server.mjs`).

Option B (manual): reuse the running servers from the scenarios above, then serve the demo bundle root:

```bash
python3 -m http.server 5173
```

- Tunnel demo: open `http://127.0.0.1:5173/examples/ts/browser-tunnel/` and paste the channel JSON (the `channel.json` you minted).
- Direct demo: open `http://127.0.0.1:5173/examples/ts/browser-direct/` and paste `direct.json`.
- Proxy sandbox demo (runtime mode): open `http://127.0.0.1:5173/examples/ts/proxy-sandbox/`, paste the channel JSON, click "Connect", then "Open App".

Tip: if you refresh/reconnect in the tunnel demo, mint a new channel init again (one-time token rule).

## Troubleshooting

- Tunnel fails with `token_replay`: you reused the same channel JSON. Mint a new one via `POST /v1/channel/init`.
- Browser cannot connect: ensure `FSEC_TUNNEL_ALLOW_ORIGIN` includes your page Origin (for example `http://127.0.0.1:5173`).
- Go binaries not found: ensure you extracted the demo bundle and run from its root (it contains `bin/`).
