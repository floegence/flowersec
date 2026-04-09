# Flowersec demos

This folder is the demo cookbook for Flowersec.

v0.19.x makes the artifact-first path the recommended demo path, while keeping the older raw grant/direct demos available as advanced compatibility references.

## Recommended demo flow

If you have Node.js installed, spin up the dev server and capture its ready JSON:

```bash
node ./examples/ts/dev-server.mjs | tee dev.json
```

Then use the artifact-first URLs in the generated JSON (`browser_tunnel_url`, `browser_direct_url`, `browser_proxy_sandbox_url`) to drive the browser demos.

Recommended quick checks without leaving artifact-first wiring:

- browser / artifact-first connect: open one of the URLs above or POST to `/__demo/connect/artifact`
- browser / direct artifact-first connect: open `browser_direct_url` or GET `/__demo/direct/artifact`
- proxy runtime / artifact-first connect: POST to `/__demo/proxy/artifact` and use the returned artifact bundle in `examples/ts/proxy-sandbox`
- node / artifact-first connect: pull `controlplane_http_url` from `dev.json` (`jq -r '.controlplane_http_url' dev.json`) and start `FSEC_CONTROLPLANE_BASE_URL=$(jq -r '.controlplane_http_url' dev.json) node ./examples/ts/node-artifact-client.mjs`
- node / tunnel artifact from stdin: `curl -sS -X POST $(jq -r '.controlplane_http_url' dev.json)/v1/connect/artifact -H 'content-type: application/json' -d '{"endpoint_id":"server-1"}' | jq -c .connect_artifact | FSEC_ORIGIN=http://127.0.0.1:5173 node ./examples/ts/node-tunnel-client.mjs`
- node / direct artifact from stdin: `curl -sS http://127.0.0.1:5173/__demo/direct/artifact | jq -c .connect_artifact | FSEC_ORIGIN=http://127.0.0.1:5173 node ./examples/ts/node-direct-client.mjs`

## Artifact-aware CLI helpers

Tunnel:

```bash
flowersec-channelinit \
  --issuer-private-key-file ./keys/issuer_key.json \
  --tunnel-url ws://127.0.0.1:8080/ws \
  --aud flowersec-tunnel:dev \
  --iss issuer-dev \
  --format artifact \
  --server-grant-out ./server-grant.json \
  > ./client-artifact.json
```

Direct:

```bash
flowersec-directinit --format artifact > ./direct-artifact.json
```

These outputs are intended for:

- browser `connectBrowser(...)`
- node `connectNode(...)`
- go `client.Connect(...)`

## Compatibility notes

Still supported in demos:

- raw `grant_client`
- wrapper JSON
- raw `DirectConnectInfo`

Preferred in new demos/scripts:

- `ConnectArtifact`

Advanced compatibility demos:

- browser pages that accept raw `grant_client`
- node tunnel clients that accept raw grant JSON

## Troubleshooting

- `token_replay`: tunnel tokens are one-time use; mint a new artifact/grant
- browser connect rejected: check Origin allow-lists
- gateway profile config no longer works as stable surface: switch to `proxy.preset_file`
