# Flowersec demos

This folder is the demo cookbook for Flowersec.

v0.18.x adds an artifact-first path on top of the existing raw grant/direct demos.

## Recommended demo flow

If you have Node.js installed:

```bash
node ./examples/ts/dev-server.mjs | tee dev.json
```

Then open:

- `browser_tunnel_url`
- `browser_direct_url`
- `browser_proxy_sandbox_url`

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

## Troubleshooting

- `token_replay`: tunnel tokens are one-time use; mint a new artifact/grant
- browser connect rejected: check Origin allow-lists
- gateway profile config no longer works as stable surface: switch to `proxy.preset_file`
