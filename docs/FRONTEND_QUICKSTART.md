# Frontend Quickstart (TypeScript)

This guide is for frontend developers who want to use Flowersec from TypeScript (Browser or Node.js) without learning the full protocol stack upfront.

If you want the full integration story (controlplane, tunnel deployment, server endpoints), see `docs/INTEGRATION_GUIDE.md`.

## 5-minute local demo (no clone)

1) Download and extract the `flowersec-demos` bundle from GitHub Releases.

2) From the extracted bundle root, start the demo dev server:

```bash
node ./examples/ts/dev-server.mjs | tee dev.json
```

3) Open the browser demo URL printed in `dev.json`:

- Tunnel demo: `browser_tunnel_url` (click "Fetch Grant", then "Connect")
- Direct demo: `browser_direct_url` (click "Fetch DirectConnectInfo", then "Connect")

Notes:

- Ctrl+C stops everything (the dev server shuts down the spawned Go demo processes).
- Tunnel grants are one-time use; click "Fetch Grant" again if you refresh/reconnect.

## Install

```bash
npm install @floegence/flowersec-core
```

## Browser: connect (recommended)

In browsers, use `@floegence/flowersec-core/browser` so the Origin header matches `window.location.origin`.

```ts
import { connectBrowser } from "@floegence/flowersec-core/browser";

// Your backend should mint and return a ChannelInitGrant (or the full {"grant_client": ...} wrapper).
const grant = await fetch("/api/flowersec/channel/init", { method: "POST" }).then((r) => r.json());

const client = await connectBrowser(grant);
await client.ping(); // encrypted keepalive ping (verifies the secure channel)
client.close();
```

## Node.js: connect (recommended)

In Node.js, use `@floegence/flowersec-core/node` so the Origin header is set correctly.

```ts
import { connectNode } from "@floegence/flowersec-core/node";

const grant = await fetch("https://your-app.example/api/flowersec/channel/init", { method: "POST" }).then((r) => r.json());

const client = await connectNode(grant, {
  origin: "https://your-app.example", // must be allowed by the tunnel/direct server Origin policy
});
await client.ping();
client.close();
```

## Common gotchas

- One-time tokens (`code=token_replay`): tunnel channel init tokens are single-use; mint a new grant for every new connection attempt.
- Origin policy: the tunnel and direct demo servers enforce an Origin allow-list by default.
  - Browser Origin is `window.location.origin` and must be explicitly allowed by the server.
  - Node.js must pass an explicit `origin` string (use `connectNode` / `connectTunnelNode` / `connectDirectNode`).

## Next steps

- Integration guide: `docs/INTEGRATION_GUIDE.md`
- API surface contract: `docs/API_SURFACE.md`
- Error model: `docs/ERROR_MODEL.md`
- Demos cookbook: `examples/README.md`
