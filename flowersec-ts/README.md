# @floegence/flowersec-core

Flowersec core TypeScript library for building an end-to-end encrypted, multiplexed connection over WebSocket (browser-friendly).

Status: experimental; not audited.

## Install

```bash
npm install @floegence/flowersec-core
```

## Usage

Browser (recommended):

```ts
import { connectBrowser, requestConnectArtifact } from "@floegence/flowersec-core/browser";

const artifact = await requestConnectArtifact({
  endpointId: "env_demo",
});

const client = await connectBrowser(artifact);
await client.ping();
client.close();
```

Node.js (recommended):

```ts
import { connectNode } from "@floegence/flowersec-core/node";

const artifactEnvelope = await fetch("https://your-app.example/api/flowersec/connect/artifact", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ endpoint_id: "env_demo" }),
}).then((r) => r.json());

const client = await connectNode(artifactEnvelope.connect_artifact, {
  origin: "https://your-app.example",
});
await client.ping();
client.close();
```

## Docs

- Frontend quickstart: `docs/FRONTEND_QUICKSTART.md`
- Integration guide: `docs/INTEGRATION_GUIDE.md`
- API surface contract: `docs/API_SURFACE.md`
- Error model: `docs/ERROR_MODEL.md`
