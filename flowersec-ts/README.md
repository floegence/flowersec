# @floegence/flowersec-core

Flowersec core TypeScript library for building end-to-end encrypted, multiplexed connections over WebSocket in browsers and Node.js.

Status: experimental; not audited.

## Install

```bash
npm install @floegence/flowersec-core
```

## Recommended usage

Browser:

```ts
import { connectBrowser } from "@floegence/flowersec-core/browser";
import { requestConnectArtifact } from "@floegence/flowersec-core/controlplane";

const artifact = await requestConnectArtifact({
  endpointId: "env_demo",
});

const client = await connectBrowser(artifact);
await client.ping();
client.close();
```

Node.js:

```ts
import { connectNode, createNodeReconnectConfig } from "@floegence/flowersec-core/node";
import { requestConnectArtifact } from "@floegence/flowersec-core/controlplane";

const artifact = await requestConnectArtifact({
  baseUrl: "https://your-app.example/api/flowersec",
  endpointId: "env_demo",
});

const client = await connectNode(artifact, {
  origin: "https://your-app.example",
});
await client.ping();
client.close();

const reconnectConfig = createNodeReconnectConfig({
  artifactControlplane: {
    baseUrl: "https://your-app.example/api/flowersec",
    endpointId: "env_demo",
  },
  connect: {
    origin: "https://your-app.example",
  },
});
```

Browser `requestConnectArtifact(...)`, `requestEntryConnectArtifact(...)`, and `ControlplaneRequestError` remain available from `@floegence/flowersec-core/browser` as stable aliases.

## Docs

- Frontend quickstart: `docs/FRONTEND_QUICKSTART.md`
- Integration guide: `docs/INTEGRATION_GUIDE.md`
- API surface contract: `docs/API_SURFACE.md`
- Controlplane artifact fetch: `docs/CONTROLPLANE_ARTIFACT_FETCH.md`
- Error model: `docs/ERROR_MODEL.md`
- Migration guide: `docs/V0_19_MIGRATION.md`
