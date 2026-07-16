# @floegence/flowersec-core

Flowersec core TypeScript library for the complete portable Flowersec client/server contract in Node.js, plus the browser and Service Worker runtime owned by TypeScript.

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
import { createControlplaneArtifactSource } from "@floegence/flowersec-core/reconnect";

const artifact = await requestConnectArtifact({
  baseUrl: "https://your-app.example/api/flowersec",
  endpointId: "env_demo",
});

const client = await connectNode(artifact, {
  origin: "https://your-app.example",
});
await client.ping();
const rttMs = await client.probeLiveness();
client.close();

const reconnectConfig = createNodeReconnectConfig({
  source: createControlplaneArtifactSource({
    baseUrl: "https://your-app.example/api/flowersec",
    endpointId: "env_demo",
  }),
  connect: {
    origin: "https://your-app.example",
  },
});
```

Browser `requestConnectArtifact(...)`, `requestEntryConnectArtifact(...)`, and `ControlplaneRequestError` remain available from `@floegence/flowersec-core/browser` as stable aliases.

High-level connects use `RequireTLS` by default. `AllowPlaintextForLoopback` permits only literal loopback
targets without DNS resolution. Deliberate non-loopback `ws://` connections must use
`createNetworkPlaintextPolicy(...)` with exact canonical IP literals and
`PlaintextRiskAcceptance.acceptPreE2ECredentialExposure`. The unrestricted `AllowPlaintext` preset is deprecated.

## Node endpoint and controlplane

`@floegence/flowersec-core/node` exports the high-level endpoint APIs for accepted direct WebSockets and server-role tunnel grants. `@floegence/flowersec-core/endpoint` provides portable session and RPC serving, while `@floegence/flowersec-core/controlplane` provides bounded artifact envelopes, FST2 tokens, issuer rotation, and channel initialization.

## Proxy

`@floegence/flowersec-core/proxy` contains both portable HTTP/1 and WebSocket proxy protocols and the TypeScript-owned browser runtime. Node endpoint servers use `serveProxySession(...)`; browser applications use the Service Worker or controller bridge helpers without changing the portable stream contract.

## Docs

- Frontend quickstart: `docs/FRONTEND_QUICKSTART.md`
- Integration guide: `docs/INTEGRATION_GUIDE.md`
- API surface contract: `docs/API_SURFACE.md`
- Controlplane artifact fetch: `docs/CONTROLPLANE_ARTIFACT_FETCH.md`
- Error model: `docs/ERROR_MODEL.md`
- Migration guide: `docs/V0_20_MIGRATION.md`
