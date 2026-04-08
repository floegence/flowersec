# Frontend Quickstart (TypeScript)

This guide is for frontend developers who want the shortest path to a production-shaped Flowersec integration.

If you need the full backend/controlplane story, see `docs/INTEGRATION_GUIDE.md`.

## 5-minute local demo

```bash
node ./examples/ts/dev-server.mjs
```

That demo stack still exercises the stable browser/node entrypoints while giving you a local controlplane/tunnel/direct environment.

## Install

```bash
npm install @floegence/flowersec-core
```

## Browser: artifact-first connect

Use `@floegence/flowersec-core/browser` so Origin handling matches the browser environment.

```ts
import { connectBrowser, requestConnectArtifact } from "@floegence/flowersec-core/browser";

const artifact = await requestConnectArtifact({
  baseUrl: "https://controlplane.example.com",
  endpointId: "env_demo",
  correlation: {
    traceId: "trace-0001",
  },
});

const client = await connectBrowser(artifact, {});
await client.ping();
client.close();
```

## Node: artifact-first connect

```ts
import { connectNode } from "@floegence/flowersec-core/node";

const artifactEnvelope = await fetch("https://controlplane.example.com/v1/connect/artifact", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ endpoint_id: "env_demo" }),
}).then((r) => r.json());

const client = await connectNode(artifactEnvelope.connect_artifact, {
  origin: "https://app.example.com",
});

await client.ping();
client.close();
```

Manual `fetch(...)` callers must unwrap the stable `connect_artifact` envelope before passing it to `connectNode(...)`.

## Browser reconnect

```ts
import { createBrowserReconnectConfig } from "@floegence/flowersec-core/browser";
import { createReconnectManager } from "@floegence/flowersec-core/reconnect";

const mgr = createReconnectManager();

await mgr.connect(
  createBrowserReconnectConfig({
    artifactControlplane: {
      baseUrl: "https://controlplane.example.com",
      endpointId: "env_demo",
      entryTicket: "one-time-ticket",
    },
    autoReconnect: { enabled: true },
  })
);
```

`requestConnectArtifact(...)` and `requestEntryConnectArtifact(...)` throw `ControlplaneRequestError` on HTTP failures, preserving `status`, `code`, and the server message.

## Compatibility notes

Still supported:

- raw `ChannelInitGrant`
- wrapper `{grant_client: ...}`
- raw `DirectConnectInfo`
- `requestEntryChannelGrant(...)`

Now rejected:

- hybrid ambiguous objects
- legacy inputs mixed with artifact-only fields
- client-facing `grant_server`

Common tunnel gotcha:

- `token_replay` means the one-time tunnel token was reused; fetch a fresh artifact or grant before reconnecting

## Next steps

- API surface: `docs/API_SURFACE.md`
- Connect artifacts: `docs/CONNECT_ARTIFACTS.md`
- Correlation and diagnostics: `docs/CORRELATION_AND_DIAGNOSTICS.md`
- Migration guide: `docs/V0_18_MIGRATION.md`
- Demos cookbook: `examples/README.md`
