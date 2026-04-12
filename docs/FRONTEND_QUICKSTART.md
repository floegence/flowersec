# Frontend Quickstart (TypeScript)

This guide is for frontend developers who want the shortest path to a production-shaped Flowersec integration.

If you need the full backend/controlplane story, see `docs/INTEGRATION_GUIDE.md`.

## 5-minute local demo

```bash
node ./examples/ts/dev-server.mjs
```

That demo stack exercises the stable browser, node, controlplane, and proxy entrypoints while giving you a local controlplane/tunnel/direct environment.

## Install

```bash
npm install @floegence/flowersec-core
```

## Browser: artifact-first connect

Use `@floegence/flowersec-core/browser` for the browser client and `@floegence/flowersec-core/controlplane` for artifact fetch.

```ts
import { connectBrowser, createBrowserReconnectConfig } from "@floegence/flowersec-core/browser";
import { requestConnectArtifact } from "@floegence/flowersec-core/controlplane";

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

const reconnectConfig = createBrowserReconnectConfig({
  artifactControlplane: {
    baseUrl: "https://controlplane.example.com",
    endpointId: "env_demo",
    entryTicket: "one-time-ticket",
  },
  autoReconnect: { enabled: true },
});
```

`requestConnectArtifact(...)` and `requestEntryConnectArtifact(...)` throw `ControlplaneRequestError` on HTTP failures, preserving `status`, `code`, and the server message.

## Browser proxy: same-origin service worker

```ts
import { connectArtifactProxyBrowser } from "@floegence/flowersec-core/proxy";

const proxy = await connectArtifactProxyBrowser(artifact, {
  serviceWorker: {
    scriptUrl: "/proxy-sw.js",
    scope: "/",
  },
});
```

The stable `proxy.runtime@1` payload can prefill the same `serviceWorker.scriptUrl` / `serviceWorker.scope` fields, but caller-provided values still win when you need deployment-specific overrides.

In runtime mode, upstream cookies stay inside the proxy runtime's in-memory CookieJar rather than the browser cookie store. Cookie path scoping follows the proxied request path, including RFC-style path matching and request-path-derived defaults when `Set-Cookie` omits `Path`.

## Browser proxy: controller-origin / runtime-isolation

Controller origin:

```ts
import { connectArtifactProxyControllerBrowser } from "@floegence/flowersec-core/proxy";

const controller = await connectArtifactProxyControllerBrowser(artifact);
```

App origin:

```ts
import { registerProxyAppWindow } from "@floegence/flowersec-core/proxy";

const appBridge = registerProxyAppWindow({
  controllerOrigin: "https://controller.example.com",
});
```

This split keeps the raw runtime on the controller origin and exposes only the narrow app-window bridge on the app origin.

## Node: artifact-first connect

```ts
import { connectNode, createNodeReconnectConfig } from "@floegence/flowersec-core/node";
import { requestConnectArtifact } from "@floegence/flowersec-core/controlplane";

const artifact = await requestConnectArtifact({
  baseUrl: "https://controlplane.example.com",
  endpointId: "env_demo",
});

const client = await connectNode(artifact, {
  origin: "https://app.example.com",
});

await client.ping();
client.close();

const reconnectConfig = createNodeReconnectConfig({
  artifactControlplane: {
    baseUrl: "https://controlplane.example.com",
    endpointId: "env_demo",
  },
  connect: {
    origin: "https://app.example.com",
  },
});
```

Manual `fetch(...)` callers must unwrap the stable `connect_artifact` envelope before passing it to `connectNode(...)`.

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
- Migration guide: `docs/V0_19_MIGRATION.md`
- Demos cookbook: `examples/README.md`
