# Flowersec v0.19 Migration Guide

Flowersec v0.19.x is the release where the artifact-first path becomes the recommended integration baseline across browser, Node, Go, and proxy bootstrap helpers.

## What changed

### New recommended stable entrypoints

- TypeScript controlplane helpers move to `@floegence/flowersec-core/controlplane`
- Node gets artifact-aware reconnect helpers:
  - `createNodeReconnectConfig(...)`
  - `createTunnelNodeReconnectConfig(...)`
  - `createDirectNodeReconnectConfig(...)`
- Browser proxy bootstrap gets artifact-first helpers:
  - `connectArtifactProxyBrowser(...)`
  - `connectArtifactProxyControllerBrowser(...)`
- Go gets `github.com/floegence/flowersec/flowersec-go/controlplane/http` as a thin HTTP reference layer

### Compatibility APIs that still work

- raw `ChannelInitGrant`
- wrapper `{grant_client: ...}`
- raw `DirectConnectInfo`
- browser `requestChannelGrant(...)`
- browser `requestEntryChannelGrant(...)`
- `connectTunnelProxyBrowser(...)`
- `connectTunnelProxyControllerBrowser(...)`

These remain supported, but they are no longer the recommended path for new integrations.

## Migration steps

### 1. Move artifact fetch to the shared controlplane helper

Before:

```ts
import { requestConnectArtifact } from "@floegence/flowersec-core/browser";
```

After:

```ts
import { requestConnectArtifact } from "@floegence/flowersec-core/controlplane";
```

Browser re-exports remain available as stable aliases during the compatibility window.

### 2. Prefer artifact-aware reconnect adapters

Before:

- custom `fetch(...) + unwrap + connectNode(...)` loops
- reconnect code that re-minted grants outside the adapter

After:

```ts
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

### 3. Switch browser proxy bootstrap to artifact-first

Same-origin service worker:

```ts
const proxy = await connectArtifactProxyBrowser(artifact, {
  serviceWorker: { scriptUrl: "/proxy-sw.js", scope: "/" },
});
```

Controller-origin/runtime-isolation:

```ts
const controller = await connectArtifactProxyControllerBrowser(artifact);
const appBridge = registerProxyAppWindow({ controllerOrigin: "https://controller.example.com" });
```

### 4. Keep `proxy.runtime` expectations tight

Stable helper contract:

- only `scope = "proxy.runtime"` with `scope_version = 1`
- supported modes:
  - `service_worker`
  - `controller_bridge`

Not part of the stable dual-read promise:

- experimental `scope_version = 2`
- payload-internal version fields
- ad hoc deployment/path fields that the SDK does not directly consume

## Behavior that is intentionally strict

v0.19.x still rejects:

- hybrid ambiguous connect inputs
- legacy connect inputs mixed with artifact-only fields
- client-facing `grant_server` inputs
- unsupported `proxy.runtime` versions in stable proxy helper entrypoints

## Suggested rollout order

1. move client-side artifact fetches to the stable controlplane helper
2. switch reconnect code to the artifact-aware browser/node adapters
3. switch browser proxy bootstrap to the artifact-first helpers
4. adopt `controlplane/http` on the Go server side only where it removes repeated decode/write boilerplate

## Related docs

- `docs/API_SURFACE.md`
- `docs/CONTROLPLANE_ARTIFACT_FETCH.md`
- `docs/CONNECT_ARTIFACTS.md`
- `docs/SCOPED_METADATA.md`
- `docs/PROXY.md`
