# Flowersec Integration Guide

This guide covers the recommended stable integration path for Flowersec v0.18.x.

See also:

- Frontend quickstart: `docs/FRONTEND_QUICKSTART.md`
- API surface: `docs/API_SURFACE.md`
- Connect artifacts: `docs/CONNECT_ARTIFACTS.md`
- Controlplane artifact fetch: `docs/CONTROLPLANE_ARTIFACT_FETCH.md`
- Error model: `docs/ERROR_MODEL.md`

## Recommended shape for new integrations

For new work, prefer:

1. mint or fetch a client-facing `ConnectArtifact`
2. connect with the high-level browser/node/go client entrypoints
3. use preset manifests instead of named proxy profiles

Legacy raw grant / wrapper / direct inputs are still supported as compatibility edges, but they are no longer the preferred controlplane contract.

## Install

Go:

```bash
go get github.com/floegence/flowersec/flowersec-go@latest
```

TypeScript:

```bash
npm install @floegence/flowersec-core
```

## Stable entrypoints

### Go

Client:

- `client.Connect(ctx, input, ...opts)`
- `client.ConnectTunnel(ctx, grant, ...opts)`
- `client.ConnectDirect(ctx, info, ...opts)`

Artifact helpers:

- `protocolio.DecodeConnectArtifactJSON(...)`
- `client.RequestConnectArtifact(...)`
- `client.RequestEntryConnectArtifact(...)`

Observability:

- `client.WithObserver(...)`
- `observability.DiagnosticEvent`

Proxy preset helpers:

- `preset.DecodeJSON(...)`
- `preset.LoadFile(...)`

### TypeScript

Root:

- `connect(...)`
- `connectTunnel(...)`
- `connectDirect(...)`
- `assertConnectArtifact(...)`

Browser:

- `connectBrowser(...)`
- `requestConnectArtifact(...)`
- `requestEntryConnectArtifact(...)`
- `createBrowserReconnectConfig(...)`

Node:

- `connectNode(...)`

Proxy preset helpers:

- `assertProxyPresetManifest(...)`
- `resolveProxyPreset(...)`

## Browser artifact-first example

```ts
import { connectBrowser, requestConnectArtifact } from "@floegence/flowersec-core/browser";

const artifact = await requestConnectArtifact({
  baseUrl: "https://controlplane.example.com",
  endpointId: "env_demo",
});

const client = await connectBrowser(artifact, {});
await client.ping();
client.close();
```

## Node artifact-first example

```ts
import { connectNode } from "@floegence/flowersec-core/node";

const artifact = await fetch("https://controlplane.example.com/v1/connect/artifact", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ endpoint_id: "env_demo" }),
}).then((r) => r.json());

const client = await connectNode(artifact, {
  origin: "https://app.example.com",
});
```

## Go artifact-first example

```go
artifact, err := cpclient.RequestConnectArtifact(ctx, cpclient.ConnectArtifactRequestConfig{
	BaseURL:    "https://controlplane.example.com",
	EndpointID: "env_demo",
})
if err != nil {
	return err
}

cli, err := client.Connect(ctx, artifact, client.WithOrigin("https://app.example.com"))
if err != nil {
	return err
}
defer cli.Close()
```

## Reconnect guidance

For browser reconnect flows:

- use `createBrowserReconnectConfig(...)`
- supply `artifact`, `getArtifact`, or `artifactControlplane`
- let the adapter carry forward `trace_id` and absorb the new `session_id`

Do not push artifact/controlplane semantics down into the framework-agnostic reconnect core.

## Proxy/gateway guidance

Use preset manifests, not stable named profiles:

- gateway: `proxy.preset_file`
- TS helpers: `resolveProxyPreset(...)`

Reference first-party files live under `reference/presets/`.

## Migration notes

v0.18.x intentionally tightens a few compatibility edges:

- hybrid ambiguous inputs fail fast
- legacy inputs mixed with artifact-only fields fail fast
- client-facing connect rejects `grant_server`
- bare `token` / `role` auto-detect heuristics are gone

See `docs/V0_18_MIGRATION.md` for the full list.
