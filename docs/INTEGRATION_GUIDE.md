# Flowersec Integration Guide

This guide covers the recommended stable integration path for Flowersec v0.19.x.

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
3. use `@floegence/flowersec-core/controlplane` or Go `controlplane/client` for client-side artifact fetch
4. use `controlplane/http` for the server-side helper contract when you want a reference layer
5. use preset manifests instead of named proxy profiles

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
- `controlplanehttp.NewArtifactHandler(...)`
- `controlplanehttp.NewEntryArtifactHandler(...)`

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

Controlplane:

- `requestConnectArtifact(...)`
- `requestEntryConnectArtifact(...)`
- `ControlplaneRequestError`

Browser:

- `connectBrowser(...)`
- `createBrowserReconnectConfig(...)`

Node:

- `connectNode(...)`
- `createNodeReconnectConfig(...)`

Proxy preset helpers:

- `assertProxyPresetManifest(...)`
- `resolveProxyPreset(...)`

## Browser artifact-first example

```ts
import { connectBrowser } from "@floegence/flowersec-core/browser";
import { requestConnectArtifact } from "@floegence/flowersec-core/controlplane";

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
import { connectNode, createNodeReconnectConfig } from "@floegence/flowersec-core/node";
import { requestConnectArtifact } from "@floegence/flowersec-core/controlplane";

const artifact = await requestConnectArtifact({
  baseUrl: "https://controlplane.example.com",
  endpointId: "env_demo",
});

const client = await connectNode(artifact, {
  origin: "https://app.example.com",
});

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

## Go controlplane/http reference-layer example

```go
handler := controlplanehttp.NewArtifactHandler(controlplanehttp.ArtifactHandlerOptions{
	ExtractMetadata: func(r *http.Request) (controlplanehttp.ArtifactRequestMetadata, error) {
		return controlplanehttp.DefaultRequestMetadata(r), nil
	},
	IssueArtifact: func(ctx context.Context, input controlplanehttp.ArtifactIssueInput) (*protocolio.ConnectArtifact, error) {
		return artifactIssuer(ctx, input)
	},
})
```

`controlplane/http` deliberately leaves auth, same-origin binding, replay policy, and audit decisions in application-owned hooks.

That division of responsibility is part of the stable integration contract:

- Flowersec helpers own the controlplane request/response envelope and bounded artifact parsing.
- Your application owns who may call the endpoint, which origins are trusted, how replay is prevented, and how issuance is audited.

For the detailed artifact-fetch contract, including the bounded 1 MiB response rule and helper error semantics, see `docs/CONTROLPLANE_ARTIFACT_FETCH.md`.

## Reconnect guidance

For browser and Node reconnect flows:

- use `createBrowserReconnectConfig(...)` or `createNodeReconnectConfig(...)`
- supply `artifact`, `getArtifact`, or `artifactControlplane`
- let the adapter carry forward `trace_id`, absorb the new `session_id`, and pass through cancellation `signal`

Do not push artifact/controlplane semantics down into the framework-agnostic reconnect core.

## Proxy/gateway guidance

Use preset manifests, not stable named profiles:

- gateway: `proxy.preset_file`
- TS helpers: `resolveProxyPreset(...)`

For browser runtime mode, prefer:

- `connectArtifactProxyBrowser(...)` for same-origin service-worker mode
- `connectArtifactProxyControllerBrowser(...)` plus `registerProxyAppWindow(...)` for controller-origin/runtime-isolation mode

Choose gateway mode only when you intentionally accept a trusted plaintext L7 relay. Runtime mode and gateway mode are different trust models, not interchangeable deployment skins.

Reference first-party files live under `reference/presets/`.

## Migration notes

v0.19.x intentionally tightens a few compatibility edges:

- hybrid ambiguous inputs fail fast
- legacy inputs mixed with artifact-only fields fail fast
- client-facing connect rejects `grant_server`
- bare `token` / `role` auto-detect heuristics are gone
- stable proxy helpers consume `proxy.runtime@1` only; experimental `scope_version = 2` is not dual-read by default

See `docs/V0_19_MIGRATION.md` for the full list.
