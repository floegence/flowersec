# Flowersec Integration Guide

This guide covers the recommended stable integration path for Flowersec v0.23.0 across Go, TypeScript, Swift, and Rust.

See also:

- Frontend quickstart: `docs/FRONTEND_QUICKSTART.md`
- API surface: `docs/API_SURFACE.md`
- Connect artifacts: `docs/CONNECT_ARTIFACTS.md`
- Controlplane artifact fetch: `docs/CONTROLPLANE_ARTIFACT_FETCH.md`
- Error model: `docs/ERROR_MODEL.md`

## Recommended shape for new integrations

For new work, prefer:

1. mint or fetch a client-facing `ConnectArtifact`
2. connect with the high-level entrypoint for the selected SDK
3. use the language's controlplane client for bounded artifact fetch
4. use the language's controlplane envelope/issuer helpers for product-neutral server integration
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

Swift:

```swift
.package(url: "https://github.com/floegence/flowersec.git", from: "0.23.0")
```

Rust:

```bash
cargo add flowersec@0.23.0
```

## Stable entrypoints

### Go

Client:

- `client.Connect(ctx, input, ...opts)`
- `client.ConnectTunnel(ctx, grant, ...opts)`
- `client.ConnectDirect(ctx, info, ...opts)`
- `client.Client.Rekey()`
- `client.Client.OpenStream(...)` returning `stream.Stream`
- `stream.Stream.Reset()`

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
- connected client method `rekey()`
- connected stream method `reset()`

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

### Swift

- `Flowersec.connect(...)`
- `Flowersec.connectTunnel(...)`
- `Flowersec.connectDirect(...)`
- `FlowersecClient.rekey()`
- `FlowersecByteStream.reset()`
- `Controlplane.requestConnectArtifact(...)`
- `Endpoint.acceptDirect(...)`
- `Endpoint.connectTunnel(...)`
- `RPCRouter` / `RPCServer`
- `ReconnectManager`
- `ProxyClient` / `ProxyServer`

### Rust

- `flowersec::connect(...)`
- `flowersec::connect_tunnel(...)`
- `flowersec::connect_direct(...)`
- `flowersec::Client::rekey()`
- `flowersec::yamux::YamuxStream::reset()`
- `flowersec::controlplane::client`
- `flowersec::endpoint::{accept_direct, accept_direct_resolved, connect_tunnel}`
- `flowersec::rpc::{RpcClient, Router, Server}`
- `flowersec::reconnect::ReconnectManager`
- `flowersec::proxy::{ProxyClient, ProxyServer}`

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
import { createControlplaneArtifactSource } from "@floegence/flowersec-core/reconnect";

const artifact = await requestConnectArtifact({
  baseUrl: "https://controlplane.example.com",
  endpointId: "env_demo",
});

const client = await connectNode(artifact, {
  origin: "https://app.example.com",
});

const reconnectConfig = createNodeReconnectConfig({
  source: createControlplaneArtifactSource({
    baseUrl: "https://controlplane.example.com",
    endpointId: "env_demo",
  }),
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

## Rekey and stream reset

Use explicit rekey only when the application or operational policy requests a key transition. Rekey is serialized with ordinary encrypted writes and preserves the session, RPC, and open streams.

Use stream reset when a single flow must terminate immediately without closing the session. Reset sends only Yamux RST; keep local causes in logs or diagnostics. A successful reset must be followed by continued RPC and stream usability in integration tests.

## Swift artifact-first example

```swift
let artifact = try await Controlplane.requestConnectArtifact(
  ArtifactRequestOptions(
    baseURL: URL(string: "https://controlplane.example.com")!,
    endpointID: "env_demo"
  )
)

let client = try await Flowersec.connect(
  artifact,
  options: ConnectOptions(origin: "https://app.example.com")
)
```

## Rust artifact-first example

```rust
use flowersec::{ConnectOptions, connect};
use flowersec::controlplane::client::{
    ConnectArtifactRequestConfig,
    request_connect_artifact,
};

let mut request = ConnectArtifactRequestConfig::new("env_demo");
request.base_url = "https://controlplane.example.com".to_owned();
let artifact = request_connect_artifact(request).await?;
let client = connect(artifact, ConnectOptions::default()).await?;
```

## Reconnect guidance

For reconnect flows in every SDK:

- use `createBrowserReconnectConfig(...)` or `createNodeReconnectConfig(...)`
- supply a discriminated `source`: `{kind: "once", artifact}` or `{kind: "refreshable", acquire}`
- prefer `createControlplaneArtifactSource(...)` for automatic reconnect
- let the adapter carry forward `trace_id`, absorb the new `session_id`, and pass through cancellation `signal`

Swift uses `ArtifactSource` and `ReconnectManager`. Rust uses `reconnect::ArtifactSource` and `ReconnectManager`. Go uses `reconnect.Manager`. All four share the retry defaults in `stability/sdk_defaults.json` and stop retrying terminal validation/authentication failures.

Treat reconnect settings as validated input. Invalid attempt counts, delay values, factors, or jitter ratios fail configuration instead of being adjusted. On Go, always check `Manager.Disconnect()` so transport and supervisor cleanup failures are not lost.

A `once` source can be consumed once and cannot enable automatic reconnect. Flowersec v0.23 does not accept overlapping artifact, grant, or direct-info source fields.

## Transport security and liveness

High-level Go, TypeScript, Swift, and Rust connects require TLS by default. Use the loopback plaintext policy only for literal local development targets. Use unrestricted plaintext only when the caller explicitly accepts pre-E2EE metadata and credential exposure.

Use `ProbeLiveness`, `probeLiveness()`, or `probe_liveness()` for an acknowledged Yamux round trip. `Ping()` remains a local encrypted-record send operation where exposed. Automatic probes are disabled for direct connections by default and derived from the idle timeout for tunnel connections.

Do not push artifact/controlplane semantics down into the framework-agnostic reconnect core.

## Proxy/gateway guidance

Use preset manifests, not stable named profiles:

- gateway: `proxy.preset_file`
- TS helpers: `resolveProxyPreset(...)`

For browser runtime mode, prefer:

- `connectArtifactProxyBrowser(...)` for same-origin service-worker mode
- `connectArtifactProxyControllerBrowser(...)` plus `registerProxyAppWindow(...)` for controller-origin/runtime-isolation mode

Choose gateway mode only when you intentionally accept a trusted plaintext L7 relay. Runtime mode and gateway mode are different trust models, not interchangeable deployment skins.

For portable endpoint mode, Go uses `proxy.Register(...)`, TypeScript uses `serveProxySession(...)`, Swift uses `ProxyServer`, and Rust uses `proxy::ProxyServer`. These APIs implement the same HTTP/1 and WebSocket stream contract, fixed-upstream/SSRF policy, Origin handling, header/cookie isolation, and shared limits.

Reference first-party files live under `reference/presets/`.

## Migration notes

v0.23 preserves the v0.20-v0.22 hardening rules and adds the Go-reference star matrix:

- TLS is the default for all high-level connects
- WebSocket, Yamux, RPC, and tunnel queues are bounded
- liveness uses acknowledged Yamux PING frames
- reconnect accepts only a discriminated `ArtifactSource`
- old keepalive, WebSocket queue, Yamux third-party config, and reconnect-source fields are removed
- portable capability cells cannot be partial
- shared fixtures must be consumed by all four languages
- release tags for Go/TypeScript, SwiftPM, and Rust must point to one commit
- Go -> Go must pass before any non-Go result is attributed
- TypeScript, Swift, and Rust must each pass as both client and server against Go
- non-Go pairwise edges are intentionally absent; shared IDL, fixtures, defaults, and diagnostics remain normative

See `docs/V0_20_MIGRATION.md` for the v0.20 transport changes and `docs/V0_21_MIGRATION.md` for the compatibility cleanup.
