# Connect Artifacts (Transport v1)

Transport v1 uses one canonical client-facing connect artifact: `ConnectArtifact`.

It is the required input for Go `client.Connect(...)` and the TypeScript `connect(...)`, `connectBrowser(...)`, and `connectNode(...)` entrypoints. It is also the integration shape for controlplanes, reconnect adapters, and CLI or demo minting flows.

## Transport v2 boundary

Transport v2 does not extend or reinterpret this envelope. It uses the separate `ArtifactV2` contract, exact signed carrier candidate tuples, a runtime capability descriptor and digest, and a durable single-use `ArtifactLeaseV2`/`ArtifactLease` spend callback. Candidate setup may race only before credential bytes are written; the winner durably commits spend before the first FSB2 byte.

A v1 `ConnectArtifact`, grant, reconnect source, or stored credential cannot be cast to `ArtifactV2`, retried as v2, or used as fallback after a v2 commitment. Controlplanes must keep v1/v2 issuance, storage, replay state, endpoints, and rollback policy isolated. See `docs/MIGRATION_TRANSPORT_V2.md`, `docs/TRANSPORT_V2_ARCHITECTURE.md`, and `stability/transport_v2_contract.json`.

## Why it exists

`ConnectArtifact` gives Flowersec one canonical client-side connect envelope and one place for:

- transport selection
- scoped metadata
- correlation metadata

## Shape

Two variants exist:

- tunnel artifact
- direct artifact

Top-level fields:

- `v: 1`
- `transport: "tunnel" | "direct"`
- exactly one of:
  - `tunnel_grant`
  - `direct_info`
- optional `scoped`
- optional `correlation`

## Strict parse rules

Parser rules:

- unknown artifact top-level fields are rejected
- `transport` is a closed enum
- tunnel artifacts must carry a client-role `ChannelInitGrant`
- `scoped[*].payload` must be a JSON object
- duplicate `scope` entries are rejected
- missing `correlation.tags` normalize to `[]`
- `correlation.tags` duplicate keys are rejected
- invalid shared `trace_id` / `session_id` are sanitized to absence

Embedded `ChannelInitGrant` / `DirectConnectInfo` keep additive unknown-field tolerance.

## `proxy.runtime`

`proxy.runtime` is the first frozen scoped payload carried by `ConnectArtifact`.

Helper-level contract:

- `scope = "proxy.runtime"`
- `scope_version = 1`
- `mode = "service_worker" | "controller_bridge"`

Recommended helper entrypoints:

- `connectArtifactProxyBrowser(...)`
- `connectArtifactProxyControllerBrowser(...)`

These helper entrypoints fail fast when `proxy.runtime@1` is missing, malformed, or uses an unsupported `scope_version`.

`proxy.runtime@1` does not carry every deployment hardening option.
Runtime `pathPolicy`, `runtimeRegistrationToken`, trusted `externalOrigin`, `maxConcurrentHttpStreams`, `maxQueuedHttpRequests`, `maxQueuedHttpBodyBytes`, `maxWsBufferedAmountBytes`, and controller/app bridge `capabilityNonce` are explicit helper/runtime options rather than `proxy.runtime@1` payload fields.
Do not expand the v1 schema to carry them; use explicit options, or introduce a future `proxy.runtime@2` when those fields need to become part of the artifact contract.

## Language-level exports

TypeScript:

- `ConnectArtifact`
- `CorrelationContext`
- `CorrelationKV`
- `TunnelClientConnectArtifact`
- `DirectClientConnectArtifact`
- `ScopeMetadataEntry`
- `assertConnectArtifact(...)`

Go:

- `protocolio.ConnectArtifact`
- `protocolio.TunnelClientConnectArtifact`
- `protocolio.DirectClientConnectArtifact`
- `protocolio.CorrelationContext`
- `protocolio.CorrelationKV`
- `protocolio.ScopeMetadataEntry`
- `protocolio.DecodeConnectArtifactJSON(...)`

## Examples

Tunnel artifact:

```json
{
  "v": 1,
  "transport": "tunnel",
  "tunnel_grant": { "...": "ChannelInitGrant" },
  "correlation": {
    "v": 1,
    "trace_id": "trace-0001",
    "session_id": "session-0001",
    "tags": [{ "key": "tenant", "value": "acme" }]
  }
}
```

Direct artifact:

```json
{
  "v": 1,
  "transport": "direct",
  "direct_info": { "...": "DirectConnectInfo" }
}
```

## Recommended usage

TypeScript:

```ts
import { connect } from "@floegence/flowersec-core";
import { requestConnectArtifact } from "@floegence/flowersec-core/controlplane";

const artifact = await requestConnectArtifact({ endpointId: "demo" });
const client = await connect(artifact, { origin: "https://app.example" });
```

Go:

```go
artifact, err := protocolio.DecodeConnectArtifactJSON(r)
if err != nil {
	return err
}
client, err := client.Connect(ctx, artifact, client.WithOrigin(origin))
```

## Explicit transport entrypoints

Raw transport inputs are accepted only by explicit entrypoints:

- pass a `ChannelInitGrant` to `client.ConnectTunnel(...)`, `connectTunnel(...)`, `connectTunnelBrowser(...)`, or `connectTunnelNode(...)`
- pass a `DirectConnectInfo` to `client.ConnectDirect(...)`, `connectDirect(...)`, `connectDirectBrowser(...)`, or `connectDirectNode(...)`

Automatic `Connect` or `connect` entrypoints do not accept raw grants, wrapper objects, direct connection info, readers, byte slices, or serialized JSON. Decode and validate a `ConnectArtifact` before calling them.
