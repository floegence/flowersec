# Connect Artifacts

Flowersec v0.18.x introduces a stable client-facing canonical connect artifact: `ConnectArtifact`.

It is the recommended integration shape for new controlplanes, browser helpers, Node helpers, and CLI/demo minting flows.

## Why it exists

`ConnectArtifact` gives Flowersec one canonical client-side connect envelope while still preserving older compatibility edges:

- raw `ChannelInitGrant`
- wrapper `{grant_client: ...}`
- raw `DirectConnectInfo`

The artifact keeps those legacy inputs available, but gives new integrations one stable place for:

- transport selection
- scoped metadata
- correlation metadata

## Stable shape

Two stable variants exist:

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

Stable parser rules:

- unknown artifact top-level fields are rejected
- `transport` is a closed enum
- tunnel artifacts must carry a client-role `ChannelInitGrant`
- `scoped[*].payload` must be a JSON object
- duplicate `scope` entries are rejected
- missing `correlation.tags` normalize to `[]`
- `correlation.tags` duplicate keys are rejected
- invalid shared `trace_id` / `session_id` are sanitized to absence

Embedded `ChannelInitGrant` / `DirectConnectInfo` keep additive unknown-field tolerance.

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

## Stable language-level exports

TypeScript:

- `ConnectArtifact`
- `CorrelationContext`
- `CorrelationKV`
- `ScopeMetadataEntry`
- `assertConnectArtifact(...)`

Go:

- `protocolio.ConnectArtifact`
- `protocolio.CorrelationContext`
- `protocolio.CorrelationKV`
- `protocolio.ScopeMetadataEntry`
- `protocolio.DecodeConnectArtifactJSON(...)`

## Recommended usage

TypeScript:

```ts
import { connect } from "@floegence/flowersec-core";
import { requestConnectArtifact } from "@floegence/flowersec-core/browser";

const artifact = await requestConnectArtifact({ endpointId: "demo" });
const client = await connect(artifact, {});
```

Go:

```go
artifact, err := protocolio.DecodeConnectArtifactJSON(r)
if err != nil {
	return err
}
client, err := client.Connect(ctx, artifact, client.WithOrigin(origin))
```

## Compatibility notes

Flowersec still accepts legacy raw inputs, but v0.18.x now rejects:

- hybrid ambiguous objects
- legacy objects mixed with artifact-only fields
- client-facing `grant_server` / server-role inputs
- `token` / `role` heuristics as auto-detect shortcuts

See `docs/V0_18_MIGRATION.md` for the exact migration guidance.
