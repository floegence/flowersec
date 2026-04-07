# Controlplane Artifact Fetch

Flowersec v0.18.x adds stable helper semantics for fetching a client-facing `ConnectArtifact` from a controlplane.

## Stable helper surface

TypeScript:

- `requestConnectArtifact(...)`
- `requestEntryConnectArtifact(...)`
- `ControlplaneRequestError`

Go:

- `client.RequestConnectArtifact(...)`
- `client.RequestEntryConnectArtifact(...)`
- `client.RequestError`

## Stable request semantics

Request body:

```json
{
  "endpoint_id": "env_demo",
  "payload": { "floe_app": "com.example.demo" },
  "correlation": {
    "trace_id": "trace-0001"
  }
}
```

Response body:

```json
{
  "connect_artifact": {
    "v": 1,
    "transport": "tunnel",
    "tunnel_grant": { "...": "ChannelInitGrant" }
  }
}
```

Error envelope:

```json
{
  "error": {
    "code": "forbidden",
    "message": "entry ticket is not valid for this endpoint"
  }
}
```

## Path handling

Helper defaults use first-party reference paths:

- `/v1/connect/artifact`
- `/v1/connect/artifact/entry`

Those default paths are helper defaults, not a globally frozen Flowersec core protocol requirement.
Third-party controlplanes may use different URLs and pass them via helper configuration.

## Reconnect guidance

Artifact-aware reconnect adapters should:

- carry forward the previous shared `trace_id`
- ingest a newly issued `session_id` from the fresh artifact

The reconnect core itself should remain transport/framework agnostic.
