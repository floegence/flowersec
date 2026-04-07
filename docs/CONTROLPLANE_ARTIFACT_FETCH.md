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

Default artifact request:

```http
POST /v1/connect/artifact
Content-Type: application/json
```

Entry artifact request:

```http
POST /v1/connect/artifact/entry
Content-Type: application/json
Authorization: Bearer <entry-ticket>
```

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

The stable helper contract freezes the envelope semantics above:

- request fields: `endpoint_id`, optional `payload`, optional `correlation.trace_id`
- success field: `connect_artifact`
- error fields: machine-readable `error.code`, human-readable `error.message`

`session_id` is issuer-owned and is returned inside `connect_artifact.correlation` when available; callers do not request it explicitly.

## Stable helper error surfaces

TypeScript `ControlplaneRequestError` preserves:

- `status`
- `code`
- `responseBody`

Go `client.RequestError` preserves:

- `Status`
- `Code`
- `Message`
- `ResponseBody`

On non-`2xx` responses, helpers keep the HTTP status plus the structured error envelope when present.

## Path handling

Helper defaults use first-party reference paths:

- `/v1/connect/artifact`
- `/v1/connect/artifact/entry`

Those default paths are helper defaults, not a globally frozen Flowersec core protocol requirement.
Third-party controlplanes may use different URLs and pass them via helper configuration, as long as the request/response envelope semantics stay equivalent.

## Reconnect guidance

Artifact-aware reconnect adapters should:

- carry forward the previous shared `trace_id`
- ingest a newly issued `session_id` from the fresh artifact

The reconnect core itself should remain transport/framework agnostic.
