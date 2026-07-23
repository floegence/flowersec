# Controlplane Artifact Fetch (Transport v1)

Transport v1 uses the client-facing contract below for fetching a `ConnectArtifact` from a controlplane.

## Transport v2 boundary

The `/v1/connect/artifact` envelope and its helpers do not issue or decode `ArtifactV2`. Transport v2 acquisition is downstream-owned and supplies an `ArtifactSourceV2`/durable lease containing an exact capability intersection, capability digest, bounded session contract, candidates, and single-use spend callback. The fetch receives the SDK-produced runtime capability descriptor; the controlplane must not reconstruct or broaden it.

Keep v1 and v2 paths, stored credentials, pending/spent state, replay keys, and rollback policy isolated. Never cast `connect_artifact` to `ArtifactV2`, reuse a v1 helper as an implicit fallback, or recycle a serialized one-time v2 artifact for reconnect. See `docs/MIGRATION_TRANSPORT_V2.md` for the application-owned v2 controlplane sequence.

## Helper surface

TypeScript:

- `@floegence/flowersec-core/controlplane`
  - `requestConnectArtifact(...)`
  - `requestEntryConnectArtifact(...)`
  - `ControlplaneRequestError`
  - `DEFAULT_CONNECT_ARTIFACT_PATH`
  - `DEFAULT_ENTRY_CONNECT_ARTIFACT_PATH`

Browser and Node code import artifact-fetch helpers from `@floegence/flowersec-core/controlplane`.

Go:

- `client.RequestConnectArtifact(...)`
- `client.RequestEntryConnectArtifact(...)`
- `client.RequestError`
- `controlplanehttp.NewArtifactHandler(...)`
- `controlplanehttp.NewEntryArtifactHandler(...)`

## Request semantics

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

The helper contract defines the envelope semantics above:

- request fields: `endpoint_id`, optional `payload`, optional `correlation.trace_id`
- success field: `connect_artifact`
- error fields: machine-readable `error.code`, human-readable `error.message`
- bounded-body rule: helpers treat the response as a small controlplane document and reject bodies larger than 1 MiB before JSON validation
- JSON response headers: artifact and error envelopes should be served with `Content-Type: application/json` and `Cache-Control: no-store, no-cache, must-revalidate, private`

`session_id` is issuer-owned and is returned inside `connect_artifact.correlation` when available; callers do not request it explicitly.

This helper surface is intentionally for controlplane bootstrap documents, not for arbitrary bulk payload delivery. If an integration needs large payloads, it should expose a different application-owned endpoint instead of stretching the artifact-fetch contract.

## Helper error surfaces

TypeScript `ControlplaneRequestError` preserves:

- `status`
- `code`
- `responseBody`

Go `client.RequestError` preserves:

- `Status`
- `Code`
- `Message`
- `ResponseBody`

Go `controlplane/http` keeps the same outward envelope while letting applications own auth, audit, and policy:

- `controlplanehttp.DecodeArtifactRequest(...)`
- `controlplanehttp.WriteArtifactEnvelope(...)`
- `controlplanehttp.WriteErrorEnvelope(...)`
- `controlplanehttp.ArtifactRequestMetadata`
- `controlplanehttp.ArtifactIssueInput`

The `controlplane/http` writer helpers set JSON/no-store headers for both success and error envelopes.
Custom controlplanes that write envelopes manually should do the same so one-time grants, scoped runtime metadata, and structured error bodies are not persisted by browsers, shared proxies, or framework caches.

On non-`2xx` responses, helpers keep the HTTP status plus the structured error envelope when present.
If a response body exceeds the helper limit, the helper fails closed before envelope parsing; non-`2xx` paths still preserve the HTTP status through `ControlplaneRequestError`.

Manual callers that fetch the controlplane endpoint directly must unwrap `connect_artifact` before passing it into client connect helpers.

TypeScript example:

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
```

## Path handling

Helper defaults use first-party reference paths:

- `/v1/connect/artifact`
- `/v1/connect/artifact/entry`

Those default paths are helper defaults, not a globally frozen Flowersec core protocol requirement.
Third-party controlplanes may use different URLs and pass them via helper configuration, as long as the request/response envelope semantics stay equivalent.

`path` is an advanced override.
Quickstart and recommended integrations should treat the default endpoints above as the default baseline.

## Ownership boundary

The artifact-fetch helper contract is intentionally narrow:

- helper-owned concerns: request envelope shape, response envelope shape, bounded response parsing, and client-side validation of `connect_artifact`
- application-owned concerns: auth, same-origin binding, replay policy, ticket semantics, auditing, and endpoint routing

`controlplane/http` is a reference envelope layer, not a complete policy framework. Browser deployments that treat artifact fetch as a privileged bootstrap step must still enforce their own same-origin or equivalent boundary at the application layer.

## Request / response sequence

Success path:

1. Caller issues `requestConnectArtifact(...)` or `requestEntryConnectArtifact(...)`.
2. Helper sends the POST request to the configured controlplane path.
3. Helper reads the response through the bounded 1 MiB reader.
4. Helper parses the JSON envelope and validates `connect_artifact`.
5. Caller receives the validated artifact.

Error path:

1. Caller issues the same helper request.
2. Controlplane returns a non-`2xx` response.
3. Helper reads the body through the same bounded reader.
4. Helper preserves the HTTP status and decodes the structured `error` envelope when present.
5. Caller receives `ControlplaneRequestError`.

The artifact-fetch contract is independent from whether the later proxy data-plane runs in runtime mode or gateway mode. See `docs/PROXY.md` for those trust boundaries.

## Reconnect guidance

Artifact-aware reconnect adapters should:

- carry forward the previous shared `trace_id`
- ingest a newly issued `session_id` from the fresh artifact
- forward `signal` so canceled reconnect attempts also cancel artifact fetch/refresh
- use a `refreshable` `ArtifactSource` when automatic reconnect is enabled

A `once` source is consumed at most once and cannot enable automatic reconnect. `createControlplaneArtifactSource(...)` returns a refreshable source.

The reconnect core itself should remain transport/framework agnostic.
