# Flowersec Error Model

Flowersec aims to make errors easy to handle programmatically and consistent across languages.
Both the Go and TypeScript high-level APIs surface a structured error with three stable fields:

- `path`: which top-level connect path failed (`auto`, `tunnel`, `direct`)
- `stage`: which layer failed (`validate`, `connect`, `attach`, `handshake`, `secure`, `yamux`, `rpc`, `close`)
- `code`: a stable, language-agnostic error identifier (see below)

Always treat `{path, stage, code}` as the primary machine-readable signal.
Human-readable details live in the error message and the underlying `cause`.

## Go

High-level APIs return `*fserrors.Error` (or an alias like `*client.Error` / `*endpoint.Error`).

```go
var fe *fserrors.Error
if errors.As(err, &fe) {
  // fe.Path, fe.Stage, fe.Code are stable.
  // fe.Err is the underlying cause.
}
```

## TypeScript

High-level APIs throw `FlowersecError`.

```ts
try {
  await connectTunnelNode(input, { origin });
} catch (e) {
  if (e instanceof FlowersecError) {
    // e.path, e.stage, e.code are stable.
    // e.cause carries the underlying error.
  }
}
```

## Stable Codes

The following `code` values are intended to be stable across Go and TypeScript:

Validation:

- `invalid_input`
- `invalid_option`
- `missing_grant`, `missing_connect_info`
- `missing_tunnel_url`, `missing_ws_url`
- `missing_origin`, `missing_channel_id`, `missing_token`, `missing_init_exp`
- `invalid_psk`, `invalid_suite`, `invalid_version`, `invalid_endpoint_instance_id`

Connect / attach:

- `dial_failed`, `attach_failed`
- `timeout`, `canceled`

Handshake:

- `handshake_failed`
- `timestamp_out_of_skew`, `timestamp_after_init_exp`
- `auth_tag_mismatch`
- `timeout`, `canceled`

Runtime:

- `open_stream_failed`, `accept_stream_failed`, `mux_failed`
- `stream_hello_failed`, `missing_stream_kind`, `missing_handler`
- `ping_failed`, `not_connected`

Notes:

- `dial_failed` / `attach_failed` are intentionally broad. Transport-specific detail belongs in the `cause` (and, in TypeScript, in the optional observer callbacks).
- You should expect new codes to be added over time as the protocol surface grows, but existing codes should keep their meaning.

## Observability Recommendation

For logs and metrics, prefer aggregating by:

- `path + stage + code`

This yields stable dashboards and alerts across both languages and across future internal refactors.

