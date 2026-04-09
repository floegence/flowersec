# Flowersec Error Model

Flowersec keeps machine-readable connection failures stable across Go and TypeScript.

For high-level connection APIs, always treat `{ path, stage, code }` as the primary machine-readable contract.

See also:

- Stable API list: `docs/API_SURFACE.md`
- Stability policy: `docs/API_STABILITY_POLICY.md`
- Canonical manifest: `stability/public_api_manifest.json`
- Error registry: `stability/connect_error_code_registry.json`
- Diagnostics registry: `stability/connect_diagnostics_code_registry.json`

## Stable connect error contract

High-level APIs surface:

- Go: `*fserrors.Error`
- TypeScript: `FlowersecError`

Stable fields:

- `path`: top-level connect path (`auto`, `tunnel`, `direct`)
- `stage`: connect layer (`validate`, `connect`, `attach`, `handshake`, `secure`, `yamux`, `rpc`, `close`)
- `code`: stable language-agnostic reason token

Human-readable detail belongs in the message and underlying cause.

## Stable codes

The machine-readable source of truth is `stability/connect_error_code_registry.json`.

Common stable codes include:

- validation/configuration:
  - `invalid_input`
  - `invalid_option`
  - `missing_grant`
  - `missing_connect_info`
  - `missing_conn`
  - `role_mismatch`
  - `missing_tunnel_url`
  - `missing_ws_url`
  - `missing_origin`
  - `missing_channel_id`
  - `missing_token`
  - `missing_init_exp`
  - `invalid_psk`
  - `invalid_suite`
  - `invalid_version`
  - `invalid_endpoint_instance_id`
  - `resolve_failed`
  - `random_failed`
- connect/attach:
  - `dial_failed`
  - `attach_failed`
  - `upgrade_failed`
  - `too_many_connections`
  - `expected_attach`
  - `invalid_attach`
  - `invalid_token`
  - `channel_mismatch`
  - `init_exp_mismatch`
  - `idle_timeout_mismatch`
  - `token_replay`
  - `tenant_mismatch`
  - `policy_denied`
  - `policy_error`
  - `replace_rate_limited`
  - `timeout`
  - `canceled`
- handshake/runtime:
  - `handshake_failed`
  - `timestamp_after_init_exp`
  - `timestamp_out_of_skew`
  - `auth_tag_mismatch`
  - `open_stream_failed`
  - `accept_stream_failed`
  - `mux_failed`
  - `stream_hello_failed`
  - `rpc_failed`
  - `missing_stream_kind`
  - `missing_handler`
  - `ping_failed`
  - `not_connected`

## Stable controlplane helper contract

Artifact-fetch helpers use a separate, minimal stable contract:

- success: `{ "connect_artifact": ... }`
- failure: `{ "error": { "code": string, "message": string } }`

TypeScript:

- `ControlplaneRequestError`
  - `status`
  - `code`
  - `responseBody`

Go client:

- `client.RequestError`
  - `Status`
  - `Code`
  - `Message`
  - `ResponseBody`

Go server helper:

- `controlplanehttp.RequestError`
  - `Status`
  - `Code`
  - `Message`
  - `Cause`

Important separation:

- connect errors describe the encrypted connection attempt
- controlplane helper errors describe the HTTP contract used to fetch a `ConnectArtifact`

## Diagnostics split

Flowersec v0.19.x also defines a stable runtime event contract:

- `DiagnosticEvent`

Important separation:

- correlation metadata belongs to the connect artifact
- `DiagnosticEvent` is runtime observability
- `code_domain=error` reuses `stability/connect_error_code_registry.json`
- `code_domain=event` uses `stability/connect_diagnostics_code_registry.json`

Current stable event codes include:

- `connect_ok`
- `attach_ok`
- `handshake_ok`
- `scope_ignored_missing_resolver`
- `scope_ignored_relaxed_validation`
- `ws_close_local`
- `ws_close_peer_or_error`
- `ws_error`
- `diagnostics_overflow`

## Observability guidance

For logs and metrics, prefer aggregating by:

- connect failures: `path + stage + code`
- controlplane HTTP failures: `status + error.code`
- runtime events: `namespace + stage + code + result`

This keeps dashboards stable across both languages and across internal refactors.
