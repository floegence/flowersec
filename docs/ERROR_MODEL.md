# Flowersec Error Model

Flowersec keeps machine-readable connection failures consistent across Go, TypeScript, Swift, and Rust.

For high-level connection APIs, always treat `{ path, stage, code }` as the primary machine-readable contract.

See also:

- API contract: `docs/API_CONTRACT.md`
- API change policy: `docs/API_CHANGE_POLICY.md`
- Contract manifest: `stability/api_contract_manifest.json`
- Error registry: `stability/connect_error_code_registry.json`
- Diagnostics registry: `stability/connect_diagnostics_code_registry.json`

## Connect error contract

High-level APIs surface:

- Go: `*fserrors.Error`
- TypeScript: `FlowersecError`
- Swift: `FlowersecError`
- Rust: `flowersec::FlowersecError`

Fields:

- `path`: top-level connect path (`auto`, `tunnel`, `direct`)
- `stage`: connect layer (`validate`, `connect`, `attach`, `handshake`, `secure`, `yamux`, `rpc`, `reconnect`, `close`)
- `code`: shared language-agnostic reason token

Human-readable detail belongs in the message and underlying cause.

The registry is shared, but protocol-generation meaning stays explicit. `yamux` is a Transport v1 stage and may describe the hop-local WebSocket mux inside a v2 WebSocket carrier; raw QUIC and WebTransport never report Yamux as their native stream layer. Transport v2 admission, candidate preparation, TLS/HTTP3 setup, native stream capacity, and session establishment map to the registered high-level stage/code pair without inventing carrier-specific product states.

Transport v2 candidate racing keeps the high-level failure singular while
retaining bounded candidate diagnostics:

- Go: `fserrors.Error.Diagnostics` contains `CandidateDiagnostic` values.
- TypeScript: `FlowersecError.diagnostics` contains
  `FlowersecCandidateDiagnostic` values.

Go diagnostics expose `CandidateID`, `Carrier`, `Stage`, `Code`, and `Err`;
TypeScript exposes `candidateId`, `carrier`, `stage`, `code`, and `message`.
Candidate diagnostics are
for one connection attempt only. Callers must not use candidate order or the
human-readable message to select a primary carrier, decide retryability, or
create unbounded metric labels. The top-level registered `{ path, stage, code
}` remains the retry and product-state contract.

## Error codes

The machine-readable source of truth is `stability/connect_error_code_registry.json`.

Each registry entry lists the stages where that code is valid. SDK mapping tests require every stable stage/code pair they expose to be a member of that set instead of collapsing a precise failure into a generic WebSocket, handshake, or RPC label. A language does not need to emit server-only or platform-specific pairs that do not apply to it. Swift's `FlowersecCode` cases are required to equal the full registry code set; the other SDKs consume the same registry through contract tests.

Common codes include:

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
  - `transport_policy_denied`
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
  - `credential_commit_failed`
  - `open_stream_failed`
  - `accept_stream_failed`
  - `mux_failed`
  - `stream_hello_failed`
  - `rpc_failed`
  - `missing_stream_kind`
  - `missing_handler`
  - `ping_failed`
  - `rekey_failed`
  - `not_connected`
  - `resource_exhausted`

`resource_exhausted` means a configured generic transport, secure-channel, multiplexing, RPC, or queue limit was reached. Callers should apply backpressure, reduce concurrency, or reconnect with a fresh session as appropriate. It must not be used to encode an application-specific quota or policy. Transport implementations map their limit failures to the nearest high-level stage, such as `connect`, `secure`, `yamux`, `rpc`, or `close`.

Transport v1 Yamux liveness probes use `yamux/timeout` when the configured ping deadline expires. Other ping or transport failures remain `ping_failed`, while caller cancellation remains `canceled`. A timed-out automatic probe also emits the low-cardinality `liveness_timeout` diagnostic event before the session terminates. Transport v2 session liveness is carrier-neutral and must not be reported as Yamux for raw QUIC or WebTransport.

The browser proxy runtime maps a full HTTP stream-admission queue to HTTP `503`. Its error message retains the shared `resource_exhausted` code; the Service Worker bridge wire is otherwise unchanged.

## Reconnect terminal classification

The exact non-retryable connection code set is the `reconnect_terminal_codes` array in `stability/connect_error_code_registry.json`. It currently contains:

- `invalid_input`
- `invalid_option`
- `role_mismatch`
- `transport_policy_denied`
- `invalid_psk`
- `invalid_suite`
- `missing_grant`
- `missing_connect_info`
- `missing_tunnel_url`
- `missing_ws_url`
- `missing_channel_id`
- `missing_token`
- `missing_init_exp`

Explicit cancellation is also terminal. Other connection failures remain retryable when automatic reconnect is enabled. After an established session terminates unexpectedly, reconnect waits the configured first backoff interval, including jitter, before acquiring a fresh artifact and dialing again. Disconnecting during that wait cancels it immediately.

## Controlplane helper contract

Artifact-fetch helpers use a separate, minimal contract:

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

Swift:

- `ControlplaneRequestError`
  - `status`
  - `code`
  - `message`
  - `responseBody`

Rust:

- `controlplane::client::RequestError`
  - `status`
  - `code`
  - `message`
  - `response_body`

Important separation:

- connect errors describe the encrypted connection attempt
- controlplane helper errors describe the HTTP contract used to fetch a `ConnectArtifact`

## Diagnostics split

Flowersec also defines a shared runtime event contract:

- `DiagnosticEvent`

In addition to the existing fields, a resource-related event may contain:

- `resource`: a low-cardinality generic resource name
- `current`: the observed count or byte total
- `limit`: the configured limit

These fields must not contain URL queries, credentials, tokens, stream kinds, RPC type IDs, or application payload data.

Important separation:

- correlation metadata belongs to the connect artifact
- `DiagnosticEvent` is runtime observability
- `code_domain=error` reuses `stability/connect_error_code_registry.json`
- `code_domain=event` uses `stability/connect_diagnostics_code_registry.json`

Current event codes include:

- `connect_ok`
- `attach_ok`
- `handshake_ok`
- `plaintext_transport`
- `scope_ignored_missing_resolver`
- `scope_ignored_relaxed_validation`
- `ws_close_local`
- `ws_close_peer_or_error`
- `ws_error`
- `diagnostics_overflow`
- `liveness_timeout`
- `queue_pressure`
- `stream_rejected`
- `resource_limit_reached`

The four liveness/resource names above use `code_domain=event`. A failed operation that reaches a configured limit uses the error-domain code `resource_exhausted` instead.

## Interoperability diagnostic evidence

The seven-cell Go-reference matrix described here is Transport v1. It records an ordered diagnostic evidence list for each transport/suite variant. Every entry includes `case`, `path`, `stage`, and `code`. `path` must equal the active `direct` or `tunnel` variant, and the ordered case list is fixed by `testdata/interop/v1/profiles.json`.

Resource-boundary evidence uses the registered error-domain tuple `yamux/resource_exhausted` or `rpc/resource_exhausted`. The proxy body action additionally verifies the protocol-specific remote code `request_body_too_large`, but the matrix tuple remains `rpc/resource_exhausted` so all four SDKs use the same shared registry domain.

Transport v2 uses `testdata/transport_v2/case_registry.json`, `performance_manifest.json`, shared wire vectors, candidate diagnostics, and signed release evidence. Local v2 smoke output is not part of the v1 seven-cell claim and cannot be presented as production real-browser, qlog, weak-network, migration, or performance evidence.

## Observability guidance

For logs and metrics, prefer aggregating by:

- connect failures: `path + stage + code`
- controlplane HTTP failures: `status + error.code`
- runtime events: `namespace + stage + code + result`

This keeps dashboards consistent across all four languages and across internal refactors.
