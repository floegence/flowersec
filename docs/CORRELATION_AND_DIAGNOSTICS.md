# Correlation And Diagnostics

Flowersec v0.19.x keeps two stable concepts separate:

- connect artifact correlation metadata
- runtime diagnostics events

## CorrelationContext

`CorrelationContext` lives on the connect artifact.

Purpose:

- carry shared trace/session hints across controlplane, connect entrypoints, and reconnect adapters
- stay data-only and parser-validated

Stable fields:

- `v: 1`
- optional `trace_id`
- optional `session_id`
- `tags`

Rules:

- invalid shared IDs become absent
- missing `tags` normalize to `[]`
- duplicate tag keys are rejected
- tags are bounded and meant for small observability hints, not business payloads

## DiagnosticEvent

`DiagnosticEvent` is the stable runtime observability contract.

Stable fields:

- `v`
- `namespace`
- `path`
- `stage`
- `code_domain`
- `code`
- `result`
- `elapsed_ms`
- `attempt_seq`
- optional `trace_id`
- optional `session_id`

## Timing semantics

`elapsed_ms` means:

- monotonic milliseconds since the current connect attempt start
- reconnect starts a new attempt clock

`attempt_seq` means:

- local attempt grouping only
- starts at `1`
- increments per reconnect attempt

## Delivery contract

Observer delivery is best-effort and must not affect connect success semantics.

Stable guarantees:

- asynchronous delivery
- per-connection FIFO queueing
- bounded queue
- overflow generates `diagnostics_overflow`
- terminal failure diagnostics are allowed to displace non-terminal events when needed

Non-guarantees:

- user callback throw/panic must not fail the connect
- pending diagnostics are not part of the success return contract

## Registry sources

- error-domain codes: `stability/connect_error_code_registry.json`
- event-domain codes: `stability/connect_diagnostics_code_registry.json`

Notable scope warning events:

- `scope_ignored_missing_resolver`
- `scope_ignored_relaxed_validation`

## Where propagation belongs

Artifact-aware adapters may propagate:

- prior `trace_id`
- newly issued `session_id`
- cancellation via `signal` during artifact refresh

Framework-agnostic reconnect core should remain unaware of artifact/controlplane specifics.

`requestConnectArtifact(...)`, `requestEntryConnectArtifact(...)`, `createBrowserReconnectConfig(...)`, and `createNodeReconnectConfig(...)` should preserve this boundary instead of inventing a second correlation contract.
