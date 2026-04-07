# Scoped Metadata

Flowersec v0.18.x stabilizes the `scoped` carrier on `ConnectArtifact`, while deliberately keeping resolver APIs and concrete scope semantics experimental.

## Stable carrier

Each scoped entry has:

- `scope`
- `scope_version`
- `critical`
- `payload`

Stable invariants:

- `scope` is a bounded, lowercase identifier
- `scope_version` is required at runtime
- `payload` must be a JSON object
- duplicate scope names are rejected
- entry count, payload size, and payload depth are bounded

## Critical semantics

`critical=true` means:

- if the local runtime does not understand or cannot validate the scope, connect must fail fast

`critical=false` means:

- missing resolver may be ignored
- malformed payload for a known optional scope is treated as validation failure by default
- relaxed optional validation must be an explicit opt-in
- ignored optional scopes emit warning diagnostics (`scope_ignored_missing_resolver` or `scope_ignored_relaxed_validation`)

## Stable vs experimental boundary

Stable in v0.18.x:

- `scoped` field on `ConnectArtifact`
- parser invariants
- critical fail-fast meaning

Experimental in v0.18.x:

- public resolver registration API
- normalize helper return types
- concrete scope payload schemas such as `proxy.runtime`
- bilateral negotiation semantics
- scope manifest toolchain

## Experimental source of truth

Current experimental scope metadata files live under:

- `stability/scopes/*.manifest.json`
- `tools/manifestgen/`

These files exist to keep scope evolution disciplined, but they are not a frozen public negotiation protocol in v0.18.x.
