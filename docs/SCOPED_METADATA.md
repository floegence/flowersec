# Scoped Metadata

Flowersec v0.19.x stabilizes the `scoped` carrier on `ConnectArtifact` and freezes one concrete scope payload: `proxy.runtime@1` for the stable proxy helper entrypoints.

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

The stable proxy helper entrypoints do not opt into relaxed downgrade behavior for `proxy.runtime`.
If `connectArtifactProxyBrowser(...)` or `connectArtifactProxyControllerBrowser(...)` sees an invalid `proxy.runtime@1` payload, it fails fast regardless of `critical`.

## `proxy.runtime@1`

Frozen scope name and version:

- `scope = "proxy.runtime"`
- `scope_version = 1`

The stable helper contract uses only the outer `scope_version`.
There is no second payload-internal version field.

Stable modes:

- `mode = "service_worker"`
- `mode = "controller_bridge"`

Stable shared fields:

- `preset`
- optional `limits`
- optional `appBasePath`

Stable mode-specific fields:

- `service_worker`
  - `serviceWorker.scriptUrl`
  - `serviceWorker.scope`
- `controller_bridge`
  - `controllerBridge.allowedOrigins`

Important boundary:

- `allowedOrigins` is the frozen controller-bridge security input
- deployment-specific path details remain caller-owned configuration, not stable scope fields

## Stable vs experimental boundary

Stable in v0.19.x:

- `scoped` field on `ConnectArtifact`
- parser invariants
- critical fail-fast meaning
- `proxy.runtime@1` when consumed through the stable proxy helper entrypoints

Experimental in v0.19.x:

- public resolver registration API
- normalize helper return types
- generic `connect(...)` scope negotiation semantics
- scope manifest toolchain outside the frozen `proxy.runtime` v1 manifest

## Source-of-truth files

Stable:

- `stability/scopes/proxy.runtime.manifest.json`

Experimental:

- `stability/scopes/*.manifest.json`
- `tools/manifestgen/`

These files exist to keep scope evolution disciplined.
Only the frozen `proxy.runtime@1` manifest is part of the stable proxy-helper contract in v0.19.x.
