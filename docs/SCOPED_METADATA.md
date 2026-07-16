# Scoped Metadata

Flowersec defines the `scoped` carrier on `ConnectArtifact` and freezes one concrete scope payload: `proxy.runtime@1` for the proxy helper entrypoints.

## Carrier

Each scoped entry has:

- `scope`
- `scope_version`
- `critical`
- `payload`

Invariants:

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

The proxy helper entrypoints do not opt into relaxed downgrade behavior for `proxy.runtime`.
If `connectArtifactProxyBrowser(...)` or `connectArtifactProxyControllerBrowser(...)` sees an invalid `proxy.runtime@1` payload, it fails fast regardless of `critical`.

Swift artifact scope validation aligns with Go and TypeScript. Register asynchronous validators by exact scope name through `ConnectOptions.scopeResolvers`. Resolver execution completes before transport policy evaluation or any network activity.

All SDKs apply the same behavior:

- missing critical resolver: fail with `resolve_failed`
- missing optional resolver: continue and emit `scope_ignored_missing_resolver`
- registered resolver failure: fail with `resolve_failed` by default
- registered optional resolver failure with explicit relaxed validation: continue and emit `scope_ignored_relaxed_validation`
- registered critical resolver failure: always fail, including when relaxed optional validation is enabled

Swift enables the explicit optional-scope downgrade with `ConnectOptions.relaxedOptionalScopeValidation`. The option does not affect scopes without a resolver and never exposes resolver errors or payload values in diagnostics.

## `proxy.runtime@1`

Frozen scope name and version:

- `scope = "proxy.runtime"`
- `scope_version = 1`

The helper contract uses only the outer `scope_version`.
There is no second payload-internal version field.

Modes:

- `mode = "service_worker"`
- `mode = "controller_bridge"`

Shared fields:

- `preset`
- optional `limits`
- optional `appBasePath`

Mode-specific fields:

- `service_worker`
  - `serviceWorker.scriptUrl`
  - `serviceWorker.scope`
- `controller_bridge`
  - `controllerBridge.allowedOrigins`

Important boundary:

- `allowedOrigins` is the frozen controller-bridge security input
- deployment-specific path details remain caller-owned configuration, not scope fields
- `pathPolicy`, `runtimeRegistrationToken`, trusted `externalOrigin` overrides, `maxConcurrentHttpStreams`, `maxQueuedHttpRequests`, `maxQueuedHttpBodyBytes`, `maxWsBufferedAmountBytes`, and bridge `capabilityNonce` are explicit runtime/bootstrap options, not `proxy.runtime@1` payload fields
- do not expand the `proxy.runtime@1` schema for deployment hardening switches; use explicit helper options, or introduce a future `proxy.runtime@2` with a reviewed manifest if the artifact contract needs new fields

## Scope contract

The public scope contract includes:

- the `scoped` field on `ConnectArtifact`
- parser invariants and critical fail-fast behavior
- `proxy.runtime@1` when consumed through proxy helper entrypoints
- public scope resolver registration and optional-scope validation
- exported normalization helpers and generic `connect(...)` scope resolution

Any public change to these APIs follows `docs/API_CHANGE_POLICY.md`.

## Source-of-truth files

- `stability/scopes/proxy.runtime.manifest.json`
- `stability/scopes/*.manifest.json`
- `tools/manifestgen/`

These files exist to keep scope evolution disciplined.
The frozen `proxy.runtime@1` manifest defines the proxy-helper payload contract.
