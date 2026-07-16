# Flowersec API Stability Policy

This document describes how Flowersec classifies public APIs and how that classification maps to engineering gates.

See also:

- Stable API list: `docs/API_SURFACE.md`
- Canonical manifest: `stability/public_api_manifest.json`
- Error contract: `docs/ERROR_MODEL.md`

## Stability levels

### Stable

Stable APIs are the supported integration entrypoints listed in `docs/API_SURFACE.md` and tracked in `stability/public_api_manifest.json`.

Stable means:

- the symbol/export is intentionally supported for downstream integrations
- docs, package exports, parser fixtures, and machine-readable registries must stay aligned
- breaking changes require an explicit compatibility review
- CI must keep stability and coverage gates green

### Experimental

Experimental APIs may ship in the repository, but they are not covered by the same compatibility commitment as the stable surface.

In v0.20.x this explicitly includes:

- public normalize helper shapes
- public scope resolver registration model
- scoped manifest toolchain/codegen factory outside the frozen `proxy.runtime@1` helper contract
- bilateral scope negotiation semantics
- direct-transport proxy helper expansion beyond the documented browser/runtime path

### Internal

Internal APIs are implementation details and are not part of the public contract.

## Source of truth

Stable source-of-truth artifacts:

- `stability/public_api_manifest.json`
- `stability/language_capabilities.json`
- `stability/sdk_defaults.json`
- `stability/connect_artifact.schema.json`
- `stability/connect_error_code_registry.json`
- `stability/connect_diagnostics_code_registry.json`
- `stability/proxy_preset_manifest.schema.json`
- `stability/scopes/proxy.runtime.manifest.json`

Experimental source-of-truth artifacts:

- `stability/scopes/*.manifest.json` except the frozen `proxy.runtime` v1 manifest above
- `tools/manifestgen/`

The stable manifest drives:

- Go stable symbol compilation checks
- TypeScript tarball export checks
- `docs/API_SURFACE.md` token coverage checks
- coverage thresholds for key packages/modules

The language capability manifest is stricter than a package inventory: every portable capability must be `complete` for Go, TypeScript, Swift, and Rust, with implementation/test evidence. Shared fixtures must list a consumer in every language. Runtime-specific capabilities must name one owner and explain why duplication would be inappropriate.

## Compatibility rules

### Go

The stable Go surface is the package/type/function set listed in `docs/API_SURFACE.md` and encoded in the manifest.

Breaking changes to stable Go APIs require:

- explicit API review
- docs updates
- stability checks passing
- updated interop/parser fixtures when wire-facing JSON contracts change

`github.com/floegence/flowersec/flowersec-go/controlplane/http` is intentionally helper-first:

- stable: request/response contract, decode/write helpers, optional handler assembly points
- not stable: application-specific policy inside `ExtractMetadata`, `ValidateRequest`, or `IssueArtifact`

### TypeScript

The stable TypeScript surface is the root package plus documented subpath exports listed in `docs/API_SURFACE.md` and encoded in the manifest.

Breaking changes to stable TypeScript APIs require:

- explicit API review
- docs updates
- packed tarball export verification
- stable browser/node wrapper paths staying green

`@floegence/flowersec-core/controlplane` is the canonical stable artifact-fetch entry for new TypeScript code.
Browser re-exports of `requestConnectArtifact(...)`, `requestEntryConnectArtifact(...)`, and `ControlplaneRequestError` remain stable aliases during the compatibility window, but they do not replace the canonical controlplane import in docs or quickstarts.

### Swift

The stable Swift surface is the `Flowersec` product and its symbol graph recorded in `stability/public_api_manifest.json`. Client, endpoint, RPC server, controlplane, reconnect, and proxy APIs are portable capabilities. Swift-specific framework adapters may evolve without weakening the shared wire and behavior contract.

### Rust

The stable Rust surface is the `flowersec` crate with MSRV 1.85. Public entrypoints are compile-probed, release tags run `cargo-semver-checks` against the previous Rust release, and Flowersec-authored Rust code forbids `unsafe`. Browser WASM and deployable service binaries are not part of the Rust v0.23 target.

### Scoped metadata and proxy runtime

Stable in v0.20.x:

- the `scoped` carrier on `ConnectArtifact`
- critical fail-fast meaning
- `proxy.runtime@1` when consumed by the stable proxy helper entrypoints

`proxy.runtime@1` is intentionally frozen narrowly.
Deployment hardening controls such as runtime path policy, runtime registration tokens, trusted external-origin overrides, and bridge capability nonces belong to explicit helper/runtime options in v0.20.x.
They must not be added to the v1 scope payload or manifest as an in-place extension; artifact-carried versions require a future reviewed scope version such as `proxy.runtime@2`.

Experimental in v0.20.x:

- public resolver registration APIs used by generic `connect(...)`
- relaxed negotiation / dual-read stories across future scope versions
- ad hoc scope manifests that are not explicitly listed as stable

### Error and diagnostics contract

For high-level connection APIs, the stable machine-readable contracts are:

- connect result: `{ path, stage, code }`
- runtime diagnostics: `DiagnosticEvent`
- controlplane HTTP envelope: `{ connect_artifact }` on success and `{ error: { code, message } }` on failure

Registry sources:

- `stability/connect_error_code_registry.json`
- `stability/connect_diagnostics_code_registry.json`

## v0.23 compatibility posture

Flowersec v0.23 keeps wire compatibility for `ConnectArtifact v1`, encrypted records, Yamux, RPC, and proxy streams while requiring portable behavior parity across all four SDKs:

- high-level WebSocket connects default to TLS-only
- plaintext requires an explicit policy decision
- record, WebSocket, Yamux, RPC, and tunnel queues have stable bounded defaults
- liveness uses acknowledged Yamux PING round trips
- browser and Node reconnect adapters accept only a discriminated `ArtifactSource`
- client and endpoint rekey operations are stable in all four SDKs
- stable byte streams expose protocol reset in all four SDKs
- interoperability uses a Go-reference star: Go -> Go baseline, every non-Go SDK -> Go, and Go -> every non-Go SDK

The following compatibility edges remain intentionally supported:

- raw grant path
- wrapper path
- raw direct path
- `requestChannelGrant(...)` / `requestEntryChannelGrant(...)`
- existing proxy wire `timeout_ms` compatibility (`omit == 0 == server default`)
- browser stable aliases for the shared controlplane helpers while `@floegence/flowersec-core/controlplane` stays the preferred import

The removed keepalive and overlapping reconnect-source fields do not have a compatibility layer. See `docs/V0_20_MIGRATION.md`.

## Review checklist

Any change that touches a stable API should answer all of the following:

1. Is the changed symbol/export listed in `stability/public_api_manifest.json`?
2. Are `docs/API_SURFACE.md` and `docs/ERROR_MODEL.md` still accurate?
3. Do the stable schemas / registries still match the implementation?
4. Do shared Go/TypeScript/Swift/Rust fixture corpora still pass?
5. Do Go compile-time stable symbol checks still pass?
6. Do TypeScript packed tarball export checks still pass?
7. Are coverage gates for the affected key packages still green?
8. Do browser/node/reconnect/controlplane/proxy migration paths still have test coverage?
9. Does `verify-parity` still prove all four languages consume every registered shared fixture?
10. Do Direct/Tunnel/RPC/stream/liveness/proxy tests cover both Go-reference directions for the affected non-Go SDK?

## CI gate mapping

PRs are expected to keep the following green:

- `make check`
- manifest validation
- docs stability checks
- Go stable symbol compile checks
- Swift symbol graph checks
- Rust public API compile and semver checks
- Go/TypeScript/Rust coverage checks
- Rust line coverage and fuzz-target compilation
- package/export verification

Nightly and heavier checks may additionally cover:

- the same deterministic Go-reference smoke profile used by CI
- reconnect edge cases
- Go and Rust fuzzing
- compatibility scaffolding

The fixed five-minute `make interop-stress` profile is a required local merge and release gate. It is intentionally not a GitHub Actions soak and never expands into non-Go pairwise edges.

## Deprecation guidance

When possible, prefer:

1. introduce replacement
2. update docs and examples
3. keep old stable API working during the transition window
4. remove only after an explicit compatibility review

For v0.20.x, grant-first browser helpers and grant-first proxy bootstrap helpers follow this rule: the stable replacement is artifact-first controlplane + proxy helper flows, while the older APIs remain compatibility-only or stable deprecated aliases during the transition window. The explicitly removed keepalive and reconnect-source fields are an exception covered by the v0.20 breaking-release review.
