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

In v0.19.x this explicitly includes:

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

`@floegence/flowersec-core/controlplane` is the canonical stable artifact-fetch entry.
Browser re-exports of `requestConnectArtifact(...)`, `requestEntryConnectArtifact(...)`, and `ControlplaneRequestError` remain stable aliases during the compatibility window.

### Scoped metadata and proxy runtime

Stable in v0.19.x:

- the `scoped` carrier on `ConnectArtifact`
- critical fail-fast meaning
- `proxy.runtime@1` when consumed by the stable proxy helper entrypoints

Experimental in v0.19.x:

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

## v0.19.x compatibility posture

Flowersec v0.19.x keeps the long-term core surface small, but makes the artifact-first path materially easier to adopt:

- `@floegence/flowersec-core/controlplane` becomes the recommended TypeScript controlplane entry
- browser/node reconnect adapters become artifact-aware without duplicating reconnect core logic
- proxy same-origin and controller-origin helper paths become artifact-first
- Go gets a thin `controlplane/http` reference layer instead of forcing every integrator to rebuild the same decode/write contract

At the same time, these compatibility edges remain intentionally supported:

- raw grant path
- wrapper path
- raw direct path
- `requestChannelGrant(...)` / `requestEntryChannelGrant(...)`
- existing proxy wire `timeout_ms` compatibility (`omit == 0 == server default`)
- browser stable aliases for the shared controlplane helpers

## Review checklist

Any change that touches a stable API should answer all of the following:

1. Is the changed symbol/export listed in `stability/public_api_manifest.json`?
2. Are `docs/API_SURFACE.md` and `docs/ERROR_MODEL.md` still accurate?
3. Do the stable schemas / registries still match the implementation?
4. Do shared Go/TS parser fixture corpora still pass?
5. Do Go compile-time stable symbol checks still pass?
6. Do TypeScript packed tarball export checks still pass?
7. Are coverage gates for the affected key packages still green?
8. Do browser/node/reconnect/controlplane/proxy migration paths still have test coverage?

## CI gate mapping

PRs are expected to keep the following green:

- `make check`
- manifest validation
- docs stability checks
- Go stable symbol compile checks
- Go/TS coverage checks
- package/export verification

Nightly and heavier checks may additionally cover:

- stress interop
- reconnect edge cases
- fuzzing
- compatibility scaffolding

## Deprecation guidance

When possible, prefer:

1. introduce replacement
2. update docs and examples
3. keep old stable API working during the transition window
4. remove only after an explicit compatibility review

For v0.19.x, grant-first browser helpers and grant-first proxy bootstrap helpers follow this rule: the stable replacement is artifact-first controlplane + proxy helper flows, while the older APIs remain compatibility-only or stable deprecated aliases during the transition window.
