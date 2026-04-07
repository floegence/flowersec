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

In v0.18.x this explicitly includes:

- public normalize helper shapes
- public scope resolver registration model
- scoped manifest toolchain/codegen factory
- concrete scoped payload schemas such as `proxy.runtime`
- bilateral scope negotiation semantics

### Internal

Internal APIs are implementation details and are not part of the public contract.

## Source of truth

Stable source-of-truth artifacts:

- `stability/public_api_manifest.json`
- `stability/connect_artifact.schema.json`
- `stability/connect_error_code_registry.json`
- `stability/connect_diagnostics_code_registry.json`
- `stability/proxy_preset_manifest.schema.json`

Experimental source-of-truth artifacts:

- `stability/scopes/*.manifest.json`
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

### TypeScript

The stable TypeScript surface is the root package plus documented subpath exports listed in `docs/API_SURFACE.md` and encoded in the manifest.

Breaking changes to stable TypeScript APIs require:

- explicit API review
- docs updates
- packed tarball export verification
- stable browser/node wrapper paths staying green

### Error and diagnostics contract

For high-level connection APIs, the stable machine-readable contracts are:

- connect result: `{ path, stage, code }`
- runtime diagnostics: `DiagnosticEvent`

Registry sources:

- `stability/connect_error_code_registry.json`
- `stability/connect_diagnostics_code_registry.json`

## v0.18.x compatibility posture

Flowersec v0.18.x intentionally tightens a few inputs and behaviors to keep the long-term core surface elegant:

- hybrid ambiguous connect inputs fail fast
- client-facing connect helpers reject `grant_server` / server-role raw inputs early
- new strict APIs no longer use `0 == default`
- observer callbacks no longer affect connect success semantics
- named proxy profiles are removed from the stable core surface in favor of preset manifests

At the same time, these compatibility edges remain intentionally supported:

- raw grant path
- wrapper path
- raw direct path
- `requestChannelGrant(...)` / `requestEntryChannelGrant(...)`
- existing proxy wire `timeout_ms` compatibility (`omit == 0 == server default`)

## Review checklist

Any change that touches a stable API should answer all of the following:

1. Is the changed symbol/export listed in `stability/public_api_manifest.json`?
2. Are `docs/API_SURFACE.md` and `docs/ERROR_MODEL.md` still accurate?
3. Do the stable schemas / registries still match the implementation?
4. Do shared Go/TS parser fixture corpora still pass?
5. Do Go compile-time stable symbol checks still pass?
6. Do TypeScript packed tarball export checks still pass?
7. Are coverage gates for the affected key packages still green?
8. Do browser/node/reconnect/controlplane migration paths still have test coverage?

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

For v0.18.x, named proxy profiles follow this rule: the stable replacement is preset manifests plus gateway `proxy.preset_file`, while the old profile helpers remain compatibility-only and are no longer part of the stable core surface.
