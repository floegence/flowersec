# Flowersec API Stability Policy

This document explains how Flowersec classifies API surface and how that classification maps to engineering gates.

See also:

- Stable API list: `docs/API_SURFACE.md`
- Canonical manifest: `stability/public_api_manifest.json`
- Error contract: `docs/ERROR_MODEL.md`

## Stability Levels

### Stable

Stable APIs are the supported integration entrypoints listed in `docs/API_SURFACE.md` and tracked in `stability/public_api_manifest.json`.

Stable means:

- the symbol/export is intentionally supported for downstream integrations
- docs, package exports, and tests must stay aligned
- breaking changes require an explicit compatibility review
- CI must keep the related stability and coverage gates green

### Experimental

Experimental APIs may be documented or shipped, but they are not covered by the same compatibility commitment as the stable surface.

Experimental means:

- semantics may still change based on usage feedback
- behavior may tighten as protocol/security work evolves
- users should expect faster iteration than the stable surface

### Internal

Internal APIs are implementation details and are not part of the public contract.

Internal means:

- they may change or disappear without a deprecation cycle
- downstream projects should not depend on them directly
- they are outside the stable review checklist

## Source Of Truth

The canonical machine-readable source for the stable surface is:

- `stability/public_api_manifest.json`

That manifest drives:

- Go stable symbol compilation checks
- TypeScript tarball export checks
- `docs/API_SURFACE.md` token coverage checks
- coverage thresholds for key packages/modules

If a change updates the public surface, it must update the manifest in the same change.

## Compatibility Rules

### Go

The stable Go surface is the package/type/function set listed in `docs/API_SURFACE.md` and encoded in the manifest.

Breaking changes to stable Go APIs require:

- explicit API review
- docs updates
- stability checks passing
- regenerated/updated examples if the public calling pattern changed

### TypeScript

The stable TypeScript surface is the package root + documented subpath exports listed in `docs/API_SURFACE.md` and encoded in the manifest.

Breaking changes to stable TypeScript APIs require:

- explicit API review
- docs updates
- packed tarball export verification
- coverage and test gates remaining green

### Error Contract

For the high-level connection APIs, the public machine-readable error contract is:

- `{ path, stage, code }`

The intended stable codes are documented in `docs/ERROR_MODEL.md`.

## Review Checklist

Any change that touches a stable API should answer all of the following:

1. Is the changed symbol/export listed in `stability/public_api_manifest.json`?
2. Are `docs/API_SURFACE.md` and `docs/ERROR_MODEL.md` still accurate?
3. Do Go compile-time stable symbol checks still pass?
4. Do TypeScript packed tarball export checks still pass?
5. Are coverage gates for the affected key packages still green?
6. Do integration / interop tests still cover the affected flow?

## CI Gate Mapping

### PR gate

PRs are expected to keep the following green:

- `make check`
- manifest validation
- docs stability checks
- Go stable symbol compile checks
- Go/TS coverage checks

### Nightly gate

Nightly jobs are used for heavier scenarios that are valuable but too expensive or too variable for every PR:

- stress interop runs
- client reset interop runs
- short fuzz runs
- compatibility scaffolding hooks

## Deprecation Guidance

When possible, prefer:

1. introduce replacement
2. update docs and examples
3. keep old stable API working during the transition window
4. remove only after an explicit compatibility review

For the current experimental phase, not every stable API has a long deprecation window yet, but the goal is still to avoid surprise breakage on the documented stable surface.
