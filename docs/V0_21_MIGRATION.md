# Flowersec v0.21 Migration Guide

Flowersec v0.21 removes product-shaped compatibility names from the core packages and aligns Swift scoped metadata handling with Go and TypeScript.

The following contracts are unchanged:

- `ConnectArtifact v1`
- `proxy.runtime@1`
- the encrypted-record format
- the Yamux frame format
- StreamHello and application RPC type IDs

## Codeserver preset migration

The Go and TypeScript core packages no longer export or resolve the `codeserver` profile or built-in preset name.

Use an explicit manifest instead:

- copy or inspect `reference/presets/codeserver/manifest.json`
- load it with Go `preset.LoadFile(...)` or `preset.DecodeJSON(...)`
- decode the same manifest shape in TypeScript with `assertProxyPresetManifest(...)`
- configure the gateway through `proxy.preset_file`

The manifest identifier `preset_id: "codeserver"` remains valid data. Only the core-owned name-to-preset mapping and profile constants were removed.

## Swift scope resolvers

Swift `ConnectOptions` now supports product-neutral scope resolvers keyed by scope name, matching the existing Go and TypeScript connect behavior.

- missing resolvers fail for critical scopes
- missing resolvers for optional scopes are ignored with diagnostics
- resolver validation failures fail by default, including optional scopes
- relaxed optional validation is an explicit opt-in and emits `scope_ignored_relaxed_validation`

Resolvers receive the full scope entry, including `scopeVersion`, `critical`, and payload. Product-specific payload parsing remains in the downstream resolver.

## Deliberate exclusions

Flowersec v0.21 does not add automatic connect-config deep comparison or identity serialization. Downstream applications should continue to keep stable config objects where their reconnect lifecycle already requires that behavior.
