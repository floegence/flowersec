# Flowersec v0.21 Migration Guide

Flowersec v0.21 removes product-shaped compatibility names from the core packages and aligns Swift scoped metadata handling with Go and TypeScript.

The following contracts are unchanged:

- `ConnectArtifact v1`
- `proxy.runtime@1`
- the encrypted-record format
- the Yamux frame format
- StreamHello and application RPC type IDs

## Release coordinates

- Go module tag: `flowersec-go/v0.21.0`
- npm package: `@floegence/flowersec-core@0.21.0`
- SwiftPM root tag: `0.21.0`

Upgrade downstream dependencies from published registries or releases. Do not use `replace`, `file:`, `link:`, `workspace:`, sibling aliases, or copied source as a completed upgrade path.

## Codeserver preset migration

The Go and TypeScript core packages no longer export or resolve the `codeserver` profile or built-in preset name.

Use an explicit manifest instead:

- copy or inspect `reference/presets/codeserver/manifest.json`
- load it with Go `preset.LoadFile(...)` or `preset.DecodeJSON(...)`
- decode the same manifest shape in TypeScript with `assertProxyPresetManifest(...)`
- configure the gateway through `proxy.preset_file`

The manifest identifier `preset_id: "codeserver"` remains valid data. Only the core-owned name-to-preset mapping and profile constants were removed.

## Swift scope resolvers

Swift artifact connects now use the same generic scope-validation semantics as Go and TypeScript. Register product-owned asynchronous validators by exact scope name:

```swift
let options = ConnectOptions(
  scopeResolvers: [
    "example.capability": { entry in
      guard entry.scopeVersion == 1 else {
        throw UnsupportedScopeVersion()
      }
      try validateCapabilityPayload(entry.payload)
    }
  ]
)

let client = try await Flowersec.connect(artifact, options: options)
```

Validation happens before transport policy evaluation and network activity. A missing resolver for a critical scope or any registered resolver failure returns `FlowersecError` with `stage=.validate` and `code=.resolveFailed`.

Missing optional resolvers remain compatible: connect continues and emits `scope_ignored_missing_resolver` with `stage=.scope`.

Optional resolver failures remain fail-closed by default. Temporary migrations can explicitly relax only that case:

```swift
let options = ConnectOptions(
  scopeResolvers: resolvers,
  relaxedOptionalScopeValidation: true
)
```

The downgrade emits `scope_ignored_relaxed_validation`. It never applies to critical scopes, does not make missing critical resolvers optional, and does not include resolver errors or payload values in diagnostics.

Scope payload interpretation and product policy remain downstream responsibilities. Flowersec does not add built-in product scope names or alter `ConnectArtifact` to support this API.

## Deliberate exclusions

Flowersec v0.21 does not add automatic connect-config deep comparison or identity serialization. Downstream applications should continue to keep stable config objects where their reconnect lifecycle already requires that behavior.
