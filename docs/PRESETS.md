# Proxy Presets

Flowersec v0.18.x replaces stable named proxy profiles with a stable preset manifest contract.

## Stable contract

Machine-readable schema:

- `stability/proxy_preset_manifest.schema.json`

TypeScript stable helpers:

- `assertProxyPresetManifest(...)`
- `resolveProxyPreset(...)`
- `DEFAULT_PROXY_PRESET_MANIFEST`

Go stable helpers:

- `preset.Manifest`
- `preset.DecodeJSON(...)`
- `preset.LoadFile(...)`
- `preset.ApplyBridgeOptions(...)`

Compatibility-only Go helper:

- `preset.ResolveBuiltin(...)`

## Shape

```json
{
  "v": 1,
  "preset_id": "default",
  "deprecated": false,
  "limits": {
    "max_json_frame_bytes": 1048576,
    "max_chunk_bytes": 262144,
    "max_body_bytes": 67108864,
    "max_ws_frame_bytes": 1048576
  }
}
```

Rules:

- unknown fields are rejected
- numeric limits are positive integers when present
- omission means “not set” at the preset API layer
- `limits.timeout_ms`, when present, becomes the default `HTTPRequestMeta.timeout_ms` for bridge/gateway and browser proxy integrations
- `preset.ResolveBuiltin(...)` only bridges deprecated named profiles to first-party reference manifests; stable integrations should consume manifest files or decoded `ProxyPresetManifest` objects instead

## Gateway consumption

Stable gateway consumer path:

- `proxy.preset_file`
- `proxy.timeout_ms` as an explicit positive-integer override for the preset default request timeout

Deprecated compatibility path:

- `proxy.profile`

Do not set both at once.

## Reference presets

First-party reference files live under:

- `reference/presets/default/manifest.json`
- `reference/presets/codeserver/manifest.json`

These reference files are distribution assets, not the core stable contract itself.
