# Proxy Presets

Flowersec uses preset manifests instead of named proxy profiles.

## Manifest contract

Machine-readable schema:

- `stability/proxy_preset_manifest.schema.json`

TypeScript helpers:

- `assertProxyPresetManifest(...)`
- `resolveProxyPreset(...)`
- `DEFAULT_PROXY_PRESET_MANIFEST`

Go helpers:

- `preset.Manifest`
- `preset.DecodeJSON(...)`
- `preset.LoadFile(...)`
- `preset.ApplyBridgeOptions(...)`

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
- integrations should consume manifest files or decoded `ProxyPresetManifest` objects instead

## Gateway consumption

Gateway consumer path:

- `proxy.preset_file`
- `proxy.timeout_ms` as an explicit positive-integer override for the preset default request timeout

If `proxy.preset_file` is omitted, the gateway uses the proxy bridge defaults.
Unknown fields, including the removed `proxy.profile` field, are rejected.

## Reference presets

First-party reference files live under:

- `reference/presets/default/manifest.json`
- `reference/presets/codeserver/manifest.json`

These reference files are distribution assets, not the core contract itself.
Both remain loadable through the generic manifest APIs; neither is exposed as a named profile.
