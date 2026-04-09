# manifestgen

Experimental helper for validating scoped metadata manifest files under `stability/scopes/`.

## Usage

Run it from the tool directory:

```bash
cd tools/manifestgen
go run .
```

The current implementation resolves the repository root relative to `tools/manifestgen/`, then validates every `stability/scopes/*.manifest.json` file it finds.

## Current checks

Today the tool verifies the manifest fields that are currently required by the scoped-metadata manifests:

- `version == 1`
- non-empty `scope`
- positive `scope_version`
- non-empty `stability`
- non-empty `carrier`
- `payload_kind == "json_object"`
- non-empty `resolver_contract`

This tool is intentionally small and not part of the stable Flowersec API surface.
