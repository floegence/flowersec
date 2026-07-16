# manifestgen

Repository tool for validating scoped metadata contract files under `stability/scopes/`.

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
- non-empty `carrier`
- `payload_kind == "json_object"`
- non-empty `consumer`
- non-empty `resolver_contract`

This tool is repository infrastructure; the public scope APIs and payload contracts it verifies are governed by `docs/API_CHANGE_POLICY.md`.
