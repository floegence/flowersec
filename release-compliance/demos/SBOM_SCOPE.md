# SBOM Scope

The SPDX and CycloneDX documents in `sbom/` describe the runtime dependency union for the exact demos targets and platforms declared in `scripts/release-go-targets.json`.
This includes the TypeScript runtime dependencies installed from the locked production dependency graph under `flowersec-ts/node_modules` in every demo archive.
Build-only, test-only, and unrelated module dependencies are excluded.
The archive does not contain operating-system or container-base-image files.
