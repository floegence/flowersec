# SBOM Scope

The SPDX and CycloneDX documents in `sbom/` describe the runtime dependency union for the exact gateway targets and platforms declared in `scripts/release-go-targets.json`.
Build-only, test-only, and unrelated module dependencies are excluded.
The archive does not contain operating-system or container-base-image files.
