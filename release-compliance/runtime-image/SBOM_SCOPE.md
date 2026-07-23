# SBOM Scope

The SPDX and CycloneDX documents in `sbom/` describe the runtime dependency union for the exact runtime-image targets and platforms declared in `scripts/release-go-targets.json`.
Build-only, test-only, and unrelated module dependencies are excluded.
These embedded application documents do not describe container-base-image files.
The container release also publishes a BuildKit SPDX SBOM attestation for the complete final OCI image, including its base image.
