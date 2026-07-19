# Flowersec API Change Policy

All public Flowersec APIs are governed by one supported contract. The project does not maintain separate public API tiers.

See also:

- API contract: `docs/API_CONTRACT.md`
- Contract manifest: `stability/api_contract_manifest.json`
- Error contract: `docs/ERROR_MODEL.md`

## Contract rule

Every exported symbol, package entrypoint, package subpath, public Swift symbol, and public Rust entrypoint is expected to remain intentional and reviewable.

Public API changes require:

- an explicit compatibility review
- contract documentation and manifest updates in the same change
- package/export, compile-probe, symbol-graph, and SemVer checks passing
- updated cross-language fixtures when wire or behavior contracts change
- focused tests for the affected user workflow

Internal implementation details are not public APIs. They may evolve freely as long as the public contract and behavior checks remain green.

## Sources of truth

- `stability/api_contract_manifest.json`
- `stability/language_capabilities.json`
- `stability/sdk_defaults.json`
- `stability/connect_artifact.schema.json`
- `stability/connect_error_code_registry.json`
- `stability/connect_diagnostics_code_registry.json`
- `stability/proxy_preset_manifest.schema.json`
- `stability/scopes/proxy.runtime.manifest.json`

The API contract manifest drives:

- Go public-symbol compilation probes
- TypeScript packed-package export checks
- Swift public symbol-graph comparison
- Rust public-entrypoint compilation probes
- API contract documentation token checks
- Go coverage thresholds for key packages

The language capability manifest additionally requires every portable capability to be complete for Go, TypeScript, Swift, and Rust, with implementation and test evidence. Shared fixtures must name consumers in every language.

## Language gates

### Go

The Go packages and symbols listed in `docs/API_CONTRACT.md` and the contract manifest must compile. Public changes must keep Go tests, race tests, coverage checks, vet, and vulnerability scanning green.

Application-owned policy callbacks in `controlplane/http` remain application code, while Flowersec-owned request, response, decoding, and handler assembly APIs remain part of the public contract.

### TypeScript

Every declared package export must be present in the packed npm tarball and import successfully as a consumer. Runtime export probes, lint, build, tests, coverage, and package verification must remain green.

### Swift

The `Flowersec` product's public symbol graph is recorded in the contract manifest. Any public symbol change must update the contract intentionally and keep package build, tests, source guards, and interoperability checks green.

### Rust

The `flowersec` crate's public entrypoints are compile-probed. `cargo-semver-checks` compares each release with the previous Rust tag, and formatting, clippy, tests, docs, MSRV, packaging, coverage, audit, deny, and fuzz-target checks remain required.

## Shared behavior contract

The following behavior is verified across all four SDKs:

- `ConnectArtifact` parsing and direct/tunnel connection setup
- fail-closed transport security policy
- bounded encrypted records, WebSocket queues, Yamux, RPC, and tunnel resources
- acknowledged liveness probes
- RPC, notifications, custom streams, rekey, and reset
- controlplane envelopes, reconnect sources, proxy streams, and diagnostics
- Go-reference interoperability in both directions for every non-Go SDK

Compatibility inputs such as raw grants, wrapper objects, and raw direct info remain supported only while their tests remain present. Removing an input or public API requires an explicit product decision and corresponding release communication.

## Review checklist

Any public API or behavior change must answer:

1. Is the symbol/export represented in `stability/api_contract_manifest.json`?
2. Are `docs/API_CONTRACT.md` and `docs/ERROR_MODEL.md` accurate?
3. Do schemas, registries, defaults, and generated artifacts match the implementation?
4. Do Go, TypeScript, Swift, and Rust shared fixtures still pass?
5. Do Go compile probes, TypeScript package checks, Swift symbol checks, and Rust compile/SemVer checks pass?
6. Are focused tests present for the changed workflow?
7. Does `verify-parity` still prove cross-language capability and fixture coverage?
8. Do the affected Go-reference interoperability directions still pass?

## Required gates

The local source of truth is `make check`. It includes:

- code generation and shared-contract verification
- API contract manifest, docs, compile, symbol, package, and SemVer checks
- Go, TypeScript, Swift, and Rust build/test matrices
- coverage, race, vulnerability, audit, deny, packaging, and fuzz-target checks
- example builds and Go-reference interoperability

Deterministic resource ceilings are enforced by automated unit tests and the loadgen checker. Machine-sensitive throughput benchmarks are run and reviewed manually; they are performance evidence, not a release gate.

The fixed `make interop-stress` profile remains a release gate for higher-volume cross-language behavior verification.
