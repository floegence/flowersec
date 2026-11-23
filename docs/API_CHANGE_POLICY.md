# Flowersec API Change Policy

Flowersec 7 maintains one strict transport and security contract across Go,
TypeScript, Swift, and Rust. Public symbols, module paths, wire identifiers,
registry values, and published artifacts follow SemVer and immutable-tag rules.

## Contract Authority

1. `docs/TRANSPORT_V5_WIRE.md` defines the `flowersec/5` wire and security
   invariants. `stability/transport_v5_contract.json` binds that specification
   by digest and identifies the shared fixtures under `testdata/transport_v5/`.
   An inconsistency between the specification, registry and fixtures blocks release.
2. Public API and package boundaries are defined by
   `stability/api_contract_manifest.json`; shared portable defaults remain in
   `stability/sdk_defaults.json` where the wire contract does not replace them.
3. `docs/API_CONTRACT.md`, the SDK READMEs, and this policy summarize those
   contracts and do not create a different acceptance set.
4. Tests execute the contract. Incidental implementation or test behavior does
   not override an explicit wire rule.

Checks verify registered Go and Rust compile entries, TypeScript source and
packed exports, the Swift symbol surface, documentation tokens, versioned
registry and vector consistency, and explicit forbidden surfaces. A language
surface that cannot be enumerated mechanically requires review in the same
change.

## Public Boundary

Applications receive opaque artifacts and leases, one-shot connection
functions, carrier-neutral Sessions, RPC peers, byte streams, metadata,
redacted errors, and bounded Controller decisions. TLS policy, pins,
certificate material, candidate identity, capability descriptors, FSB5/FSA5,
carrier handles, wire state, keys, and durable spend internals stay below the
public Session/RPC/Stream boundary.

The Go control-plane package receives structured endpoints containing URL and
typed TLS policy. It does not fetch pins, issue certificates, install trust
roots, or manage certificate rollout. The deployment system owns those tasks.

Current APIs accept only Transport v5 artifacts and use only current routes,
profiles, frame magics, and cryptographic domains. There is no compatibility
API or fallback path.
CA and pin are mutually exclusive, and a failed pin candidate never retries
the same endpoint as CA.

Every public API change requires:

- explicit contract and security review;
- specification, registry, manifest, and vector updates in the same change;
- focused behavior and negative surface tests;
- four-language interoperability updates when wire or canonicalization changes;
- focused tests and `make precommit` on every feature candidate;
- `make test` on the complete integrated main tip, run once by `scripts/push-main.sh`.

Release performs version/ref validation, packaging, signing, publication, and
registry readback only. It consumes no test evidence and runs no test suite.
The Go SDK, SQLite adapter, SwiftPM and Rust tags identify the same commit. With four tags, GitHub does not send a tag push event: `scripts/release.sh` explicitly dispatches the full workflow on the exact Go tag after the atomic push. If dispatch is uncertain, check the runs for the tagged SHA before retrying. Never move or recreate the tags.
To recover a full release after `main` advances, dispatch the release workflow
from the current `main` tip. Recovery accepts the tagged ancestor only when the
changes since that tag are limited to the approved release tooling. Standalone
npm recovery verifies the signed release archives before publishing those exact
bytes. Major 5 maintenance uses `release/5.x` and the npm `legacy-v5` tag; it
does not promote the GHCR `latest` tag.

## Transport Behavior

WebSocket, raw QUIC, and WebTransport are equal candidate classes only when the
exact runtime tuple and TLS security mode are declared. Unsupported candidates
are skipped before transport construction. If all candidates are unsupported,
the result is `transport_security_unsupported`; there is no attempted fallback.

TLS succeeds before durable spend and FSB5. Native CA mode uses platform or
deployment roots with hostname validation. Native pin mode verifies the
portable certificate profile and complete leaf DER SHA-256 while preserving
the TLS provider's CertificateVerify, Finished, transcript, ALPN, and private
key proof. Browser pinning is available only through a registered production
WebTransport provider and `serverCertificateHashes`.

Browser JavaScript cannot inspect the peer leaf SPKI and cannot prove the
P-256-only certificate profile. A browser may accept a different non-RSA key
algorithm through its WebTransport policy; such an endpoint has no
cross-runtime profile or interoperability guarantee. SDK documentation and
APIs MUST NOT claim that JavaScript verified P-256-only. Use a native verifier
or an explicitly browser-supported deployment profile when P-256-only is a
requirement.

WebTransport preserves transport-managed passive rebinding but does not expose
application-managed active migration. Raw QUIC may declare active migration
only when its production runtime and capability tuple implement it.

The Controller owns one scheduler, one acquisition/attempt at a time,
deterministic bounded backoff, one policy-sensitive replacement lease per
cycle, monotonic blocked pin policies, and atomic lease retirement or spend.
It never replays streams, RPCs, or writes into a replacement Session.

## Required Review

For every affected language or runtime, reviewers verify:

1. Public symbols and errors match `stability/api_contract_manifest.json`.
2. Strict codec, canonicalization, hash, binding, and vectors agree byte for
   byte across all four languages.
3. TLS policy, capability filtering, error phase, rotation, and no-downgrade
   rules match the v5 registry.
4. Controller, lease, refresh, retry/backoff, and cancellation behavior match
   the v5 Controller vectors.
5. Focused tests, `make precommit`, and the applicable browser, diagnostic,
   performance, weak-network, and final acceptance gates pass on the reviewed
   commit.
