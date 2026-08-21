# Flowersec API Change Policy

Flowersec 3.0.0 maintains one strict transport and security contract across Go,
TypeScript, Swift, and Rust. Public symbols, module paths, wire identifiers,
registry values, and published artifacts follow SemVer and immutable-tag rules.

## Contract Authority

1. Wire and security invariants are defined by the final Chinese design in
   `docs/TRANSPORT_V3_DESIGN.zh-CN.md`. The English wire and architecture
   documents, `stability/transport_v3_contract.json`, and the shared fixtures
   under `testdata/transport_v3/` are derived consistency artifacts. A conflict
   stops release and is resolved against the Chinese design; derived artifacts
   never replace or extend its general rules.
2. Public API and package boundaries are defined by
   `stability/api_contract_manifest.json`; shared portable defaults remain in
   `stability/sdk_defaults.json` where v3 does not replace them.
3. `docs/API_CONTRACT.md`, the SDK READMEs, and this policy summarize those
   contracts and do not create a different acceptance set.
4. Tests execute the contract. Incidental implementation or test behavior does
   not override an explicit v3 rule.

Checks verify registered Go and Rust compile entries, TypeScript source and
packed exports, the Swift symbol surface, documentation tokens, versioned
registry and vector consistency, and explicit forbidden surfaces. A language
surface that cannot be enumerated mechanically requires review in the same
change.

## Public Boundary

Applications receive opaque artifacts and leases, one-shot connection
functions, carrier-neutral Sessions, RPC peers, byte streams, metadata,
redacted errors, and bounded Controller decisions. TLS policy, pins,
certificate material, candidate identity, capability descriptors, FSB3/FSA3,
carrier handles, wire state, keys, and durable spend internals stay below the
public Session/RPC/Stream boundary.

The Go control-plane package receives structured endpoints containing URL and
typed TLS policy. It does not fetch pins, issue certificates, install trust
roots, or manage certificate rollout. The deployment system owns those tasks.

v3 APIs accept only v3 artifacts and use only v3 routes, profiles, frame
magics, and cryptographic domains. Any retained v2 compatibility API is
explicitly versioned and cannot be selected as fallback from a v3 failure.
CA and pin are mutually exclusive, and a failed pin candidate never retries
the same endpoint as CA.

Every public API change requires:

- explicit contract and security review;
- specification, registry, manifest, and vector updates in the same change;
- focused behavior and negative surface tests;
- four-language interoperability updates when wire or canonicalization changes;
- focused tests and `make precommit` on every feature candidate;
- the bounded `make test` acceptance run owned by `scripts/push-main.sh` on the
  final integrated main tip.

Release performs version/ref validation, packaging, signing, publication, and
registry readback only. It consumes no test evidence and runs no test suite.

## Transport Behavior

WebSocket, raw QUIC, and WebTransport are equal candidate classes only when the
exact runtime tuple and TLS security mode are declared. Unsupported candidates
are skipped before transport construction. If all candidates are unsupported,
the result is `transport_security_unsupported`; there is no attempted fallback.

TLS succeeds before durable spend and FSB3. Native CA mode uses platform or
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
   rules match the v3 registry.
4. Controller, lease, refresh, retry/backoff, and cancellation behavior match
   the v3 Controller vectors.
5. Focused tests, `make precommit`, and the applicable browser, diagnostic,
   performance, weak-network, and final acceptance gates pass on the reviewed
   commit.
