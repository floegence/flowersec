# Flowersec API Change Policy

Flowersec 2.x maintains one carrier-neutral public contract across Go, TypeScript, Swift, and Rust. There is no maintained v1 tier or in-process compatibility surface.

## Sources of Truth

- `docs/API_CONTRACT.md`
- `docs/ERROR_MODEL.md`
- `docs/TRANSPORT_V2_ARCHITECTURE.md`
- `docs/TRANSPORT_V2_WIRE.md`
- `stability/api_contract_manifest.json`
- `stability/language_capabilities.json`
- `stability/transport_v2_contract.json`
- `stability/sdk_defaults.json`
- `testdata/transport_v2/`

The API manifest drives Go compile probes, packed TypeScript exports, Swift symbol checks, Rust compile probes, documentation tokens, and coverage thresholds. The language and Transport v2 manifests record portable behavior, internal runtime support facts, and executable evidence.

## Public Boundary

Applications receive only opaque artifacts and leases, connectors, carrier-neutral sessions, RPC peers, byte streams, metadata, and stable redacted errors. Candidate selection, carrier adapters, Yamux, wire messages, cryptographic state, keys, and durable spend-ledger details are implementation boundaries.

Every public API change requires:

- an explicit contract review;
- documentation and manifest updates in the same change;
- focused behavior and negative API-surface tests;
- cross-language fixture updates when serialization or wire behavior changes;
- package, symbol, SemVer, and full integration gates before release.

Removed v1 symbols, generated packages, package subpaths, and CLIs remain on negative package/source guards. A manifest change must not silently restore them.

## Transport Behavior

WebSocket, raw QUIC, and WebTransport are equal candidate classes. WebSocket may use hop-local Yamux internally; raw QUIC and WebTransport use native bidirectional streams and preserve native FIN, reset, stop-sending, flow-control, and migration behavior. Application 0-RTT and QUIC DATAGRAM are disabled.

Internal runtime support facts may contain only exact tuples backed by production connector/listener code and end-to-end evidence. Capability descriptors and carrier selection are not public SDK contracts. Unsupported carriers fail closed and are not fallbacks.

## Required Review

For every affected language or runtime, reviewers verify:

1. The public symbol/export is represented in `stability/api_contract_manifest.json`.
2. Opaque boundaries and error redaction remain intact.
3. Shared vectors and runtime capability facts match the implementation.
4. Focused unit, package, and interoperability tests cover the changed behavior.
5. `make check` passes on the final integrated commit before release.
