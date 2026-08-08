# Flowersec API Change Policy

Flowersec 2.x maintains one carrier-neutral public contract across Go, TypeScript, Swift, and Rust. Flowersec 2.0.0 is the immutable coordinated baseline; Flowersec 2.1.0 adds the reviewed server acceptor boundary, and 2.2.0 adds accepted-session handler resolution plus the Go server counterpart to the published TypeScript proxy runtime. Earlier tags and artifacts are never moved or replaced. There is no maintained v1 tier or in-process compatibility surface.

## Sources of Truth

- `docs/API_CONTRACT.md`
- `docs/ERROR_MODEL.md`
- `docs/TRANSPORT_V2_ARCHITECTURE.md`
- `docs/TRANSPORT_V2_WIRE.md`
- `stability/api_contract_manifest.json`
- `stability/language_capabilities.json`
- `stability/transport_v2_contract.json`
- `stability/sdk_defaults.json`
- `stability/connection_controller_recovery.json`
- `testdata/transport_v2/`

The API manifest drives Go compile probes, packed TypeScript exports, Swift symbol checks, Rust compile probes, documentation tokens, and coverage thresholds. The language and Transport v2 manifests record portable behavior, explicit server/control-plane capability status, and executable test IDs.

## Public Boundary

Applications receive only opaque artifacts and leases, one-shot connection functions, carrier-neutral sessions, bounded session-handler registries, RPC peers, byte streams, metadata, stable redacted errors, and bounded recovery decisions. Go session handlers freeze inbound RPC and stream registrations together for a valid connection attempt and dispatch application streams with bounded metadata without exposing the carrier. Go server control planes additionally receive opaque endpoint sets, issued artifacts, authorization records, runtime requests, and runtime responses through the dedicated v2 control-plane package. The TypeScript proxy entrypoint may compose an opaque lease into a `Session` runtime and browser bridge, but must not expose transport objects, raw artifact scopes, proxy wire frames, or `proxy.runtime@1`. Candidate selection, carrier adapters, Yamux, wire messages, FSB2 payloads, cryptographic state, keys, and durable spend-ledger details are implementation boundaries.

Portable RPC means outbound call and notification support. Notification subscriptions and inbound request-handler registration are separate capabilities and must not be implied by the portable RPC capability. Portable core, server admission, accepted sessions, control-plane issuance/authorization, connection control, RPC/stream lifecycle, and published consumer workflows must have same-semantic public entries in every applicable SDK. Genuine platform limitations alone may be marked `unsupported`; every unsupported entry requires a concrete reason, an alternative public boundary, and a test ID in `stability/language_capabilities.json`. Controller recovery dispositions must continue to match `stability/connection_controller_recovery.json` in every language.

Every public API change requires:

- an explicit contract review;
- documentation and manifest updates in the same change;
- focused behavior and negative API-surface tests;
- cross-language fixture updates when serialization or wire behavior changes;
- package, symbol, SemVer, and full integration gates before release.

Adding a public `Acceptor`, server admission, handler resolver, proxy server, or control-plane symbol is a SemVer minor capability unless the change is strictly documentation or an internal fix. The 2.2.0 handler/proxy additions therefore cannot be published as 2.1.1; all already published tags and artifacts remain immutable.

Removed v1 symbols, generated packages, package subpaths, and CLIs remain on negative package/source guards. A manifest change must not silently restore them.

## Transport Behavior

WebSocket, raw QUIC, and WebTransport are equal candidate classes. WebSocket may use hop-local Yamux internally; raw QUIC and WebTransport use native bidirectional streams and preserve native FIN, reset, stop-sending, flow-control, and migration behavior. Application 0-RTT is disabled. Reliable streams never use QUIC DATAGRAM; a negotiated native DATAGRAM path is available only through the carrier-neutral unreliable-message contract.

Internal runtime support facts may contain only exact tuples backed by production connector/listener code and end-to-end evidence. Capability descriptors and carrier selection are not public SDK contracts. Unsupported carriers fail closed and are not fallbacks.

## Required Review

For every affected language or runtime, reviewers verify:

1. The public symbol/export is represented in `stability/api_contract_manifest.json`.
2. Opaque boundaries and error redaction remain intact.
3. Shared vectors and runtime capability facts match the implementation.
4. Focused unit, package, and interoperability tests cover the changed behavior.
5. `make check` passes on the final integrated commit before release.
