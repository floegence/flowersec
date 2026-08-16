# Flowersec API Change Policy

Flowersec 2.5.1 maintains one carrier-neutral public contract across Go, TypeScript, Swift, and Rust. Public symbols, module paths, wire identifiers, and published artifacts follow the SemVer and immutable-tag rules.

## Contract Authority

1. Wire and security invariants are defined by `docs/TRANSPORT_V2_WIRE.md`, `stability/transport_v2_contract.json`, and the shared wire and security fixtures under `testdata/transport_v2/`. Any conflict among them must be fixed rather than resolved by choosing one source.
2. Public API, profiles, and defaults are defined by `stability/api_contract_manifest.json`, `stability/language_capabilities.json`, and `stability/sdk_defaults.json`. Controller recovery behavior is recorded in `stability/connection_controller_recovery.json`.
3. Human-readable facts in `docs/API_CONTRACT.md`, `docs/ERROR_MODEL.md`, `docs/TRANSPORT_V2_ARCHITECTURE.md`, and the READMEs summarize the first two layers and do not create a separate contract.
4. Tests execute these contracts; an incidental test behavior does not override an explicit product contract.

The current checks verify registered Go and Rust compile entries, registered TypeScript source entries and actual packed exports, the bidirectional Swift symbol surface, documentation tokens, and explicit forbidden surfaces. Languages that cannot yet be enumerated bidirectionally require a public-surface review in the same change. The language and Transport v2 manifests record portable behavior, explicit server/control-plane capability status, and executable test IDs.

## Public Boundary

Applications receive only opaque artifacts and leases, one-shot connection functions, carrier-neutral sessions, role-specific inbound RPC definitions, accepted-session handler registries, RPC peers, byte streams, metadata, stable redacted errors, and bounded recovery decisions. Native endpoint clients freeze reusable RPC/notification definitions and create a fresh router for every Session generation. Accepted server Sessions separately freeze RPC, notification, and stream definitions and dispatch application streams with bounded metadata without exposing the carrier. Go server control planes additionally receive opaque endpoint sets, issued artifacts, authorization records, runtime requests, and runtime responses through the dedicated v2 control-plane package. The TypeScript proxy entrypoint may compose an opaque lease into a `Session` runtime and browser bridge, but must not expose transport objects, raw artifact scopes, proxy wire frames, or `proxy.runtime@1`. Candidate selection, carrier adapters, Yamux, wire messages, FSB2 payloads, cryptographic state, keys, and durable spend-ledger details are implementation boundaries.

Portable RPC includes typed calls, outbound notifications, and subscriptions to peer outbound notifications through the local Session's inbound reserved RPC stream. Go `RPCPeer.OnNotify(...)`, TypeScript `RpcPeer.onNotify(...)`, Swift `RPCPeer.subscribeNotification(...)`, and Rust `RpcPeer::subscribe_notification(...)` expose the same lifecycle: registration completion is deterministic, cancellation is idempotent, decode or handler failures are isolated, and Session close terminates subscriptions. Inbound request-handler registration remains a separate server capability. Portable core, server admission, accepted sessions, control-plane issuance/authorization, connection control, RPC/stream lifecycle, and published consumer workflows must have same-semantic public entries in every applicable SDK. Genuine platform limitations alone may be marked `unsupported`; every unsupported entry requires a stable reason and must not claim an entrypoint or test ID in `stability/language_capabilities.json`. Controller recovery dispositions must continue to match `stability/connection_controller_recovery.json` in every language.

Every public API change requires:

- an explicit contract review;
- documentation and manifest updates in the same change;
- focused behavior and negative API-surface tests;
- cross-language fixture updates when serialization or wire behavior changes;
- focused tests and `make precommit` on the feature change;
- the bounded `make test` acceptance run only by `scripts/push-main.sh` when pushing the final integrated `main` tip.

Release performs version and ref validation, packaging, signing, publication, and registry readback. It does not run tests.

Adding a public `Acceptor`, server admission, handler resolver, proxy server, or control-plane symbol is a SemVer minor capability. Documentation and internal fixes are patch changes. Published tags and artifacts are immutable.

The loopback plaintext WebSocket profile is an explicit SDK capability. Only direct candidates addressed to `127.0.0.1` or `::1` may use `ws://`; tunnel candidates and non-loopback hosts use WSS and fail closed. Flowersec 2.5.1 enforces this profile during Go connector and Acceptor carrier readiness.

The reviewed public surface is recorded in `stability/api_contract_manifest.json`. Existing package, source, symbol, and forbidden-surface checks enforce the boundaries they can enumerate; public-surface review covers the remaining language-specific gaps.

## Transport Behavior

WebSocket, raw QUIC, and WebTransport are equal candidate classes. WebSocket may use hop-local Yamux internally; raw QUIC and WebTransport use native bidirectional streams and preserve native FIN, reset, stop-sending, and flow-control behavior. Raw QUIC exposes the declared active migration capability. WebTransport preserves transport-managed passive rebinding but does not expose application-managed active migration. Application 0-RTT is disabled. Reliable streams never use QUIC DATAGRAM; a negotiated native DATAGRAM path is available only through the carrier-neutral unreliable-message contract.

Internal runtime support facts may contain only exact tuples backed by production connector/listener code and executable conformance tests. Capability descriptors and carrier selection are not public SDK contracts. Only declared carrier tuples are accepted; unsupported tuples fail closed.

## Required Review

For every affected language or runtime, reviewers verify:

1. The public symbol/export is represented in `stability/api_contract_manifest.json`.
2. Opaque boundaries and error redaction remain intact.
3. Shared vectors and runtime capability facts match the implementation.
4. Focused unit, package, and interoperability tests cover the changed behavior.
5. The feature passes focused tests and `make precommit`; the final main push passes the bounded acceptance run in `scripts/push-main.sh`.
