# Migrating to Transport v2

Transport v2 is a breaking wire and session migration. It introduces equal WebSocket, raw QUIC, and WebTransport carriers below a transport-neutral session API. It does not reinterpret the existing v1 wire in place.

## Compatibility Boundary

- A v1 endpoint cannot join a v2 session.
- A v1 credential cannot be reused by v2, and a v2 credential cannot be retried through v1 after commitment.
- WebSocket URL paths and subprotocols, raw QUIC ALPN values, WebTransport paths, artifacts, listeners, metrics, and replay state remain versioned and isolated.
- The v1 implementation remains available during the dual-stack window; accidental fallback or in-band downgrade is forbidden.

The authoritative carrier, path, runtime, and capability registry is `stability/transport_v2_contract.json`. Downstream code consumes that registry through released Flowersec contracts rather than rebuilding a carrier cross-product.

## Rollout Order

1. Release Flowersec v2 SDK contracts. Deploy application-owned v2-capable tunnel listeners without advertising them; the published `flowersec-tunnel` CLI remains v1 in 0.28.0.
2. Deploy a dual-stack artifact issuer that issues only candidates present in the exact requester, endpoint, and tunnel capability intersection.
3. Upgrade native SDK consumers to the transport-neutral v2 artifact and session API while retaining their explicit v1 connection path.
4. Upgrade browser SDK consumers after real-browser WebTransport interoperability passes. Preserve one visible connecting lifecycle while Flowersec races equal candidates internally.
5. Enable v2 cohorts in stages: WebSocket-to-WebSocket first, mixed carrier paths next, then raw QUIC-to-QUIC and control connections.

Product routing, cohort selection, environment authority, quota, and audit business logic remain in the downstream control plane. Flowersec validates generic transport contracts and never learns those business rules.

## Downstream Repository Boundaries

The migration spans three consumers, but their product responsibilities remain outside this library:

- `redeven-portal` owns candidate-group issuance, rollout cohorts, opaque routing and attach tokens, quota and audit policy, and deployed tunnel readiness. It issues only exact capability intersections; Flowersec validates the generic artifact and transport contracts.
- `redeven` consumes the carrier-neutral artifact and session APIs, reports exact runtime capabilities, and keeps v1 and v2 credential persistence isolated during the dual-stack window. It must not pass Yamux-specific options into Transport v2.
- `floe-webapp` preserves its existing provider, RPC proxy, service-worker, and controller lifecycle while the Flowersec browser adapter races equal WebSocket and WebTransport candidates internally. Browser WebTransport enablement requires real-browser evidence and a production HTTP/3 edge.

These names define integration ownership only. No environment, provider, tenant, rollout, billing, or application workflow logic belongs in Flowersec.

## Published Dependency Sequence

The downstream rollout uses only published artifacts and follows this order. A
local checkout, Go `replace`, npm `file:`, npm `link:`, workspace shortcut, or
unpublished revision is useful for temporary development only and cannot be the
dependency recorded by a completed migration.

### Flowersec Release

1. Merge and validate Flowersec first, run `scripts/release.sh <version>` from a
   clean synchronized `main`, and wait for the matching
   `flowersec-go/v<version>` release and `@floegence/flowersec-core` npm package
   to be published. Record the released Go and npm versions as the only inputs
   to the downstream upgrades.
2. Upgrade `redeven-portal` to the published Go module before deploying its v2
   endpoint-set or artifact issuance changes. Update
   `backend/pkg/deployment/deployment_contract_test.go` to assert that exact
   release and run Portal's full local gate. Portal may deploy its dual-read and
   dual-write storage support at this point, but it must not enable a v2 cohort
   until the client packages and native consumer below have been published and
   validated together.

### Floe Webapp Release

1. Starting from the pre-migration `@floegence/flowersec-core@0.27.0`
   pin, update `packages/boot/package.json` and
   `packages/protocol/package.json` to the new published Flowersec npm release.
   Keep `packages/core/package.json` and `packages/init/package.json` on the
   same new Floe Webapp package version even when only boot and protocol consume
   Flowersec, because the release workflow requires all four package versions
   to match one `v<floe-version>` tag.
2. Regenerate `pnpm-lock.yaml` from the registry so it resolves the published
   Flowersec tarball. Update
   `packages/boot/test/release-contract.test.ts` to freeze the new manifest,
   lockfile, engine, and no-local-shortcut contract. Update both
   `packages/boot/test/doc-contract.test.ts` and
   `packages/protocol/test/doc-contract.test.ts` assertions and the versioned
   guidance in `docs/protocol.md` and `docs/runtime.md`; the pre-migration baseline names
   `@floegence/flowersec-core@0.27.0` explicitly.
3. Run the Floe Webapp local quality gate, including real-browser WebSocket and
   WebTransport adapter evidence, then create the matching `v<floe-version>`
   tag. Wait until the release workflow has published boot, protocol, core, and
   init and verify the boot/protocol manifests, registry tarballs, and lockfile
   all resolve the released Flowersec version. Do not start the Redeven upgrade
   from an unpublished Floe Webapp package.

### Redeven Upgrade

1. Upgrade the Go side from its pre-migration Flowersec Go `v0.27.0` pin to the
   published v2-capable module in `go.mod` and `go.sum`. Update
   `THIRD_PARTY_NOTICES.md` and the exact version assertions and previous-version
   rejection list in `internal/session/dependency_contract_test.go` in the same
   change.
2. Upgrade the UI side from the pre-migration Floe Webapp `0.39.2` and Flowersec Core
   `0.27.0` pins to the releases completed above. Update the boot, protocol,
   core, and direct Flowersec dependencies and overrides in
   `internal/envapp/ui_src/package.json`, then regenerate
   `internal/envapp/ui_src/package-lock.json` and
   `internal/envapp/ui_src/pnpm-lock.yaml`. Update the direct Flowersec pin and
   lock in `internal/codeapp/ui_src/package.json` and
   `internal/codeapp/ui_src/package-lock.json`, plus the Floe Webapp core pin in
   `desktop/package.json`, `desktop/package-lock.json`, and
   `desktop/pnpm-lock.yaml` when that consumer is part of the release. Keep
   `THIRD_PARTY_NOTICES.md`, `README.md` and every localized README, the
   executable architecture dependency contracts
   `okf/architecture/runtime-transport-dependencies.md` and
   `okf/architecture/env-app-upstream-web-dependencies.md`, and
   `internal/session/dependency_contract_test.go` synchronized with every
   published package and tarball version. The README literals are part of the
   versioned dependency mirror and must be updated in the same release change.
3. Run Redeven's full local gate against the published Flowersec Go,
   Flowersec Core, and Floe Webapp combination. The dependency-policy tests must
   reject sibling checkout paths, Go replacements, workspace/link/file npm
   specs, stale tarballs, and stale notice markers. Then run the native and
   browser acceptance gates below on that exact combination before Portal
   enables any v2 cohort. Rollback selects the last fully published and tested
   combination; it never mixes a new Flowersec Go release with old browser
   packages or vice versa.

### Direct Authority Handoff

Direct control migration must preserve one authoritative connection for each `environment_id + agent_instance_id + binding_generation`. Each physical connection has a monotonic `connection_generation`. The downstream control plane performs this state transition:

```text
OLD_AUTHORITATIVE
  -> NEW_CONNECTING
  -> NEW_ADMITTED_E2EE
  -> NEW_REGISTERED_NON_AUTHORITATIVE
  -> ATOMIC_AUTHORITY_SWAP
  -> OLD_GOAWAY_DRAINING
  -> OLD_CLOSED / NEW_AUTHORITATIVE
```

The new connection cannot receive grants or become externally visible before `ATOMIC_AUTHORITY_SWAP`. The swap uses one compare-and-swap or transaction over both generations. New work goes only to the new generation after the swap; responses for work already dispatched on the old generation are accepted only when their recorded origin generation matches. A failed new connection leaves the old authoritative connection serving. A failed old drain never rolls authority back.

### Durable Artifact Spend

Artifact persistence is versioned by credential generation and keeps active, pending, draining, spent, revoked, and expired states separate. A reconnect never reuses a spent v1 or v2 credential.

The carrier-neutral acquisition API exposes an `ArtifactLeaseV2` with `commitSpend(signal)`. This is the TypeScript spelling of the cross-language `CommitSpend` operation. TypeScript consumers import `decodeArtifactV2JSON`, `encodeArtifactV2JSON`, `validateArtifactV2`, `createArtifactLeaseV2`, and `createArtifactV2Resolver` from the root, browser, or Node package entry. `ArtifactSourceV2` adapts either one-time serialized artifacts or refreshable downstream acquisition callbacks into the same lease contract. The downstream durable store still owns the transition: its `commitSpend` callback advances `DURABLE_PENDING` to `SPENT` and fsyncs successfully before it resolves.

All candidate transports may reach the credential-free ready barrier, but the winner must call `commitSpend` before writing the first credential or protocol byte. For v2 that boundary is the first FSB2 byte; v1 adapters keep their existing version-specific attach or handshake boundary. Failure guarantees zero credential bytes. Success followed by a partial or unknown write still leaves the artifact spent.

The connector enforces `init_expire_at_unix_s` at every irreversible boundary. An artifact already expired before racing starts creates no candidate attempt and no spend. Expiry after a transport becomes ready but before `commitSpend` closes the prepared winner without spending or writing FSB2. If expiry is observed while a successful durable spend is in progress, the artifact remains spent, the prepared winner is closed, and no FSB2 byte is written.

### Custom Tunnel Readiness

A custom tunnel registration for v2 is the structured, versioned
`flowersec-tunnel-endpoint-set/2` endpoint set. Go control-plane consumers use
`github.com/floegence/flowersec/flowersec-go/v2/endpointsetv2` instead of defining
a product-local schema. It reports the rendezvous group, endpoint instance,
exact WebSocket/raw QUIC/WebTransport listener tuples, certificate and audience
readiness, and issued/expires freshness. A listen tuple records both its local
bind endpoint and canonical public `advertised_url`; candidate issuance uses
the advertised URL and never treats a wildcard bind address as routable.
Expired, unready, non-canonical, duplicate, unsorted, or cross-path endpoint
sets are rejected before registry state changes. The legacy `custom_tunnel_url`
remains a v1 WebSocket field and is never interpreted as v2 QUIC or
WebTransport support. Candidate issuance stops when the exact requester,
endpoint, and tunnel capability intersection is empty.

`redeven-portal` migration is an explicit data and API rollout; the endpoint-set
package does not make the existing `CustomTunnelURL` path v2-aware by itself:

1. Merge Flowersec first, run `scripts/release.sh <version>`, wait for the
   `flowersec-go/v<version>` publication, then update Portal's Go dependency and
   the exact version assertions in
   `backend/pkg/deployment/deployment_contract_test.go`. Portal must not use a
   local path, revision, or unreleased endpoint-set package for completed rollout.
2. Keep `CustomTunnelURL` and the `custom_tunnel_url` JSON/database field as the
   v1-only WebSocket value. Add a separate nullable canonical JSON column and API
   field named `custom_tunnel_endpoint_set_v2`; do not overload the legacy URL or
   infer raw QUIC/WebTransport readiness from it.
3. The registration write path passes the submitted v2 bytes through
   `endpointsetv2.DecodeJSON` with the current time before changing registry
   state, stores the exact canonical bytes, and records the endpoint instance
   update transactionally. During dual-write rollout, a request may update the
   legacy URL and the v2 endpoint set in one transaction, but neither field is
   synthesized from the other and a failure leaves both unchanged.
4. Environment and internal-region read APIs return both fields during the
   dual-read window. V1 issuance reads only `CustomTunnelURL`. V2 issuance reads
   and revalidates `custom_tunnel_endpoint_set_v2` at issuance time, calls
   `endpointsetv2.CompatibleListeners` with the exact requester capability
   descriptor, and converts only the returned tuple URLs or `advertised_url`
   values into ArtifactV2 candidates. Stale, unready, malformed, wrong-role, or
   empty intersections fail closed; they never fall back to v1 WebSocket inside
   a v2 artifact.
5. Split Portal's current single-URL `pickTunnelForChannel` and legacy
   `TunnelURL` channel-init path by artifact generation. The v1 path remains
   unchanged. The v2 path issues the canonical candidate array, endpoint instance
   identity, listener audience, and exact role/path/profile bindings; it must not
   squeeze a v2 endpoint set back into the v1 `TunnelURL` field.
6. Database migration tests cover create, update, concurrent registration,
   rollback, null v2 state, canonical-byte preservation, and no automatic
   backfill from legacy URLs. Route and control-plane tests cover both session
   roles on one physical listener, mixed-carrier candidate issuance, freshness
   expiry between registration and issuance, and fail-closed empty intersection.
7. Rollback disables v2 issuance but retains the v2 column and registration data
   through the maximum artifact/grant lifetime. V1 continues from
   `CustomTunnelURL`; deleting or rewriting v2 state is a later audited cleanup,
   not part of the emergency rollback.

### Browser Boundary

`floe-webapp` keeps `ProtocolProvider`, `RpcProxy`, the Service Worker, and the controller bridge as its product integration boundary; the explicit asynchronous disconnect change is described below. It receives one connecting state while the Flowersec browser adapter starts equal WebSocket and WebTransport candidates at the same credential-free barrier, commits exactly one winner, and closes losers before they can write FSB2. `detectBrowserRuntimeCapabilityV2(...)` removes WebSocket or WebTransport tuples when the corresponding browser constructor is unavailable. Missing browser transport support is an explicit capability result, not a hidden preference for another carrier.

### Browser Application Adapter Contract

The v1 `Client` and v2 `SessionV2` are not assignment-compatible. The
`floe-webapp` integration therefore uses one version-owning adapter between
`ProtocolProvider` and Flowersec instead of casting a v2 session to `Client`.
The v2 `ProtocolContextValue` deliberately replaces `client(): Client | null`
with `session(): SessionV2 | null`; product code that only needs RPC continues
to use the stable application-owned `rpcTransport`. `ConnectConfig` is no
longer an alias for the v1 `BrowserReconnectConfig`. Its v2 replacement owns an
`ArtifactSourceV2`, acquisition context, `SessionAutoReconnectConfigV2`, and
browser connector options. The adapter derives the actual browser capability
descriptor and constructs `SessionReconnectConfigV2`; its `connect` callback
calls `connectBrowserSessionV2(lease, { ...connectorOptions, signal })` and
returns the result's session. This keeps artifact acquisition and candidate
selection inside released Flowersec contracts instead of rebuilding either in
the application.

Choose exactly one lifecycle owner:

- The normal auto-reconnect path owns one `SessionReconnectManagerV2` for the
  provider lifetime. `ProtocolProvider` subscribes to manager state, maps its
  `session` field to the public state, and attaches `session.rpc` to `RpcProxy`
  only on a new `connected` generation. The manager alone observes
  `waitClosed()`, classifies terminal errors, schedules retries, and aborts
  acquisition, candidate racing, and backoff. The provider must not start a
  second termination observer or retry loop.
- A raw `BrowserSessionConnectorV2` path is allowed only when automatic
  reconnect is disabled. In that path the adapter owns the operation abort
  controller, one monotonic generation, and exactly one `waitClosed()`
  observer. It publishes the terminal result but never creates a reconnect
  manager for the same session.

For either path, detach `RpcProxy` before user disconnect, hard replacement, or
terminal publication. Detachment prevents new RPC calls and notifications from
reaching a draining session while preserving notification registrations for
the next attachment. Attach a replacement only after its authenticated READY
boundary and only if its generation remains current. A stale completion must
not attach, detach, or overwrite a newer session.

This migration intentionally changes the v2 adapter's disconnect contract to
`disconnect(): Promise<void>`. It aborts any acquisition, candidate race, or
backoff first, detaches RPC synchronously, then awaits the idempotent
`SessionV2.close()`. The adapter publishes `disconnected` only after that
promise settles. UI event handlers may start the promise without blocking
rendering, but lifecycle owners and tests must retain and await it before
disposing the controller or starting an operation that requires completed
cleanup.

`SessionV2.close()` is bounded by the configured session close deadline.
Flowersec carrier implementations perform graceful close within the remaining
budget and then trigger their synchronous, idempotent `abort` primitive. A
custom TypeScript or Swift carrier must implement that primitive so pending and
future open, accept, read, write, reset, and close operations settle even when
peer cleanup hangs. Go custom carriers provide the equivalent guarantee through
`CloseWithErrorContext(...)`: when it returns, including after context expiry,
the carrier is locally unable to open or write. Application adapters must not
add an application-only timeout that returns early while Flowersec still owns
live waiters or capacity.

Stream migration is explicit. V1 `openStream(...)` returns a Yamux stream;
Transport v2 returns the carrier-neutral `ByteStreamV2`/`ByteStream`. The
open/accept contract carries bounded metadata, while the byte stream exposes
the logical ID, asynchronous FIN (`closeWrite`), reset, close, and chunked read
semantics. Update proxy and custom-stream adapters to those operations or wrap
them behind an application-owned neutral stream interface. Do not cast a v2
byte stream to a Yamux stream, pass Yamux tuning through the adapter, expose
native QUIC stream IDs, or open the reserved RPC stream manually.
`SessionV2.rpc` owns the persistent RPC stream for every carrier.

Connection errors cross the adapter without string parsing. The adapter maps
Flowersec's high-level `{ path, stage, code }` fields to its public error state,
preserves the original error as the cause, and retains bounded per-candidate
diagnostics for logs. Go reads those observations from
`fserrors.Error.Diagnostics` as `fserrors.CandidateDiagnostic` values;
TypeScript reads `FlowersecError.diagnostics` as
`FlowersecCandidateDiagnostic` values. Candidate IDs and messages are never
metrics labels. The adapter must not infer retryability from the message,
carrier, or candidate order. Explicit user cancellation becomes
`disconnected`; codes listed in `reconnect_terminal_codes` become terminal
errors; other registered connection failures may enter automatic reconnect.
Candidate failures remain diagnostics for the one visible connection attempt
rather than separate UI errors. The registry permits `reconnect` for lifecycle
errors emitted by a reconnect layer, but a connector preserves its actual
`validate`, `connect`, `attach`, `handshake`, or `close` stage.

## Runtime Handling

Capability negotiation uses flat exact tuples of carrier, network mode,
session role, and one path. All SDKs use the canonical codec and digest vectors
in `testdata/transport_v2/capability_vectors.json`; a missing tuple is
unsupported. In particular:

- Browser TypeScript may dial WebSocket or WebTransport and may use either endpoint session role on a tunnel path; it cannot listen or use raw QUIC.
- Node.js currently advertises no Transport v2 carrier. Existing Node WebSocket utilities are v1 or generic transport helpers; the npm package has no committed production v2 WebSocket admission/carrier adapter and no production-grade QUIC or WebTransport runtime.
- Rust currently advertises no Transport v2 carrier tuple. Its tested raw QUIC
  adapter must be reported as `rust_transport_v2_connector_not_committed` until
  the complete ArtifactV2 acquisition, equal-candidate race, durable-spend, and
  server admission paths exist. Its carrier-neutral Yamux adapter is also not a
  production path-specific WebSocket admission and carrier adapter.
- Swift currently advertises no Transport v2 network carrier. Its portable protocol/session implementation is not a deployable capability until a production WebSocket adapter is committed; raw QUIC and WebTransport also remain blocked by the registered Network.framework constraint.

Do not hide an unsupported runtime by silently selecting WebSocket while reporting QUIC support. The control plane must avoid issuing candidates outside the declared tuple set.

## Application Changes

Replace Yamux-specific options and public stream types with the transport-neutral v2 session and byte-stream contracts as they become available. RPC, proxy, and custom-stream call sites should not select a carrier or inspect native stream identifiers.

Every downstream carrier adapter must report the exact physical inbound
bidirectional-stream capacity. Bind it to `N + 2` and reject a mismatch before
the control stream, FSC2/FSH2, or credential transmission; `N = 1` is the
minimum conformance case.

Bind `ArtifactV2.session.idle_timeout_seconds` to the Session v2 watchdog. A zero value disables idle expiry; positive values expire only after no authenticated control or stream record has been sent or received for the full interval. Session shutdown is also bounded, and downstream lifecycle code observes the authoritative termination signal (`Termination()`/`WaitClosed(ctx)` in Go, `termination`/`waitClosed()` in TypeScript, `wait_closed()` in Rust, and `waitClosed()` in Swift) rather than polling carrier state. TypeScript automatic reconnect requires a refreshable artifact source and reacquires a fresh lease on every attempt; a serialized one-time artifact cannot be recycled by starting another connection. Each fetch receives an `ArtifactAcquireContextV2` containing the Transport v2 version policy, exact runtime capability descriptor, and its canonical digest, so Portal does not reconstruct SDK capabilities.

### Downstream Acceptance Gates

The migration is not complete until the affected downstream repository passes
its focused adapter tests in addition to Flowersec's release gates.

`redeven-portal` must demonstrate that:

- artifact issuance uses the exact requester, endpoint, tunnel, and runtime
  capability intersection and never rewrites an unsupported candidate to
  WebSocket;
- v1 and v2 credentials, pending/spent transitions, replay records, and
  rollout cohorts remain version-isolated across success, cancellation,
  ambiguous first-write failure, and rollback;
- registered `{ path, stage, code }` failures and bounded candidate diagnostics
  survive its API boundary without message parsing or unbounded labels.

`redeven` must demonstrate that:

- its native adapter consumes `SessionV2` and `ByteStream` without Yamux types
  or options, and the same application RPC and custom-stream workflows pass on
  WebSocket, raw QUIC, WebTransport, and every supported mixed tunnel path;
- termination drives reconnect and authority handoff, a terminal error does not
  reconnect, and every retry acquires a fresh artifact lease;
- disconnect, replacement, peer loss, and a hanging graceful close all finish
  within the configured deadline with no active stream, task, file descriptor,
  or authority-generation residue.

`floe-webapp` must demonstrate in a real browser that:

- `ProtocolProvider` publishes one `connecting` lifecycle while equal
  WebSocket and WebTransport candidates race, attaches `RpcProxy` only after
  READY, and preserves notification subscriptions across a successful
  reattachment;
- disconnect, terminal completion, rapid reconnect, and stale completion obey
  the generation and attach/detach ordering above, and callers can await the
  new asynchronous disconnect contract;
- RPC, Service Worker, controller bridge, proxy streams, and custom
  `ByteStreamV2` FIN/reset behavior remain correct for both winning carriers;
- error-state tests assert registered `path`, `stage`, and `code` values,
  terminal-versus-retry behavior, and immediate cancellation during candidate
  racing and reconnect backoff.

Carrier-specific deployment settings remain at the edge:

- WebSocket keeps TLS, Origin, upgrade, path, and subprotocol configuration.
- Raw QUIC keeps UDP exposure, server certificate/private-key material, explicit non-empty client trust roots, path-specific ALPN, connection-ID-aware routing, and migration-safe stateless reset/token keys.
- WebTransport keeps trusted HTTP/3 server certificate/private-key material, explicit non-empty client trust roots, Origin policy, and path routing.

## Rollback

Rollback stops new v2 artifact issuance and requests fresh v1 credentials. It never reuses a previously spent v1 or v2 artifact. Existing v2 sessions drain until their bounded lifetime ends, after which v2 listeners and UDP exposure can be removed.

Keep the dual-stack control plane, replay records, and listener separation in place for at least the maximum artifact and grant lifetime. A rollback is a version-policy change, not a promotion of WebSocket to a permanent primary carrier.

## Verification

Before enabling a cohort:

- Validate the contract with `cd tools/stabilitycheck && go run . verify-parity`.
- Run the shared wire vectors and transport-neutral model tests.
- Require final-SHA raw QUIC, WebTransport browser, mixed-tunnel, weak-network, resource, and performance evidence.
- Confirm the capability registry and deployed listener readiness match exactly.
