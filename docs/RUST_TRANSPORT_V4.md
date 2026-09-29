# Rust transport v4 direct WSS

`V4ContractAcceptance` validates finite local contract snapshots. The default is
exact acceptance. `V4ContractRange` selects a closed range through
`V4ContractRangeField` for history retention, result retention or response
limits; at most four distinct supported fields are permitted. Bounded updates
compare every unlisted canonical field and reject missing or unsupported
fields with `V4ContractPolicyRejected`. This value performs no remote acquisition
and does not itself create a managed service binding.

`V4TransportEnvironment::close` seals the original root and returns
`Result<CleanupStatus, SessionError>` after its bounded cleanup observation.
`cleanup_incomplete` preserves actual native references and resource charges;
later `cleanup_status` can converge to completion. `wait_cleanup` also bounds
an observation made before close without changing the Environment's lifecycle.

`V4TransportEnvironment::connect_pool_wss` is the production Rust client entrance
for one direct network WSS candidate, preauthorized pool consumption and the
transport application profile. It negotiates no optional features. Both
X25519/ChaChaPoly and P-256/AES-GCM Noise profiles are implemented.
`connect_pool_wss_with_handler_plan` captures an Environment-bound
`V4HandlerPlan` and caller-supplied `V4ApplicationLimits` before irreversible
pool consumption. The same frozen manual or registered raw-stream dispatch
used by Serve is attached before the Connect Session is returned. Invalid or
closed plans fail before spend. Session termination seals new callbacks, waits
for admitted handler work to exit, then confirms the original application
charge; a caller's canceled wait cannot refund that work.

## Original owner composition

1. Construct `V4TransportEnvironment` with an explicitly trusted interval time
   source and finite root, tenant and Session capacities.
2. Generate an original identity handle with `identity_keys`. Provision its
   public signing and Noise keys through the application control plane. The
   private key material is not exported.
3. Construct a namespace with independently trusted authority roots. Bootstrap
   it using its fresh nonce, signed response and complete state. Retain and
   refresh this same namespace handle through the connection lifetime.
4. Pass exact Artifact, client/server certificates and pool activation bytes
   into `pool_connection_material`. Verification fixes the original Environment,
   candidate, route, identity, activation and authorization subscriptions.
5. Open the Environment-owned SQLite pool backing with an independent trusted
   continuity adapter. A restored database or newer competing fencing epoch
   cannot supply the original consume continuation.
6. Call `connect_pool_wss` with one numeric IP address and bounded provider
   capacities. A Tokio multithread runtime is required. TLS and WebSocket prepare
   finish before the irreversible pool transaction. Fixed handshake, key tables,
   rekey/stream backing and future Session/receiver positions are also reserved
   before consume. The original winner then sends HELLO and FSB, authenticates
   FSA, completes Noise and both READY obligations, and publishes `V4Session`.

There is no system wall-clock fallback, platform CA fallback, DNS retry,
redirect or post-consumption candidate change. Namespace verification order is
stable under concurrent material creation. Call cancellation, carrier loss,
fencing, authorization and original deadlines remain effective through READY.

## Accepted server and durable admission

`V4TransportEnvironment::serve_pool_wss` constructs a direct WSS server using
`V4WssServerIdentity`, `V4WssServeOptions`, independently trusted namespace and
identity handles, `V4AcceptedMaterialSource`, and `V4SQLiteAdmissionAuthority`.
The material source receives bounded unauthenticated HELLO bytes for lookup;
its answer is independently verified before admission. TLS, route, Origin and
both READY obligations use the original accepted connection.

The required `V4ServeCallbacks` are fixed in `V4WssServeOptions` along with
`V4ApplicationLimits` and a parent cancellation token:

1. `authorize_request` receives a bounded `V4ServeRequestContext` after native
   HTTP policy validation and before WebSocket upgrade. Its method, target,
   authority, Origin, headers and socket addresses are not peer authentication.
   Cancellation and the original handshake deadline signal the same callback;
   the accepted position remains charged until that future actually exits.
2. `resolve_handlers` receives only the verified `V4AuthenticatedRequestContext`
   after FSB signature, identity and binding checks. Its `binding()` is detached
   inspection data, not admission or replay authority.
3. `authorize_application` reserves exactly one application lease using
   `context.reserve_lease(context.binding(), lease)` as soon as reserve succeeds,
   including late success. It returns `V4AuthorizeApplicationResult`. Only an
   authorized result with a registered lease and a captured plan may reach the
   durable CAS. Rejection, panic, unknown and cancellation retain cleanup duties
   without publishing a Session. Cancellation claims lease Close exactly once,
   including while the original authorizer is still running.
4. `on_session` runs once after both READY obligations and the Serve publication
   gate. Its callback position is claimed before publication; later Drain or
   Close cannot withdraw that delivery. `V4SessionAcceptance::Retained` means the
   callback kept the Session; `Queue` transfers it to `V4ServeHandle::accept`;
   `Rejected` closes it. Registered handlers may run after publication while
   this callback is pending. A delivered Session may already be closing.
5. `release` runs once with `V4ServeReleaseContext` after core/provider cleanup
   and application callback exit, or an explicit incomplete observation at the
   original cleanup deadline. The original lease is closed before its cleanup
   is observed. An incomplete lease observation may be repeated serially;
   Release is never repeated. An incomplete Release or error is terminal and
   retains the original capacity, without granting new authorization.

Callbacks execute outside SDK gates. Keep a callback future pending until its
owned work exits; independently retained application work must belong to the
registered lease. Error cleanup snapshots are observations, not registrations
of new background work. Lease cleanup must be able to finish after its own
Close without waiting for Release to start. `ServeError` contains only a finite
code and cleanup snapshot; application error strings are not propagated.

Create an immutable `V4HandlerPlan` with `V4TransportEnvironment::handler_plan`
and `V4HandlerPlanOptions`. `V4StreamDispatch::Manual` gives the application
explicit `next_open` ownership. `Registered` freezes at most 128 unique raw kinds,
optional `V4RawStreamMetadataContract` projections and `V4RawStreamHandler`
implementations. It owns the only inbound dispatcher; public `next_open` cannot
compete. Unknown, invalid-metadata and excess requests are rejected locally.
The handler authorizer returns `V4StreamAuthorization`; successful handlers
retain the original FIN through completion, while handler failures reset only
that Stream. Closing a plan seals future captures; existing Sessions keep their
captured declarations. The last plan/capture drop releases its backing.

Application limits reserve one control callback, one protected cleanup callback,
one dispatcher and 1–128 ordinary callbacks from the original Session account
before CAS. Each ordinary/control byte budget is 256 bytes through 1 GiB;
registered dispatch requires at least 32 KiB per ordinary callback. Callback
tasks, completed-but-uncollected JoinSet entries and original cleanup tails
remain bounded. Drain seals new callback admission inside the Session drive
gate and waits for admitted ordinary work. Cleanup also waits for the original
maintenance worker to return its task charge. Parent cancellation closes an
idle listener as well as existing children; it does not close the Environment.

`V4SQLiteAdmissionBinding` fixes the trusted tenant, issuer, server identity and
audience mapping. Consumer spend, ParentWinner and AdmissionLedger are separate
durable facts. SQLite format revision 2 has manifest, spend, parent_winner and
admission tables. The original reserved-to-admitted CAS and fencing epoch govern
the once-only continuation; restart, replay, an equal credential or a different
connection cannot acquire it. `V4PoolStoreFailure::AdmissionConflict` and
`V4PoolStoreFailure::WinnerConflict` distinguish the rejected durable facts.

`V4ServeHandle::local_address` observes the listener. `accept` yields only a
fully authenticated Session. `drain` seals ingress and pending publication,
starts the admitted Sessions' original Drain, and returns the same
`V4ServeDrainOperation`. Its `result` and `wait`, and the handle's `wait_drain`,
expose `V4ServeDrainResult`: `outcome` distinguishes pending, drained,
deadline-aborted and failed; `error` preserves the first stable child failure;
`cleanup` observes current physical cleanup independently. All children share
the first absolute group deadline; an earlier child deadline is preserved.
Repeated Drain and canceled waits cannot extend either deadline or reopen
admission. Explicit Close forces a pending group to failed.

`close`, `cleanup_status` and `wait_cleanup` retain actual worker and native
tails. The cleanup observation window starts at final shutdown and is never
extended; incomplete cleanup keeps the original resources charged until work
exits. Drain and cleanup waits return `Result`, share sixteen prepaid observer
slots and use the original pump's wakeups. An excess pending wait returns
`V4ConnectError::Capacity`; dropping a wait releases only that observer.
Terminal observations need no slot. Serve never closes the shared Environment
or durable stores.

## TLS and carrier

The numeric address is separate from the signed host. Signed DNS names remain
the SNI, hostname-verification and HTTP Host identity; numeric signed hosts must
match the selected address. The path, ALPN and subprotocol are exactly
`/flowersec/v4/direct`, `http/1.1` and `flowersec.direct.v4`. The actual Origin
must satisfy the signed policy. TLS is restricted to TLS 1.3, resumption and
early data are disabled, and the actual peer socket tuple is checked.

Set `binding_mode` in both `V4WssConnectOptions` and `V4WssServeOptions` to
`V4BindingMode::DirectExporter` or `V4BindingMode::AuthenticatedContext`.
The former derives exactly 32 bytes from the actual rustls connection using
`EXPORTER-flowersec-v4` and the verified Artifact digest. The client completes
this step before durable consume. The accepted server reads and retains the
original bounded ClientHello, derives from its own TLS connection, and verifies
the resolved material's digest before admission. That HELLO is delivered once
to the existing admission owner. The mode is fixed through negotiation,
TransportContext and FSB/FSA; missing exporter support never triggers fallback.

CA mode uses only explicit DER roots and validates the chain/SAN against both
ends of the trusted time interval. Pin mode validates the actual complete leaf
DER SHA-256, its signed interval, actual X.509v3 P-256 key and positive lifetime
of at most fourteen days. It does not add CA/hostname authority or fall back to
CA verification. The selected actual certificate interval remains live.

A bounded native I/O thread owns each independent TLS/WebSocket connection.
The Session publisher waits for actual ordered WebSocket send completion, with
a fixed publication deadline. Input/output queues and frames have finite caps;
preauthentication I/O is metered before native reads/writes. Logical close
cancels the original worker, while cleanup waits for the worker and receiver to
exit. Retained queues, tasks and native backing remain charged during that tail.

## Stream and lifecycle surface

`V4Session` provides `open_stream`, `next_open`, `probe_liveness`, `rekey`,
`drain`, `wait_termination`, `close`, `cleanup_status` and `wait_cleanup`.
`V4OpenRequest` transfers one pending OPEN decision. `V4Stream` implements
`ByteStream`, preserving explicit half-close, reset, prepared writes and reader
cursor ownership. The first Drain fixes its boundary and deadline; repeated
calls observe that original operation. Unread graceful bytes remain owned until
read or explicit abandonment. Slow consumers terminate the affected direction.

`probe_liveness` uses one of eight independent, finite Session owners. Its
original deadline starts at admission and is capped at ten seconds. `V4ProbeResult`
preserves the fixed outcome, irreversible record-ticket `submitted` fact, actual
provider-handoff `complete` fact observed before that outcome, and elapsed time
from admission, including local queueing. A dropped waiter releases its matcher
without waiting for the synchronous provider; the original reservation remains
owned until actual publication exits. Trusted-clock discontinuity produces
`TimeUnavailable`, and elapsed time is unavailable when it cannot be measured
on the original clock. Rekey intent interrupts probes before waiting for a new
round. Ordinary PONGs can use the legal old maintenance gate, while candidate
epoch sequence zero is reserved for COMMIT/ACK.

`TransportEnvironmentOptions::automatic_liveness` is disabled by default. An
explicit `V4AutomaticLivenessPolicy` fixes `interval_ms`, `submission_ms`,
`response_ms` and `miss_threshold` before Session admission, and prepays one
protected owner within the eight-slot bound. A miss requires actual complete
PING publication within the submission budget and a full response interval,
without rekey or known local resource, read or write stalls. Actual native
queue stalls remain visible even when they clear before the Session runs again.
Only a successful automatic PONG or completed rekey resets consecutive misses.
The threshold closes the original Session with `LivenessPathUnresponsive`;
ordinary caller cancellation or timeout does not. This policy observes the
authenticated maintenance path and does not prove peer application health or
authorize business replay.

`close_write` seals new send admission in the original direction. The Session
driver retains FIN publication when its waiting future is dropped. `finish`
requires the real FIN and an authenticated normal DRAINED proof; Reset and
aborted proofs cannot satisfy it. Ordinary writes may return a bounded accepted
prefix, so callers continue only with their remaining suffix.
`V4Stream::wait_peer_authenticated` observes an already accepted absolute byte
offset, with at most four waits per Stream and 64 per Session. ACK and normal
DRAINED advance that observation; aborted final offsets do not. Fulfilled
observations remain available after retirement and do not prove peer application
consumption.

SQLite consumption is synchronous, bounded and durable with WAL/FULL settings.
`V4PoolStoreError` preserves `NotSubmitted`, `Committed` or `Unknown` write
state. After explicit successful consume, a later failure becomes
`V4ConnectError::Spent(V4PostSpendFailure)`. No error, reopened database, query,
matching credential or new connection can adopt the old activation.

Persistent SQLite backing remains charged after store close. The host must
remove the database and sidecar files before calling `release_removed`.
A continuity adapter must independently detect rollback/history replacement;
an always-success adapter is not a production history guarantee.

## Current boundaries

`ResourceLimits` has eleven independent dimensions in the fixed
`ResourceLimits::DIMENSIONS` order: `sdk_bytes`, `provider_bytes`, `disk_bytes`,
`items`, `work_slots`, `tasks`, `timers`, `connections`, `tls_handshakes`,
`sessions` and `native_handles`. Arithmetic is checked and reservations are
atomic across the original root, tenant and Session chain. A zero dimension
rejects the corresponding allocation; another dimension cannot supply it.
Splitting a reservation changes only its ownership, never aggregate capacity.

WSS charges SDK message queues separately from TLS/runtime/stack provider
backing. It reserves the connection, handshake, native handles, tasks and timers
before dialing. The handshake slot returns only when the exact preparation
future exits. Remaining native ownership returns after physical worker/receiver
cleanup. SQLite keeps provider runtime separate from SDK metadata and retained
database/journal disk bytes; closing the database releases the live provider
but not its persistent backing. Record keys, rekey/stream geometry, pending
items and deadline positions are reserved together before irreversible spend.
Prepared writes split their actual timer and running task tails from metadata.

Full provider/deployment qualification remains unfinished. These finite local
caps are not claims about total process RSS, unobservable host allocations,
full reference-profile concurrency or the unsupported application assemblies.

These entrances do not implement issuer, candidate racing, live-authority activation, tunnel,
raw QUIC, WebTransport, datagrams, v4 RPC/services/notifications or a v4
connection controller. Unsupported combinations are rejected before spend.
The existing unversioned connector/server/application APIs retain their stated
strict-v3 behavior and do not silently switch wire protocols.

Real local TLS/WSS tests cover CA and DER pin modes, both Noise profiles,
SQLite consume, exact handshakes, dual READY, encrypted streams, rekey, PING/PONG,
Drain and physical cleanup. Wrong TLS pins and insufficient fixed resource
capacity leave the pool unspent. Cancellation after HELLO remains spent.
Real server tests also cover both Noise profiles, TLS CA/pin, replay and restart
rejection, pending Drain/Close, cancellation at durable commit, and cleanup.
These checks do not qualify unsupported carriers or application profiles.
