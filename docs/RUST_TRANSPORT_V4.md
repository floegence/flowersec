# Rust transport v4

`ContractAcceptance` validates finite local contract snapshots. The default is
exact acceptance. `ContractRange` selects a closed range through
`ContractRangeField` for history retention, result retention or response
limits; at most four distinct supported fields are permitted. Bounded updates
compare every unlisted canonical field and reject missing or unsupported
fields with `ContractPolicyRejected`. This value performs no remote acquisition
and does not itself create a managed service binding.

`TransportEnvironment::close` seals the original root and returns
`Result<CleanupStatus, SessionError>` after its bounded cleanup observation.
`cleanup_incomplete` preserves actual native references and resource charges;
later `cleanup_status` can converge to completion. `wait_cleanup` also bounds
an observation made before close without changing the Environment's lifecycle.

`TransportEnvironment::connect` is the current Rust client entry point. It
accepts one captured `ConnectionMaterialSource`, a semantic
`ConnectionRequest`, and the caller's original cancellation token. The source
owns its verified material generation, identity, provider, and spend owner;
one call performs one Acquire and then uses the same winner, authorization,
activation, and READY path. Applications that need managed replacement use
`MaterialConnectionController`, which calls this entry point for each new
original generation.

`TransportEnvironment::connect_pool_wss` remains the explicit lower-level
entry point for one direct network WSS candidate, preauthorized pool
consumption, and the transport application profile. Feature negotiation
intersects the original signed policy, application profile, and selected
provider capability. Both X25519/ChaChaPoly and P-256/AES-GCM Noise profiles
are implemented. `connect_pool_wss_with_handler_plan` captures an
Environment-bound
`HandlerPlan` and caller-supplied `ApplicationLimits` before irreversible
pool consumption. A HandlerPlan's ServicePlan is also reserved before Prepare
and irreversible authorization, then installed on the original private paused
Session before actual local READY publication. The handshake retains the peer
READY verifier and original authorization gate until both obligations complete;
failed or canceled preparation closes that same Session. RPC bootstrap and
service streams cannot publish while the protocol is paused. The returned
Session exposes those exact graphs through `configured_services`, without
creating a second bootstrap lane. The same frozen manual or registered raw-stream dispatch
used by Serve is attached before the Connect Session is returned. Invalid or
closed plans fail before spend. Session termination seals new callbacks, waits
for admitted handler work to exit, then confirms the original application
charge; a caller's canceled wait cannot refund that work.

## Original owner composition

1. Construct `TransportEnvironment` with an explicitly trusted interval time
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
   FSA, completes Noise and both READY obligations, and publishes `Session`.

There is no system wall-clock fallback, platform CA fallback, DNS retry,
redirect or post-consumption candidate change. Namespace verification order is
stable under concurrent material creation. Call cancellation, carrier loss,
fencing, authorization and original deadlines remain effective through READY.

`Namespace::refresh` preserves the current complete Head/State pair within its
original validity while a newer pair awaits time proof or complete State.
Independently verified, mature Head floors immediately reject the affected
credential class; missing State does not defer those denials or revoke unrelated
credentials. Pending candidates retain their original deadline. After expiry,
a newer pair can be verified independently, without reviving the old candidate.

SQLite pool and relay transaction groups inspect the bounded manifest header,
installed identity and matching physical revision before selecting a record
reader. They validate the complete current schema and stored state in a read
transaction before changing database configuration, checkpointing or advancing
the epoch. A refusal exposes `PoolStoreError.format`, whose fixed projection
identifies the transaction group, required revision and finite reason through
`storage_format_incompatible`. Observed revision is present only when the
manifest schema, stored header, identity and SQLite revision agree. Independent
groups retain their normal lifecycle. No exact converter is provided and opens
never migrate or clear an incompatible group.

## Accepted server and durable admission

`TransportEnvironment::serve_wss` constructs a direct WSS server using
`WssServerIdentity`, `WssServeOptions`, independently trusted namespace and
identity handles, `AcceptedMaterialSource`, and `SQLiteAdmissionAuthority`.
The material source receives bounded unauthenticated HELLO bytes for lookup;
its answer is independently verified before admission. TLS, route, Origin and
both READY obligations use the original accepted connection.

Deployments that issue a signed route after binding can pass the same bound
socket to Serve: TCP through `serve_wss_on_listener`, and UDP through
`serve_raw_quic_on_socket` or `serve_webtransport_on_socket`. Each method checks
the socket address against `listen_address` and transfers socket ownership to
Serve. The deployment can keep one endpoint from route issuance through acceptor
startup without releasing the address. The handle reports the bound address and
retains the listener through its normal cancellation and cleanup lifecycle.

`authorization_profile()` is captured from trusted source configuration before
socket ingress and fixes `preauthorized_pool` or `live_authority`; the peer cannot
select or change it. Both use the same current credential verifier, original
admission binding, SQLite once ledger, Noise and dual READY publication path.

For live issuance, `live_accepted_material_source` creates a bounded volatile
server-local registry. The trusted original authority owner registers the exact
Artifact and identities before TxB and retains `OriginalLiveServerPublication`.
Only its explicitly confirmed original continuation calls `publish_original`.
The registry verifies the signed proof and original key/namespace closure,
then allows one matching HELLO to capture the material. Failed, expired or
consumed positions cannot be recreated by a receipt, status lookup or restart.
The independent SQLite admission tombstone survives source loss.

For a separate authority process, bind `serve_original_delivery` on the same
original source before issuance, with a dedicated `WssServerIdentity` and
`LiveServerDeliveryOptions`. The listener uses TLS 1.3 mTLS, configured client
roots, exact authorized client leaf digests, and the Environment interval clock.
It accepts one bounded HTTP/1.1 request per connection and has no redirect,
status, reopen, adoption or retry endpoint. Root/parent cancellation, certificate
expiry and explicit Close seal ingress and pending publication positions;
`wait_cleanup` observes retained native tasks for at most five seconds.

The original authority constructs `original_live_server_delivery` with a fixed
`ControlHTTPSConfiguration` whose base path is empty. Before TxB, it calls
`register_original` with the exact Artifact and identity certificates and keeps
the resulting non-cloneable `RemoteLiveServerPublication` in that invocation.
Only the explicitly confirmed original TxB continuation may consume
`publish_original`. It must receive the publication ACK before returning the
activation proof to the client. A lost reply is unknown and cannot trigger a
second publication, a status lookup or credential handoff. The recipient binds
the volatile capability to the registering mTLS identity, consumes it once,
and calls the same `OriginalLiveServerPublication` verifier used locally.

Tunnel issuance uses `original_live_tunnel_server_delivery` with separate,
fixed mTLS configurations for the original server recipient and RelayHost.
Both are built before TxB. `register_tunnel_original` binds the exact relay
certificate, service and audience in the non-cloneable publication capability;
it fails before TxB if the RelayHost recipient was not configured. The original
confirmed continuation calls `publish_tunnel_original` once with the exact
canonical relay preparation request, activation authorization and server-leg
Grant. It installs the server leg at `/tunnel/relay-server-grant` first and
requires that ACK before publishing the same activation and Grant to the
original server recipient. Only after both ACKs may the authority return the
client authorization. An uncertain response consumes the capability; it has no
retry, query, reopen or outbox path. The recipient verifies the publication
under the same live verifier before enqueueing the non-cloneable
`OriginalLiveTunnelServerMaterial` for `LiveServerDeliveryHandle::next_tunnel_publication`.
This owner retains its verified Account and storage through the queue. The
`serve_original_live_tunnel_material`,
`serve_original_reverse_live_tunnel_material`, and
`serve_original_live_tunnel_material_on_original_listener` entry points consume
that owner directly; they check the installed identity, namespace owners,
service and audience without recreating an Account from detached bytes.
The delivery-consuming Serve entry points use the same handoff. Only one
original invocation may wait on the delivery queue at a time; another caller
receives a capacity error before allocating a waiter.

For a registered JSON control deployment, A constructs
`RegisteredLiveTunnelSourceConfiguration` from its independently installed
original Artifact, identities, namespaces, provider and control authority.
`LocalDirectMaterialSource::registered_live_tunnel_authority` and
`registered_live_reverse_tunnel_authority` consume that Artifact once through
ordinary Acquire. The original material retains one Account, random attempt,
immutable cutoff and canonical authorization request through native Prepare,
signed `live_client_prepared`, signed `live_authorize` and exact activation/Grant
digest handoff. Forward and reverse preparation keep the same physical carrier
or original listener. Failure or withdrawal terminates the registration and
cannot authorize another nonce, retry or Acquire of the installed Artifact.

An independently installed external RelayHost uses the root HTTPS
`relay_preparation` configuration in A's tunnel control. A sends reverse
listener readiness, canonical preparation and its original activation/client
Grant to that receiver using the same mTLS identity as registered authority
control. The authority delivers the server Grant through its own fixed issuer
identity inside the original TxB invocation. A completes registered digest
handoff only after the relay's original activation acknowledgement; interrupted
control permanently retires the attempt. Both the HTTP driver and every final
request-body view retain the original Account, transport prepayment and control
position until release.

B retains `OriginalLiveTunnelServerPublication` before control registration.
`register_original_control` takes
`RegisteredLiveServerControlConfiguration` and one
`RegisteredLiveServerPreparation` carrier or listener. Registered control and
local physical preparation run concurrently under the same cancellation owner.
The optional `relay_preparation` fixes B's external RelayHost recipient and must
use B's same registered mTLS leaf. B announces only its actually bound reverse
listener; this message cannot publish a Grant or replace the original listener.
The registration retains its Account and source position through all original
registered and relay HTTP writers. After both preparations complete,
the capability is a
`RegisteredLiveTunnelServerPublication`. `receive_original_publication` binds
the authority's attempt on that registration, confirms its reservation,
receives the original signed activation and server Grant, verifies them on the
same Account, and acknowledges their exact digests before returning the material
to Serve. No A response supplies B's Grant. The fixed JSON mTLS endpoint remains
`/flowersec/control/live`; its writer retains original control backing through
actual driver and last request-body release, and request scratch is cleared on
release. The original B registration position remains counted and cannot be
reused while any driver or body view retains it. Deadline checks precede request
handoff and follow the response read. Withdrawing a forward B preparation also
cancels an unobserved prepared result; raw QUIC, native WebTransport and WSS
retain their original physical join observations through real worker, handle
and thread exit before retiring the registration or its cleanup backing.

The client-facing `/live/authorize` response contains only the activation
authorization and client-leg Grant; the client never reads back the server
Grant. The client submits the exact same request and activation authorization
with its client Grant through `/tunnel/relay-activate-client`. The RelayHost
requires the installed server leg, verifies both grants as a pair, and opens
forwarding only after the client-leg ACK is written. Neither leg can be
replaced with different bytes or a new attempt. The channel is bounded by the
source's publication capacity and charged while queued. Receiving that value
consumes it; there is no status lookup, replay, or reopen operation.

Connect and Serve independently submit their own READY after graph installation
without first waiting for peer READY. Their private Sessions remain paused until
the original peer Ed proof and root MAC both verify; every error closes the
original prepared Session and retains its cleanup owner.

The required `ServeCallbacks` are fixed in `WssServeOptions` along with
`ApplicationLimits` and a parent cancellation token:

1. `authorize_request` receives a bounded `ServeRequestContext` after native
   HTTP policy validation and before WebSocket upgrade. Its method, target,
   authority, Origin, headers and socket addresses are not peer authentication.
   Cancellation and the original handshake deadline signal the same callback;
   the accepted position remains charged until that future actually exits.
2. `resolve_handlers` receives only the verified `AuthenticatedRequestContext`
   after FSB signature, identity and binding checks. Its `binding()` is detached
   inspection data, not admission or replay authority.
3. `authorize_application` reserves exactly one application lease using
   `context.reserve_lease(context.binding(), lease)` as soon as reserve succeeds,
   including late success. It returns `AuthorizeApplicationResult`. Only an
   authorized result with a registered lease and a captured plan may reach the
   durable CAS. Rejection, panic, unknown and cancellation retain cleanup duties
   without publishing a Session. Cancellation claims lease Close exactly once,
   including while the original authorizer is still running.
4. `on_session` runs once after both READY obligations and the Serve publication
   gate. Its callback position is claimed before publication; later Drain or
   Close cannot withdraw that delivery. `SessionAcceptance::Retained` means the
   callback kept the Session; `Queue` transfers it to `ServeHandle::accept`;
   `Rejected` closes it. Registered handlers may run after publication while
   this callback is pending. A delivered Session may already be closing.
5. `release` runs once with `ServeReleaseContext` after core/provider cleanup
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

Create an immutable `HandlerPlan` with `TransportEnvironment::handler_plan`
and `HandlerPlanOptions`. `StreamDispatch::Manual` gives the application
explicit `next_open` ownership. `Registered` freezes at most 128 unique raw kinds,
optional `RawStreamMetadataContract` projections and `RawStreamHandler`
implementations. It owns the only inbound dispatcher; public `next_open` cannot
compete. Unknown, invalid-metadata and excess requests are rejected locally.
The handler authorizer returns `StreamAuthorization`; successful handlers
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

`SQLiteAdmissionBinding` fixes the trusted tenant, issuer, server identity and
audience mapping. Consumer spend, ParentWinner and AdmissionLedger are separate
durable facts. SQLite format revision 2 has manifest, spend, parent_winner and
admission tables. The original reserved-to-admitted CAS and fencing epoch govern
the once-only continuation; restart, replay, an equal credential or a different
connection cannot acquire it. `PoolStoreFailure::AdmissionConflict` and
`PoolStoreFailure::WinnerConflict` distinguish the rejected durable facts.

`ServeHandle::local_address` observes the listener. `accept` yields only a
fully authenticated Session. `drain` seals ingress and pending publication,
starts the admitted Sessions' original Drain, and returns the same
`ServeDrainOperation`. Its `result` and `wait`, and the handle's `wait_drain`,
expose `ServeDrainResult`: `outcome` distinguishes pending, drained,
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
`TransportConnectError::Capacity`; dropping a wait releases only that observer.
Terminal observations need no slot. Serve never closes the shared Environment
or durable stores.

## TLS and carrier

The numeric address is separate from the signed host. Signed DNS names remain
the SNI, hostname-verification and HTTP Host identity; numeric signed hosts must
match the selected address. The path, ALPN and subprotocol are exactly
`/flowersec/v4/direct`, `http/1.1` and `flowersec.direct.v4`. The actual Origin
must satisfy the signed policy. TLS is restricted to TLS 1.3, resumption and
early data are disabled, and the actual peer socket tuple is checked.

Set `binding_mode` in both `WssConnectOptions` and `WssServeOptions` to
`BindingMode::DirectExporter` or `BindingMode::AuthenticatedContext`.
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

`Session` provides `open_stream`, `next_open`, `probe_liveness`, `rekey`,
`drain`, `wait_termination`, `close`, `cleanup_status` and `wait_cleanup`.
`OpenRequest` transfers one pending OPEN decision. `Stream` implements
`ByteStream`, preserving explicit half-close, reset, prepared writes and reader
cursor ownership. The first Drain fixes its boundary and deadline; repeated
calls observe that original operation. Unread graceful bytes remain owned until
read or explicit abandonment. Slow consumers terminate the affected direction.

`probe_liveness` uses one of eight independent, finite Session owners. Its
original deadline starts at admission and is capped at ten seconds. `ProbeResult`
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
explicit `AutomaticLivenessPolicy` fixes `interval_ms`, `submission_ms`,
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
`Stream::wait_peer_authenticated` observes an already accepted absolute byte
offset, with at most four waits per Stream and 64 per Session. ACK and normal
DRAINED advance that observation; aborted final offsets do not. Fulfilled
observations remain available after retirement and do not prove peer application
consumption.

SQLite consumption is synchronous, bounded and durable with WAL/FULL settings.
`PoolStoreError` preserves `NotSubmitted`, `Committed` or `Unknown` write
state. After explicit successful consume, a later failure becomes
`TransportConnectError::Spent(PostSpendFailure)`. No error, reopened database, query,
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
full reference-profile concurrency or deployment qualification.

The current direct assembly accepts signed WSS, raw QUIC and HTTP/3
WebTransport routes through `connect_pool_direct` and the SDK-owned material
Sources. `serve_wss`, `serve_raw_quic` and `serve_webtransport` share the original
credential verification, durable admission, independent READY publication,
application callbacks, configured service graphs and bounded Drain owner.
Native routes require sufficient reserved native backing and connection credit
headroom before spend. Forward and reverse tunnel Sources use the signed relay
legs, original HOP authorization and READY owner; reverse legs retain their
physical listener preparation. `Session::unreliable_messages` exposes the
negotiated datagram path on its original eligible native carrier and rejects
unavailable carrier combinations. Pool-backed connection assembly admits the signed candidate set, prepares at most
two finite candidates concurrently under the signed preauth budget, commits the
first ready carrier as the winner, closes and joins loser carriers before the
single pool spend, and binds the selected candidate into the spend projection.
Live authority material retains the candidate selected by its original verified
preparation and does not invent a second authorization or spend.

Local TLS/WSS test sources cover CA and DER pin modes, both Noise profiles,
SQLite consume, exact handshakes, dual READY, encrypted streams, rekey, PING/PONG,
Drain and physical cleanup. Wrong TLS pins and insufficient fixed resource
capacity leave the pool unspent. Cancellation after HELLO remains spent.
Real server tests also cover both Noise profiles, TLS CA/pin, replay and restart
rejection, pending Drain/Close, cancellation at durable commit, and cleanup.
These checks do not qualify unsupported carriers or application profiles.

`ConnectionController::capture_session` returns the current READY Session only
while its original dispatch gate remains eligible. It performs no acquisition or
OPEN and does not extend that Session's authority. Applications can capture once
and assemble a terminal, editor, notification subscription or Stream on that
fixed Session. Each later operation still checks the original Session's current
security and admission gates.

`replace_session_with_options` fixes `MaterialSessionRetirement::Drain` or
`Retain { retain_until_ms }` before source acquisition. Retain validates the
absolute cutoff against the old Session's trusted time and cannot extend its
security lifetime. A candidate becomes current only after READY, all configured
managed bindings and the initializer have succeeded. Ordinary replacement uses
Drain; `retain_replaced_for` selects a bounded retain cutoff for the convenience
`replace_session` entry. Retain leaves the old Session accepting until its fixed
cutoff or an earlier explicit Drain, Close or authority failure. The returned
`MaterialSessionReplaceResult` includes the previous owner and its observable
physical cleanup status. Existing operations, headers, Streams and unconfirmed
writes continue to belong to that previous Session.

Managed service replacement carries the previous verified contract snapshots
and method generations into the new binding. Exact acceptance requires the same
digest; bounded acceptance permits only its declared ranges. Publication checks
that the original source revisions have not changed during initialization.
Explicit `ServiceClient::refresh` installs a future binding under the same source
publication gate, with one deadline covering query, required pool readiness and
installation. Already prepared operations retain their original snapshot.

`ServicePeer::bind_selected` accepts `ServiceBindingSelection::initial_methods`.
The complete method definition and all local capacity reservations remain fixed;
unselected methods have no captured snapshot and return `NotReady` before
encoding. Explicit `refresh` can ready a deferred method.
`refresh_methods` accepts a bounded, duplicate-free known method list and returns
one result per method, preserving successful installations when another fails.

`ManagedServiceConfiguration::new` enables the default `ManagedOfferRenewal`.
The renewal worker reserves its task, timer and original Session cleanup tail
from binding prepayment. It renews only ready execution-method Offers through
ordinary exact-policy refresh; failure remains observable in `renewal_progress`
and never silently changes contract acceptance, reacquires material or replays
business. `close`, `cleanup_status` and `wait_cleanup` cancel and account for
renewal and in-flight explicit refresh through actual exit.

`ControllerServiceClient::with_method_source` explicitly assigns a bounded list
to a second existing Controller in the same Environment. Each source must have
the same complete method identities and authenticated logical authority; the
comparison binds both endpoint roles, tenant, subject, audience and verified
namespace authority independently of certificate renewal generations. Assigned
methods then capture their own source even while the other source is unavailable.

Queued Controller unary preparation encodes once and permits at most two
current-generation reselections, including changes while the original channel
publication is queued after `Start`. A scalar incarnation gate orders revocation,
actual native BEGIN acceptance and Close. A changed generation revokes the old
publication right before the new Session reserves its complete result and
completion owner. The original encoded bytes, header, deadline, response limit,
execution ID, request digest, captured Offer and reference remain fixed.
Selection never queries, acquires, re-encodes or extends authority. A confirmed
`NotSubmitted` receipt permits the next bounded choice; BEGIN acceptance,
uncertain publication, cancellation and exhausted choices seal that right.
Old channel callbacks retain their original Session backing through actual exit,
and CleanupStatus includes both retired callbacks and the current route. Fixed Session clients and pure local `TryNow` preparations keep
their original source. Saving an execution reference freezes that source before
the external persistence callback.

`ConnectionProgress::connection_facts` preserves detached spend, admission and
network READY evidence independently from application publication. A service or
initializer failure after READY therefore remains spent and READY, while
`application_publish` records failed or unknown initialization. Observing these
facts does not acquire material, issue a query or retry an operation.

Controller service facades capture an already bound ServiceClient and its
configured notification peer from one current generation. Unary, streaming,
notification and Resume preparations use that captured owner throughout awaits.
Queued unary preparation may select within its original pre-BEGIN bound as described above;
submitted operations never retarget their owner. A configured ServicePlan's original
query peer is reused for managed bindings; a different fixed query is rejected.
Notification unsubscribe closes future delivery while its finite subscriber
position remains occupied until the original decoder and observer exit.

`ProxyServer::stream_registrations` provides the current HTTP and WebSocket raw
Stream registrations for a HandlerPlan. Each original pending OPEN admits the
bounded body/frame/JSON buffers, native socket/work positions and a Session
cleanup descriptor before acceptance. Those resources follow the original DNS
worker and upstream socket through TLS, HTTP body/driver and WebSocket teardown;
handler return cannot refund a still-running native tail. The existing proxy
request authorization, headers, cookies, cancellation and network destination
policy apply on these current Streams.


Native direct transport uses one dedicated maintenance bidirectional stream for
handshake and scope-zero records, plus one original native stream for each
application OPEN/DATA scope. A first OPEN is authenticated before the original
native stream is bound. The local Session owner transfers its original binding
before releasing the publication gate; a provider cannot reconstruct a binding
from retired scope identifiers or untrusted record headers. Native input
positions and complete frame buffers are finite and separately charged.

Raw QUIC and WebTransport use the Environment trusted clock for actual TLS
verification. WebTransport uses its fixed native HTTP/3 CONNECT and stream
prefix mapping; CONNECT Origin is checked at the listener. Native provider
preparation creates only an empty maintenance stream before original
activation. Application bytes never use that maintenance stream.

Native EOF and normal-drained observations remain direction hints until current
maintenance authenticates the corresponding rejection or terminal frontier.
Abnormal native direction errors retain the opposite direction and maintenance
path. Native stream charges remain held through actual read/write and connection
observer exit. Sealing the native listener rejects new handshakes while existing
Serve children retain their original Drain and physical cleanup owners. Source
implementation does not establish runtime interoperability or provider
qualification; those checks follow the complete source-writing milestone.


## Unreliable native messages

`Session::unreliable_messages` returns the original Session's
`UnreliableMessages` channel when the signed feature intersection and actual
raw QUIC or HTTP/3 WebTransport connection support it. WSS reports unavailable.
`max_message_bytes` is a conservative local submission limit based on the
current native MTU and the complete 1024-byte Flowersec envelope bound. The
maximum application payload is 949 bytes.

`send` checks the caller's absolute expiration against the Environment's trusted
time. Its four normal outcomes are accepted, dropped_expired, dropped_budget and
dropped_carrier. Acceptance makes no delivery promise. The 64 pending positions
include the original native output buffers and hold their prepayment until the
provider actually releases those bytes. Neither an expired ticket nor a local
carrier drop returns consumed crypto usage or causes a retry.

Receive uses one current-epoch 256-bit replay window. Failed authentication
cannot move its frontier, and a full queue still consumes unique authenticated
replay acceptance. The channel keeps one inbound failure counter across wrappers
and rekeys: each eight actual failures pauses receive for one second; 32 disables
receive for the Session lifetime. Receive reports temporarily_blocked with a
remaining time only for a timed pause, or receive_disabled for the permanent
invalid-input guard. Exhausting only the current inbound key's open allowance
reports key_open_budget without a retry time. These guards preserve sending,
reliable streams and the Session. Rekey switches datagram keys only at its real
completion point and retains Session usage and guard facts. Invalid-only open
attempts do not independently request rekey.

## Managed notification roots

`ControllerServiceClient::subscribe_notification` creates a bounded local root
for one configured observation contract. It attaches to the configured peer of
each published current Session, without acquiring material or creating a second
service graph. Its snapshot identifies the generation, attachment and finite
service/controller failure. A failed attachment is retried only by a subsequent
publication; it does not replay an application request.

The root retains at most two original subscription positions during replacement.
Closing delivery does not release an observer still executing on the old
Session. If both positions remain occupied, the one local publication observer
waits for actual callback cleanup before attaching to the latest published
Session. Close and bounded cleanup observation retain the original captures and
charges through those exits.


## Original pool relay hosting

The original pool issuer calls `TransportEnvironment::relay_pool_publication`
with `RelayPoolPublicationInput`, exact paired Grants and certificates, and the
independently configured server admission authority. The verifier captures the
complete signed parent and namespace closure, then detaches only public facts.
`OriginalRelayPoolPublication` retains no Artifact, PSK, Noise secret or endpoint
admission capability. Its ownership cannot be reconstructed from public bytes
or a durable registration row.

`SQLiteRelayLedger` uses an Environment-owned `SQLitePoolBacking`, explicit
`SQLiteRelayOptions`, trusted continuity and independent `SQLiteRelayBinding`
entries. Its `parent_authority` is the common protected `SQLitePoolStore` used
by endpoint admission and pool selection. Registering a publication chooses no
winner and claims no leg. Only original HOP possession selects the immutable
parent winner and commits one logical A/B claim. Conflicting public selections,
reopen, newer fencing epochs and uncertain writes return no forwarding handle.

`TransportEnvironment::wss_relay_host` captures the relay identity, protected
ledger, `WssRelayHostOptions`, and independently installed
`WssRelayLegOptions::Dialer` or `Listener` for each physical leg. The signed
route fixes WSS, raw QUIC or HTTP/3 WebTransport and each physical direction.
`WssRelayHost::publish_pool` consumes one original publication. Both provider
prepayments, HOP/claim positions, meters, queues, native mapping positions and
the finite scope tombstone table are reserved before either leg prepares or
claims. The publication owns both original native futures and their cleanup.

For a separate relay process, `TransportEnvironment::original_relay_delivery`
creates `OriginalRelayDelivery` from a fixed `ControlHTTPSConfiguration`.
`register_pool_original` consumes the sealed original pool publication. Its
canonical public projection contains the exact activation, paired Grants and
certificates, the signed selection-set witness, the selected public Candidate
and SessionContract. It contains no Artifact, PSK, Noise secret or Session nonce.
`RemoteRelayPublication::start_original` consumes the original confirmed
registration continuation; an unavailable response is never retried.

The relay binds `WssRelayHost::serve_original_delivery` with
`RelayOriginalDeliveryOptions` and independently installed `RelayOriginalIssuer`
entries. Each exact mTLS leaf identifies one configured `SQLiteRelayBinding`
and namespace closure. TLS 1.3, roots, host, validity and the single-request
HTTP/1.1 protocol are fixed at deployment. The receiver independently verifies
public signatures, parent/delegation history, identity, selection, route,
SessionContract and namespace dependencies before protected registration. Only
that original authenticated request creates a volatile registration position;
public rows or token equality cannot recreate it. Start consumes the position
before host publication, retains actual cleanup ownership, and acknowledges
only after physical listener readiness and original dialer Prepare. Closing
`RelayOriginalDeliveryHandle` retires unconsumed positions and cancels original
running publications; `wait_cleanup` reports physical exit within its bounded
observation window. `WssRelayHost::publish_registered` also consumes an original
local registration directly. The mTLS control listener can take an already-bound
TCP socket through `serve_original_delivery_on_listener`; its actual local
address must match `RelayOriginalDeliveryOptions::listen_address`, and the
original listener remains owned until relay-delivery cleanup completes.

`serve_original_live_control` installs bounded public
`RelayLiveControlDeployment` projections before readiness. Each installation
fixes its original candidate, contract, parent digest, lease, deadlines,
certificates, control role leaf digests and prepaid limits; it carries no
Artifact, endpoint identity seed, PSK or Session nonce. The staged receiver
prepares its original carriers and verifies both independently delivered Grants
on those same accounts before releasing the original forwarding barrier.
`RelayOriginalDeliveryHandle::live_forwarding_progress` returns aggregate
`RelayLiveForwardingProgress` counts observed from those retained objects:
installation, publication, authenticated pairing, READY forwarding, datagram
forwarding, physical completion and failure. `wait_live_completion` observes all
installed publications within the caller's bounded deadline and cancellation;
withdrawing that observer creates no retry, adoption or publication rights.
Completed physical tasks retain their observed milestones for the lifetime of
this original handle.

The live engineering relay reads `FLOWERSEC_PARITY_RELAY_LIVE_DEPLOYMENT`, an
exclusive installation exported by the independently installed Go authority.
The authority retains the full registry, endpoint material and signing keys.
Its relay export includes only the public candidate, contract, parent digest,
lease, deadlines, certificates, control role digests and limits, together with
the relay's own identity, native/control TLS and explicit ledger mappings.
The fixed control endpoint preserves its exact hostname and root path. The
relay bootstraps the installed namespace pins and binds its original staged
receiver before emitting a public `relay-prepared` acknowledgement. The parity
driver matches that acknowledgement to the authority's original endpoint
publication and sends endpoint material directly to A and B. The relay receives
only the public configuration acknowledgement. Pool engineering keeps its
original issuer and sealed publication path.

The engineering driver can prepare a fresh live installation with
`FLOWERSEC_PARITY_ACTIVATION_SOURCE=live_authority` and
`FLOWERSEC_PARITY_RELAYS=rust`. The Go `live-installation` owner fixes the
original authority, A control and B registry/control files before peers start.
It holds namespace bootstrap until the endpoints, relay and authority have
joined cleanup. Each process receives only its own installation path; each
live endpoint receives only its own identity and native TLS private material.
The driver's original A projection and B's public readiness form A's input.
Set `FLOWERSEC_TEST_ARTIFACT_DIR` to an absolute repository-external directory
when choosing the artifact root; otherwise the driver uses the sibling
`flowersec-test-artifacts` directory. System temporary roots are rejected.
Successful installations are removed after process cleanup. Failed runs retain
only a verified checksummed log outside the installation directory.

Listener legs share continuous bounded ingress across pending publications.
The first bounded HOP HELLO can select only an exact already registered Grant.
The input reader pauses until that original namespace account and signed byte
meter are installed; this selection cannot manufacture authorization. Matching
A/B listener configurations at the same address and carrier use one ingress.
TLS identity, Origin, host and provider bounds remain independently configured.
`TransportEnvironment::wss_relay_host_on_listener` and
`wss_relay_host_on_udp_socket` can transfer an already-bound TCP or UDP ingress
socket into the original relay host when its address matches the configured
listener leg. A prebound socket is rejected if the host does not consume it as a
listener leg. For a deployment that issued the route against a prebound ingress
socket, `serve_reverse_tunnel_pool_on_listener` transfers TCP and
`serve_reverse_tunnel_pool_on_udp_socket` transfers UDP into the shared relay
owner; both require the address to equal `provider.listen_address`.
`wait_listener_ready` observes physical readiness without granting HOP, Session,
retry or admission authority.

For `preauthorized_pool`, the server's `TunnelServeHandle::serve_pool_allow`
installs the independently configured TLS 1.3 mutual-authentication receiver at
`/tunnel/server-allow`. `PoolServerAllowOptions` fixes the coordinator certificate,
trust, destination, provider budget and a maximum two-second request timeout.
The returned `PoolServerAllowBinding` identifies that original recipient and
incarnation. Installation and reverse-listener readiness do not dispatch a
Grant leg. Only the exact authenticated Allow admits one preparation into its
original Serve slot; duplicate deliveries join that execution, and terminal
slots cannot restart. `close` and `wait_cleanup` include physical control ingress
and reverse-listener cleanup.

The pool client installs `TunnelServerAllowConfiguration` with its own control
TLS identity, the original public B binding and the separately issued role-1
server Grant. `preauthorized_tunnel_pool_with_server_allow` and
`preauthorized_reverse_tunnel_pool_with_server_allow` capture one configuration
per credential. The original Connect verifies and prepays the control request
before consuming; only confirmed original consumption can publish Allow, before
HOP. Missing configuration fails before spend. Query results, unknown consumption
and replacement Connect calls cannot reconstruct this publication owner.

The relay forwards the visible NEGOTIATE, FSB/FSA, Noise and dual READY sequence
without decrypting it. Native application mappings open only after both visible
READY messages have been forwarded. A visible scope binds one original mapping
and remains tombstoned after its physical cleanup. Native FIN, reset and stop
signals apply to their actual directions; endpoint authentication still decides
accepted OPEN, application records and graceful termination. Datagram forwarding
requires native support on both legs and preserves actual submission completion.
WSS does not acquire a synthetic datagram or native mapping capability.

`WssRelayPublication::close` and host Close cancel the original physical owners.
`wait_completion`, `cleanup_status` and `wait_cleanup` observe those same tails.
Buffered frames, native handles, callbacks and provider backing retain their
charges until actual driver and forwarding exits. Neither a dropped observer
nor a canceled cleanup wait starts another claim or releases live backing.


## Owned duplex bridges

`DuplexBridge::new(a, b, options)` takes two distinct unused raw Streams in the
same original Environment. `DuplexBridge::with_native_tcp(stream, tcp, options)`
takes one Stream and one sealed `NativeTcpDuplex` created by
`NativeTcpDuplex::connect(&environment, numeric_address, options).await`.
The factory reserves native descriptor, provider/runtime, monitor and facade
backing before publishing an endpoint. It exposes no external socket adoption,
raw descriptor or alternate producer. Facade aliases share the original owner;
an alias cannot close an endpoint claimed by a bridge.

Construction reserves both finite copy chunks and tail owners before claiming
I/O. The overall deadline includes the prepared period before `start()`.
Source EOF half-closes only its destination. Both directions continue until
their own EOF, then finish their actual sends concurrently. Native completion
uses `NativeTcpWriteShutdownQueued`; authenticated Flowersec completion uses
`AuthenticatedStreamDrained`. TCP queue/shutdown completion does not prove
peer authentication or business execution.

`wait()` is passive: dropping its future leaves the operation and its progress
intact. Use `abort()` for explicit operation cancellation. Failures retain
bounded partial progress and the original tail owners. `transfer_sealed` is
true only after both pumps exit; an incomplete cleanup observation can still
have live transfer progress. `cleanup_status()` observes actual late retirement
without refunding work still in flight. Environment close wakes connection
and prepared-endpoint waits. Socket retirement and final facade-alias release
are separately charged lifecycle facts.

Registered pool server installations use
`TransportEnvironment::register_pool_tunnel_server` with independent control
TLS, namespaces, identity, parent material, relay certificate and audience.
The returned material verifies both original Grants and the shared winner
selection before transferring its single admitted Account through `serve` or
`serve_reverse`. Installing that Serve's pool Allow receiver acknowledges
verified installation to the issuer; it does not dispatch Prepare or HOP.
Only the original authenticated Allow opens that gate. Before local admission,
the same established carrier consumes its retained issuer winner continuation
once. Failure or cancellation cannot retry or reconstruct the continuation.

An independently installed external relay can retain
`RelayParentRegistration::take_pool_winner_continuation()` during original
publication. Its once-only `match_original` operation compares the original
lease and shared control selection against the winner actually committed by
this relay's authenticated HOP. It performs no winner insertion and exposes
no recovery constructor. The local durable encoding remains internal to its
original ledger. The continuation retains its resource custody until the
caller drops it after the physical control reply finishes, including failure.
