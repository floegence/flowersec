# TypeScript current transport runtime

The explicit v4 client entrances are `configureV4NodeWSS(...)` from
`@floegence/flowersec-core/node` and asynchronous `configureV4BrowserWSS(...)`
or `configureV4BrowserWebTransport(...)` from `@floegence/flowersec-core/browser`.
Each installs a connector on the original
Environment returned by `createV4TransportEnvironment(...)`. The Environment owns both connection and Node direct WSS serving. Its
`serve(...)` entry returns the original listener aggregate.

The v4 implementation supports the following exact client tuples. These are
implementation capabilities; release readiness additionally requires the schema
and qualifications in [TRANSPORT_V4_BINDING.md](TRANSPORT_V4_BINDING.md).

| Property | Node WSS | Browser WSS |
| --- | --- | --- |
| Path and role | Direct endpoint client | Direct endpoint client |
| Activation | `preauthorized_pool` with SQLite, or `live_authority` with mutual-TLS HTTPS or an independently authenticated host control adapter | `preauthorized_pool` with optional host IndexedDB, or `live_authority` with controlled HTTPS or the host live control contract |
| Application profile | `transport`, or explicit `services`/`execution` | The same profiles |
| Crypto profiles | X25519/ChaChaPoly/Ed25519 and P-256/AES256GCM/Ed25519 | The same two profiles |
| TLS policy | CA or exact signed leaf-DER SHA-256 pins; TLS 1.3 | Browser CA verification plus a trusted controlled-terminator deployment |
| Reliable progress | `shared_ordered` | `shared_ordered` |
| Bound stream input isolation | `shared_failure_scope` | `shared_failure_scope` |
| Datagram | Unavailable | Unavailable |
| Consumer TLS guarantee | `consumer_enforced` | `controlled_terminator` |

## Node direct WSS serving

Create a single-use listener with `createNodeWSSListener(environment, options)`
from `@floegence/flowersec-core/node`, then call `environment.serve(...)`. The
listener captures a numeric bind address, server name, TLS certificate and key,
identity/Noise keys, Session and ingress limits, one activation source, and one
SQLite admission authority. The trusted credential resolver receives bounded,
unauthenticated HELLO bytes only as a lookup selector and fills SDK-owned
credential buffers. It must end every buffer borrow when its promise settles,
including after cancellation. Application callbacks receive authenticated
identity facts only after original FSB verification.

Provision admission storage using `createV4SQLitePoolBacking(...)` and
`openSQLiteAdmissionStore(...)`. Its service binding fixes tenant, issuer,
audience and server identity. Pool activation additionally requires the
separately configured shared `parentWinnerStore`; the consumer spend authority
cannot replace it. Reopening requires independent continuity and advances the
local fence. A reserved or admitted lease cannot create another invocation.
Only the original admitted transaction may recover its lost commit receipt with
one exact confirmation read while the original continuation remains unused.

`createHandlerPlan(environment, options)` captures immutable service contracts,
typed unary/streaming/notification handlers, execution configuration and raw
stream declarations. `services.profile` selects `services` or `execution`;
omitting services selects transport-only operation. Raw stream declarations
reuse the Session registration and application executor. Their initial owners,
the RPC graph and SQLite work are reserved before admission CAS. A selected
plan retains its original contracts through assembly even when its reusable
handle is closed. Supply the same maintenance owner to the plan and Serve when
handlers require response publication maintenance.

The five callbacks are fixed when Serve starts:

- `authorizeRequest` checks bounded Origin policy before WebSocket upgrade.
- `resolveHandlers` selects a plan using verified identity metadata.
- `authorizeApplication` reserves the application's authorization lease once,
  returning an authorized plan/lease or a rejected/unknown decision.
- `onSession` receives the Session only after authenticated dual READY and
  returns whether the application accepted it.
- `release` settles the original application's cleanup after native and Session
  cleanup. It also runs when authorization throws or rejects.

Each callback context carries the same opaque `invocation` object, allowing
application code to associate an uncertain authorization reservation with its
original Release call without exposing a protocol or database identifier.
Cancellation burns a returned lease, closes ingress and retains callback work
until the original promise actually settles. Release and lease cleanup must
confirm `complete`, `core_cleanup: complete`, and zero pending callbacks before
Serve refunds the position. A lease's incomplete bounded observation is checked
again serially in that same position, without repeating authorization or Release.
The Release promise must cover its actual cleanup; Serve bounds public waiting
independently. If Release returns an incomplete snapshot or rejects, that
unconfirmable invocation remains charged, including its reported callback count.

`serveHandle.drain(...)` seals new ingress and drains published Sessions within
its original deadline. `waitDrain(...)` observes that operation; canceling a
wait does not cancel serving. `close()` aborts owned ingress and Sessions.
`cleanupStatus()` and bounded `waitCleanup(...)` report remaining native and
application responsibilities. Drain preserves child deadline/failure outcomes;
Close interrupts a pending Drain with `failed`. Its result observes the same
current cleanup facts as the Serve handle, even after Drain becomes terminal.
Core cleanup can be complete while application callbacks still hold their
original positions. Closing Serve never closes its borrowed
Environment. Parent cancellation performs the same abort. Startup failures use
opaque `ServeError` and preserve the original cleanup snapshot.

## Host construction and connection

1. Construct a bounded `V4ResourceRoot` and Environment with explicit tenant and
   Environment limits, a qualified monotonic clock, independently trusted UTC
   interval and secure randomness. Clock callbacks are trusted host inputs.
2. Select exactly one activation source. For pool activation, provision or reopen the matching durable pool store with its stable authority,
   store identity, generation and tenant/issuer bindings. Supply an independent
   continuity authority and finite storage/runtime limits. Provisioning and
   reopening are distinct operations. For live activation, configure the
   independently authenticated authority adapter described below.
3. Install the runtime-specific client, immutable identity/Noise keys,
   carrier policy and finite Session limits. One Environment owns that connector.
4. Obtain `client.namespace(...)`, then authenticate its bootstrap response and
   trust state against the configured root and original nonce. Merely having
   signed material does not replace namespace bootstrap.
5. Use `client.registerPoolSource(policy, provider)` or
   `client.registerLiveSource(policy, provider)` for bounded material acquisition
   under the configured activation source. For already obtained complete
   material, use the corresponding `verifyPoolMaterial` or `verifyLiveMaterial`.
   The source borrows SDK buffers and returns their actual filled lengths;
   completion ends that original borrow, including after cancellation.
6. Call `environment.connect(source, requirements, options)` or
   `environment.connectMaterial(material, options)`. Material transfers once to
   the Environment. Each connection retains its original authorization,
   deadline, resource admission and actual provider/store tails.

Applications can import `V4NamespaceOptions`, `V4CredentialPolicy`,
`V4CredentialProvider`, `V4CredentialBuffers`, `V4CredentialLengths` and
`V4ConnectionMaterialSource` from the package root or its `./node` and
`./browser` entrances. These types cover namespace configuration, bounded
credential acquisition and the registered source shared by one-shot connections
and Controllers.

The source-based form can request these transport guarantees:

```ts
const session = await environment.connect(source, {
  application_profile: "transport",
  independent_reliable_read_progress: false,
  bound_stream_input_isolation: false,
  datagram: false,
  local_consumer_tls13_verification: false,
});

try {
  const stream = await session.openStream("example/raw");
  await stream.write(new TextEncoder().encode("hello"));
  const received = await stream.read(4096n);
  // Handle received.cause and received.stream_status with received.data.
  await session.rekey();
  await session.probeLiveness();
} finally {
  await session.close();
}
```

Node may require `local_consumer_tls13_verification: true`; the browser client
rejects that requirement before source acquisition. Both clients reject
unsupported requested guarantees before acquisition and reject incompatible
signed profiles before durable consumption.

The configured Node WSS, browser WSS and browser WebTransport connectors reserve
their Session plan and carrier vectors before source acquisition. The plan uses
the captured local frame/stream limits, application configuration and native
carrier topology. It includes Session protocol storage, initial RPC tables and
bootstrap channels, maintenance storage, carrier buffers and policy parsing,
and the admission exchange. WebTransport also reserves its original native
stream positions. The carrier's Environment dependency position is held at the
same time. The original aggregate send account and protected direction account
pool also claim actual root account slots before acquisition. Session assembly
adopts those same accounts; it does not repeat account admission. The direction
pool retains its configured upper bound through the Session lifetime, even when
the signed active-stream limit is smaller. Failure releases unused reservations
and accounts without invoking the source.

Actual material must fit this plan. Assembly moves the original references into
the carrier and Session; it never refunds them to compete for the same capacity
again. Maximum backing stays charged until its actual owner releases it; unused
positions are released when the connection attempt ends. `connectMaterial`
performs the same reservation before preparing its carrier. The optional
`limits.maxGeneralOutstanding` bounds the signed ordinary RPC capacity accepted
by this connector (1–1024, default 1024); larger signed values are refused before
carrier creation or credential consumption, without changing the signed value.
For application profiles, the Environment also prepares its original contract
query pool, service binding pool and declared execution history owners before
acquisition. Candidate assembly reuses them; a failed candidate does not reset
shared history or remove another Session's pools. Shared application executor
positions, later method bindings and per-call execution gates still perform
their own admission checks.

Actual carrier preparation and complete Session admission precede authority
activation or pool TxA-P. The verified live authorization or successful durable
pool consume receipt precedes the first HELLO byte. FSB/FSA,
KKpsk0 Noise and both authenticated READY messages all complete before a public
Session is returned. Every WebSocket message carries exactly one envelope.
Streams support bounded reads and writes, reader cursors and write operations;
the Session also exposes accepted streams, rekey, liveness, termination and
cleanup observations. A canceled manual rekey waiter does not undo an already
started protocol round.

Before consuming connection authorization, the Session protects the actual root
references and backing for its rekey round, decoder and two alternating sets of
epoch and scope-zero keys. Four cryptographic usage-counter slots belong only
to these maintenance keys. Ordinary application derivations cannot use them.
The original round buffers follow the bounded canonical barrier encoding;
they do not each allocate the full ordinary DATA frame size. Client construction
uses the signed barrier scope ceiling even when its local active cap is smaller.

Each application direction separately obtains two protected key positions and
two actual cryptographic usage-counter slots before its first derivation. These
slots are bound to the original scope/direction. Rekey checks out the next position and retains the old one
until the actual key/packet references exit. This reserves the direction's
current/next key backing at stream admission; it does not allocate maximum
application credit or promise admission for all future streams. Complete
resource-profile qualification additionally covers complete signed rekey work
envelopes and actual scheduling/cleanup coexistence.

`session.drain({ timeoutMS })` returns the original `V4DrainOperation`. The
first call atomically seals new local OPEN and peer acceptance, fixes the
highest previously accepted peer ID, and publishes authenticated GOAWAY. The
accepted frontier survives stream retirement. Pending and later authenticated
OPENs receive a bounded `draining` rejection; already submitted local OPENs
still require an explicit peer result. Peer GOAWAY independently prevents new
local OPEN and never treats every smaller ID as accepted.

The default and maximum Drain window is thirty seconds, tightened by an
explicit shorter timeout and original safety deadlines. Repeated calls return
the same object and cannot extend it. `operation.status()` and
`await operation.wait({ signal })` return `V4DrainResult`, with `pending`,
`drained`, `deadline_aborted` or `failed` outcome and separate cleanup status.
`V4DrainOptions` selects only the first deadline; `V4DrainError` reports local
wait cancellation or capacity failure without canceling Drain. At most 32
independent, resource-admitted waits may observe one operation.

Existing stream traffic and necessary rekey continue under the original
authorization. Communication completes only after both directional terminal
proofs and unread graceful bytes are consumed or explicitly abandoned. Native
callbacks may still be active when `drained` is observed; their original
resources remain charged. Session close has one five-second cleanup observation
deadline, and `session.waitCleanup({ signal })` is a bounded, passive wait.
`cleanup_incomplete` never refunds live resources and can later become
`complete` when the actual tails exit. A terminal Drain observation retains
finite facts without a reference back to the Session.

The signed `session_contract.idle_duration_ms` is enforced from the completed
dual READY publication gate. Zero disables its watchdog; an explicit positive
`limits.localIdleDurationMS` may independently tighten idle lifetime. Only a
complete authenticated envelope handed to the provider, or complete incoming
authenticated and protocol-validated input, refreshes the original monotonic
anchor. Queue admission, partial I/O and native WebSocket Ping/Pong do not.
Rekey and drain keep that deadline. Admission refuses an idle policy shorter
than the locally promised full rekey work window. Expiration is reported as
`idle_timeout` through Session termination; clock continuity failure reports
`time_unavailable`.

`session.probeLiveness(options)` returns `{ submitted, complete, elapsedMS }`.
The bigint elapsed value includes queuing from local acceptance, not just wire
latency. Typed `V4LivenessError` retains a bounded reason and the same progress,
using `null` when elapsed time is unavailable. Cancellation, timeout or rekey
removes the matcher immediately while actual provider tails retain their slot.
Up to eight independent probes are admitted. The nonce counter is local to the
original Session send role and never resets on rekey. Authenticated unmatched
late PONGs do not create new work or satisfy another probe.

Automatic probes run only with explicit `limits.automaticLiveness` containing
positive bigint `intervalMS`, `submissionMS`, `responseMS` and a positive finite
`missThreshold`. One of the eight slots is protected for this policy. Its total
deadline is fixed at acceptance. A miss requires complete PING publication
within the submission budget and a full real response interval, with no rekey
or known local read/write/resource stall. Successful automatic PONG or a
completed independent rekey resets misses. Reaching the threshold terminates
with `liveness_path_unresponsive`; no business work is replayed.

The signed `max_streams` is an authorization ceiling. The local active capacity
is the smaller of that ceiling, `limits.maxStreams` and 1024. A larger signed
allowance does not force allocation of that many active streams.

`createStreamMetadataEnvelope(namespace, version, values)` preserves the ordinary
v4 CBOR shell and opaque byte values. `createStreamMetadata(...)` supplies the
optional `application/json` version 1 codec. Received metadata retains its exact
canonical bytes, namespace and version.

`stream.closeWrite(options)` seals send admission and waits for the original FIN
ticket after earlier admitted output. `stream.finish(options)` additionally
requires an authenticated normal DRAINED proof. Canceling either wait does not
reopen the send gate or discard admitted output. Reverse reads remain available,
including unread bytes received with FIN. `stream.close(options)` and
`stream.reset(options)` use the same bidirectional abort operation. Their
`V4CloseResult` distinguishes normal send drain, read terminal state and actual
cleanup. `stream.waitPeerAuthenticated(offset, options)` waits only for the
already accepted prefix's authenticated peer frontier; it does not prove peer
application consumption. Retirement retains these compact observations without
retaining the Session's key and payload ownership graph.

`session.close()` and `environment.close()` synchronously seal admission and
return the original bounded `Promise<V4LifecycleResult>`. Repeated calls join
that operation. The result separates `object_kind`, `lifecycle_state`,
`cleanup_status` and a finite `reason`: Session close establishes
`session_aborted`; it does not establish normal stream drain or peer receipt.
The default cleanup deadline is five seconds of trusted elapsed time. Actual
provider and application tails retain their original resource charges after a
`cleanup_incomplete` observation. `lifecycleResult()` and `cleanupStatus()` can
later report actual completion. A native cleanup failure is reported as
`core_cleanup_failed`.

`waitCleanup(options)` uses original cleanup transitions and one finite wait
deadline. Canceling the wait only detaches that observer. A timeout while the
owner is active reports incomplete cleanup without closing it. Completed
public handles keep compact observations and drop the runtime owner; the
Environment continues to account for any independently retained message result.

Ordinary `write` accepts a bounded prefix even when its input exceeds the
optional `prepareWrite` staging cap; its progress retains the original requested
size and actual accepted bytes. Continue only with the unaccepted suffix.
Receive ACKs coalesce ordinary progress for at most 25ms or one effective window
(capped at 64KiB). Releasing a real exhausted credit boundary makes its reserved
replacement grant immediately eligible. This bypasses only coalescing, not
authorization, output admission or other protocol gates.

## Node carrier and SQLite store

Both client configurations require exactly one of `poolStore` and
`liveAuthority`. The live configuration captures an independently authenticated
host control transport through `V4LiveAuthorizationProvider`, a finite
`maxConcurrentRequests`, and explicit `runtimeBytes`/`providerBytes` allowances.
It does not install an activation signer or consumer-side authority database.

Node includes `createV4NodeLiveHTTPS(environment, options)`. Pass its immutable
result as `liveAuthority` to `configureV4NodeWSS`. `V4NodeLiveHTTPSOptions`
captures a separate canonical HTTPS `baseURL`, its host-resolved numeric
`remoteAddress`, exact `authority`/`tenant`/`audience` binding, explicit CA roots,
and the client's PEM certificate chain and private key. The key is supplied as
bytes, copied into the admitted native TLS context, and the SDK's temporary
copies are cleared. The caller retains ownership of its input bytes.

This adapter sends exactly one POST to `<baseURL>/live/authorize` using the
Go control service's bounded `live-authorization-1` CBOR envelope. Before
publishing it, the actual socket must pass TLS 1.3, explicit CA trust,
hostname/SAN, certificate-time and local-client-certificate checks. The
original trusted clock bounds the complete operation with `timeoutMS`;
`headerBytes`, `handshakeBytes`, concurrency and runtime/provider budgets are
fixed before allocation. HTTP redirects, automatic retries, proxies, cookies,
compression and connection reuse are absent. The only success envelope is a
bounded HTTP/1.1 200 response with `application/cbor` and one positive, exact
Content-Length. It still requires original signed-proof verification.

The adapter belongs to the same Environment as the connector. Environment
Close cancels its sockets and fences further publication. Outstanding native
write, request, response and socket callbacks retain the original reservation
and buffers until they really finish. An HTTP failure cannot resolve an unknown
authority transaction or authorize another attempt. The server must independently
require mutual TLS and bind that client identity to its durable authority.

Use `registerLiveSource(policy, provider)` or
`verifyLiveMaterial(policy, input)` for live material. It contains the Artifact
and both identity certificates; the source reports zero activation bytes.
Original namespace, identity, route, policy and deadline verification still
precede preparation. The connection generates one attempt ID and prepares its
actual carrier. After full Session admission, the original owner invokes the
authority once with a bounded `V4LiveAuthorizationRequest`: tenant, authority,
lease, Artifact/identity digests, selected candidate/route and attempt. The
request contains no PSK or private key.

The host control provider resolves the independently authenticated authority and
performs one physical request without retry, fallback or detached borrowing. It
calls the supplied guard immediately before actual request publication, including
after asynchronous TLS work, then writes the complete canonical activation proof
into the SDK's reserved output buffer. A successful HTTP call, Boolean or query
receipt cannot activate the connection. The SDK independently verifies the
proof's signature, original parent namespace and authority, lease, identities,
selected route, exact attempt and non-extending deadlines before its first HELLO.

Cancellation prevents late installation and connection publication. An uncertain
control outcome remains uncertain; the material is never returned as reusable.
Original request buffers, carrier and provider allowances stay owned until the
actual work returns. Custom providers are trusted host integrations; implementing
their callback alone does not establish durable once semantics.
Authority durability and the deployed transport's authentication still require
their separate qualification.

`asNodeDuplex(stream, options)` from `@floegence/flowersec-core/node` directly
owns the accepted v4 Stream's two application I/O directions. Construction
rejects a concurrent cursor, read, write, other adapter or an already started
termination. Raw I/O stays unavailable while the adapter owns the directions;
the original Stream's Reset, Close and cleanup observations remain available.

Supply a finite `producer` profile with `maxChunkBytes`, `maxBackingBytes`,
`maxPendingWrites` and `maxQueuedBackingBytes`. The original resource root
reserves native queue/backing allowances plus reader and callback state before
publishing the Duplex. `highWaterMark` defaults to 64 KiB. Producer bounds are a
deployment obligation: Node can queue writes before invoking `_write`, so HWM
and current-chunk validation cannot enforce a hard bound on an uncooperative
producer. Full retained backing counts even for a tiny view; input remains
borrowed until its callback. Larger legitimate inputs need an appropriate
profile or cooperative chunking, rather than truncation.

Each write callback waits for the entire chunk's local acceptance and reports a
bounded `V4NodeDuplexError.progress` on partial failure. Native `_final` publishes
FIN and waits for authenticated normal DRAINED while reverse reads continue.
The adapter uses `allowHalfOpen: true` and `autoDestroy: false`. Only its own
normal completion after actual readable `end` and writable `finish` selects
normal cleanup; caller destruction, abort and I/O failure select the original
Reset operation. Normal cleanup never resets the Stream.

`gracefulFinishTimeoutMS` selects the Stream's original termination preset before
termination begins (default 30 seconds). `cleanupTimeoutMS` bounds the subsequent
native destroy wait (default 5 seconds). `closeResult()`, `cleanupStatus()` and
`waitCleanup()` distinguish authenticated send completion from actual cleanup.
Timeout may report `cleanup_incomplete`; actual callbacks and unread native
buffers retain their reservations and active Stream slot until they exit.

For accepted Streams, normal termination expiry enters a bounded quarantine
before escalating to Session failure. The total cap is fixed from the original
normal deadline plus ten seconds and is still constrained by Session safety
deadlines. At most 32 directions are quarantined, retaining their original
capacity and proof resources. Authenticated STOPPED/DRAINED can settle a failed
send while reverse traffic and healthy Streams continue. Local authenticated
input failure starts quarantine immediately.

`V4NodeWSSClientConfig` captures an Ed25519 private `KeyObject` and an X25519 or
P-256 private `KeyObject`. The software Noise adapter exports its private scalar;
deployments requiring an unexportable Noise key need another supported adapter.
`V4NodeWSSOptions.remoteAddress` is one preselected numeric address. Preparation
performs no DNS resolution, redirect or retry; the signed logical host still
governs SNI, CA target verification and the WebSocket authority. The actual
socket must negotiate TLS 1.3 and HTTP/1.1 with the exact v4 path/subprotocol and
signed Origin policy. Compression is disabled and message/fragment queues are
bounded.

`V4NodeWSSClientConfig.bindingMode` optionally selects `"direct_exporter"`;
its default is `"authenticated_context"`. Direct exporter uses the actual owned
TLS 1.3 socket's 32-byte export with `EXPORTER-flowersec-v4` and the original
Artifact digest. Derivation and carrier revalidation precede SQLite consume.
The selected mode stays fixed through HELLO, TransportContext and FSB/FSA;
unavailable exporters, mismatched peer binding and downgrades fail closed.
The browser WSS entrance supports authenticated context only because its
standard WebSocket API does not expose the native TLS exporter.

CA mode validates the native certificate chain and target identity, and checks
certificate validity against the trusted interval. Node's native CA validation
also uses its host clock; an incorrect host clock can conservatively reject a
connection. Pin mode verifies the complete leaf DER against only the active
signed pin set and enforces the pin certificate profile without CA fallback.

`createV4SQLitePoolBacking(...)` and `openV4SQLitePoolStore(...)` own an actual
SQLite database. Serialized durable transactions enforce the tenant/issuer/lease
uniqueness key and current fencing epoch. The stored projection retains signed
proof and owner bindings without persisting Artifact plaintext or PSK. SQLite
commit success is the consume receipt; a callback cannot assert that a commit
occurred.

## Browser carrier and optional IndexedDB store

`V4BrowserWSSClientConfig` requires actual extractable WebCrypto private keys:
Ed25519 with signing usage and X25519/ECDH P-256 with derive-bits usage. The
current software adapter exports and validates those keys under Environment
ownership; non-extractable or hardware-only requirements fail before consume.

`V4BrowserWSSDeployment` captures the exact endpoint, application origin, route
digest, deployment/revision identity, trusted validity interval and independent
deployment evidence reference. Its fixed terminator profile covers TLS 1.3,
early-data refusal, HTTP/1.1, exact actual Origin enforcement and no WebSocket
extensions at the browser-facing terminator, including any proxy or load
balancer. This configuration is a trusted host deployment responsibility.

The SDK checks observable local `location.origin`, the signed route and Origin
policy, actual WebSocket open state, subprotocol and extensions. JavaScript does
not inspect the TLS version, early-data state, ALPN or actual outgoing Origin
header. WSS leaf pins and signed requirements for consumer TLS verification are
rejected before constructing the WebSocket or consuming material. Native output
remains charged until actual `bufferedAmount` drain or the native close event.
Browser-internal allocation before message delivery is a qualified host boundary,
not a JavaScript-enforced memory cap.

### Browser WebTransport

`configureV4BrowserWebTransport(environment, config)` accepts
`V4BrowserWebTransportClientConfig` and returns a
`V4BrowserWebTransportClient`. Its `V4BrowserWebTransportClientLimits`, identity
keys, pool/live source selection, namespace and material methods share the
same owners as the browser WSS entrance. It supports direct client routes and
the `transport` application profile. Datagram negotiation remains disabled.

`V4BrowserWebTransportOptions` contains a captured
`V4BrowserWebTransportDeployment`: the exact signed route digest, HTTPS endpoint
`/flowersec/webtransport/v4/direct`, application origin, validity interval,
registry provider/source tuple, observed user agent and trusted build identity.
The deployment profile requires TLS 1.3 without early data, dedicated HTTP/3,
exact Origin enforcement and no extra WebTransport session flow control. These
are trusted operator obligations where browser APIs provide no observation.
The SDK does not invent a Chromium pooling option or export a TLS binding.

CA routes omit `serverCertificateHashes`. Pin routes derive hashes exclusively
from active signed leaf-DER SHA-256 pins using the signed `x509v3-p256-14d`
profile. Prepare and spend recheck every originally supplied active pin because
the browser does not identify the matched pin. A signed requirement for local
consumer TLS 1.3 verification is refused. Each Environment captures its provider
configuration before Prepare; caller mutation cannot alter the private digest.

Prepare creates one empty maintenance bidi. Original admission opens its send
gate after confirmed authorization, then uses HELLO/FSB/FSA, Noise and dual
READY. Application create/accept starts after READY. Every application Stream
owns a distinct native bidi, bounded frame assembler and output position. Only a real
authenticated OPEN establishes its logical scope. Complete ordinary frames use
a bounded fair authentication queue; partial native reads do not take that
service slot. DATA length prechecks use the original direction's remaining
credit and the canonical encoder. Reads request at most 16 KiB, with a fixed
16 KiB browser BYOB backing. Unauthenticated DATA occupies the original receive
promise's unused backing plus its schema-derived fixed overhead; a partial body
does not reserve a full maximum-frame buffer. Authentication, envelope coalescing
and DATA decoding use shared Session workspaces. Each incoming key retains only
its own key, nonce, usage, authorization and bounded workspace link.

The Session admission transaction also reserves the actual protocol reference
slots and fixed charges for every native reader, output descriptor, logical
association and ciphertext backing position. These positions remain protected between uses; a position with a
live reference or alias cannot be reused. OPEN input backing has a separate
finite pool sized to `maxPending + ingressItems + 1`, including the original
pending accept. Binding an authenticated OPEN replaces its head with H_DATA
and returns only that opening backing; active DATA directions do not retain a
full OPEN-sized buffer. Slow native/provider cleanup retains the original
association position. This protocol reservation is separate from the carrier's
prepaid native reader/writer/handle positions and does not replace complete
receive-promise, crypto-work and maintenance coexistence qualification.

Outgoing native application records share a separate Session encoding/AEAD
workspace. It is held only through synchronous sealing and state publication;
a blocked native write retains its own exact ciphertext copy. Every copy is
admitted before the crypto ticket using an already protected root reference.
The original root, tenant, Environment, Session-send and direction-send accounts
atomically charge its exact ciphertext bytes and retained metadata. All actual
aliases must return before those bytes and dynamic account scopes are released;
closing an account or pool cannot refund a provider borrow. The fixed position
remains prepaid between sends. Bytes are cleared only after actual provider
completion. Idle application streams retain compact output descriptors rather
than maximum-frame encoding and encryption buffers. Maintenance keeps its
independent output and cipher position. Rekey still waits for original native
output tails before advancing the barrier.

`limits.sessionSendQueueBytes` caps the aggregate SDK-owned send allocation for
one client Session; its default is 12 MiB. Configuration must fit one maximum
WriteRequest and, for native streams, its simultaneous ciphertext output before
connection authorization is consumed. Immutable WriteRequest payloads,
typed-message encoding inputs and copies, standard adapter SDK backing, and
native ciphertext copies share this account in the original ResourceRoot.
Each reserve checks that account together with the original Environment and
tenant accounts. Shared codec workspace has its own original admission charge.
The cap is not peer receive credit or a bound on hidden browser/provider queues.
Closing seals new reservations; actual callbacks and I/O keep their charges
until their original references release. Replacement Sessions cannot refund
those tails from the Environment or root budget. This cap alone does not reserve
all future protocol progress, per-direction service floors, or a complete
qualified Session resource profile.

`limits.streamSendQueueBytes` additionally limits one local send direction
(default 4 MiB for client construction; the internal server assembly defaults
to 8 MiB). Before connection authorization is consumed, the Session protects
`maxReceiveDirections + ingressItems + 1` actual root account slots for local
send directions, including closing owners. A direction checks out one of those
slots before OPEN or accepted publication. Returning its handle does not make
the slot reusable while any charge, borrowed alias or attached service remains.
A later checkout advances the original slot generation; old handles cannot
reserve against it. Closing the pool seals every live lease and releases only
positions whose actual charges have exited.
Send reservations check the direction and Session accounts in the same original
root transaction; they do not charge an independent second byte allocation.
Stream retirement and Session Close seal these accounts. Unreturned callback
or I/O references keep the original account slots and bytes occupied. Root
configuration must cover the simultaneous Session/direction account slots and
still-retained closing accounts. Missing account capacity rejects establishment
before authorization consumption. The account cap is separate from protected
service/admission byte and work reservations and does not establish those guarantees.

`limits.nativeDataAssemblyDepth` selects one or two candidates per accepted
native DATA receive direction; its default is two. A Session shares at most 16
client or 32 server next-candidate positions through a finite FIFO. Each extra
position prepays fixed header storage, segment indices and the real reader and
cleanup continuation before admission. No available permit means ordinary
depth-one progress. WebSocket, maintenance and unconfirmed OPEN never prefetch.

The next candidate reads only its fixed envelope/record prefix unless its full
conservative payload claim fits the remaining original promise. Otherwise it
resumes from that prefix after promotion. It cannot inspect record semantics,
choose a key, authenticate or report an error before its predecessor completes.
Promotion copies only fixed overhead, preserves the original body segments and
releases the extra position after its actual read task exits. A third frame
cannot start reading until the promoted current has entered its AEAD job. Final
frontier changes and rekey suspend new overlap; already-read bytes and actual
tails retain their charges and are checked in order.

Pending OPEN staging is separate from terminal proof capacity. Full staging
permits an authenticated OPEN to take a prepaid rejection proof and publish the
ordinary resource-exhausted rejection through one maintenance continuation.
That path retains no application metadata and invokes no application callback.
Pending authorization obtains its terminal proof before calling application
code. Exhausted proof capacity preserves existing pending owners until actual
retirement; input with neither staging nor a rejection responsibility closes the
Session. Permanent used-ID bits are set at the outcome or original local ticket.

`applicationStreams` includes pending, live, unbound and physically cleaning
native streams. Configuration must cover the selected active limit, bounded
ingress and one accept position. Provider connection and per-stream peak memory
allowances are explicit. Before creating the native connection, the carrier
atomically reserves every configured position, including its resource-reference
slot, BYOB backing, provider allowance, tasks and native handles. Maintenance
has one exclusive position; application positions are reusable only after the
original stream's actual tails exit. These positions belong to one carrier
dependency, so stream counts do not consume the Environment's top-level
dependency table. Idle positions retain their prepaid capacity until carrier
close, which prevents unrelated work from consuming already-promised space.

Cancellation detaches the observer's resolvers while retaining original
late-result disposal duties and native create/read/write/FIN/cancel charges.
Reader and writer `closed` observations must actually settle independently of
cancel/abort completion before a position can return. The same rule applies to
the incoming-stream readers. Native
`normal_drained` is a direction hint until the original authenticated rejection
or terminal proof is available; it never accepts an OPEN or proves business
success. Queued FIN is preserved during cleanup. An incoming native uni stream
is unsupported by this reliable mapping and closes the carrier. One prepaid
observer and its actual cancellation tail handle that input without body reads.

This entrance currently publishes the conservative `shared_ordered` and
`shared_failure_scope` guarantee values. It refuses required independent read
progress, required bound-stream isolation and datagrams. Native association and
directional handling, segmented promise-backed DATA assembly and shared
authentication/decoding workspaces are implemented. The full resource admission
model and actual browser/provider qualification remain incomplete. Depth-two
assembly has implementation but still needs its final behavioral and resource
qualification. Public API availability
does not claim those additional guarantees or production qualification.

`createV4IndexedDBPoolBacking(...)` and asynchronous
`openV4IndexedDBPoolStore(...)` provide an optional explicit host integration;
the SDK does not create a database by default. Actual read-write transactions
must report `durability: "strict"`. Only the original transaction's `complete`
event can report successful consumption. Request success, a later readback or
an application Boolean cannot activate a connection. A reopened store increments
its durable epoch, fences older tab owners and shares the same unique lease
history across tabs.

Strict durability cannot prove that storage survived origin eviction, disk
rollback or restored backups. `V4IndexedDBPoolContinuity.check(...)` must consult
an independently trusted host authority outside that database/origin. The SQLite
adapter has the same independent-history requirement through
`V4SQLitePoolContinuity.check(...)`. Neither API supplies a permissive default,
accepts an asynchronous/Boolean continuity result, or treats local ledger
readback as rollback resistance. Missing continuity fails closed. The current
TypeScript client has no remote pool-consume adapter; this optional host path
does not ask ordinary browser users to operate a production database.

## Closure and persistent history

`asWebStreams(stream, options)` returns an actual native `ReadableStream` and
`WritableStream` pair. It first acquires both application directions and the
complete adapter budget from the original accepted Stream. Releasing a standard
reader/writer lock does not return those directions to raw Stream I/O. The
original Stream can still be reset or closed.

The readable uses HWM zero and a single bounded pull, with a default 64 KiB
chunk. Two chunk allowances cover the private current result and a possible
native queued result. Each public enqueue uses one fixed controller, owned
backing and byte count. Cancellation or a host callback reentering during that
handoff cannot cause a second enqueue or roll back a disclosed prefix.

The writable's native `size` hook reserves FIFO byte/entry responsibility before
native queue insertion. Defaults are four pending writes, 256 KiB per chunk
and complete ArrayBuffer backing, and 1 MiB aggregate input backing. An extra
256 KiB completion allowance remains until a subsequent sink invocation or an
actual MessagePort task confirms native Promise reactions/dequeue. These
allowances come from the original budget. Shared, resizable and detached
backing is rejected; aliases are conservatively charged per queue entry. Inputs
remain borrowed until their write Promise settles. Exceeding the finite profile
errors that writable and cancels a pending write immediately, including when
the native implementation does not call its underlying abort hook.

`maxWriteChunkBytes`, `maxWriteBackingBytes`, `maxPendingWrites` and
`maxQueuedWriteBytes` select finite local bounds without changing raw Stream
limits. `readChunkBytes` selects the bounded reader allowance. Writable success
means the entire input was locally accepted; `V4WebStreamError.progress` retains
the stable accepted prefix on failure. Closing the writable uses the original
CloseWrite/Finish preset and requires authenticated normal DRAINED. Canceling
the readable sends receive-direction STOP; aborting the writable terminates
only its send direction. The reverse direction remains usable. Whole Stream
Reset/Close and authorization loss fence both endpoints. Arbitrary native
cancel/abort reasons are never inspected or retained in SDK diagnostics.

`gracefulFinishTimeoutMS` and `cleanupTimeoutMS` default to 30 seconds and
5 seconds. A cleanup timeout rejects with `cleanup_incomplete` while actual
native and protocol tails keep their original charge. Standard pipe options
retain their native propagation behavior. Application promises, tee branches,
transforms, transferred results and downstream caches are outside this bounded
adapter's queue guarantee. This adapter does not support BYOB reads.

Close the Session and Environment, then observe `environment.waitCleanup(...)`.
Actual native operations, IndexedDB transactions and borrowed source buffers
remain charged until their callbacks really finish. Cancellation prevents late
activation but does not turn an uncertain commit into an unused lease.

Store/Environment closure does not delete consumption history or release its
persistent backing reservation. `backing.releaseRemoved()` only confirms that
the host has already removed the corresponding database/files after discharging
history obligations; it performs no deletion. Both stores retain records for at
least seven days after the later of initiation end and consumed trusted upper
time, have finite record capacity and expose no automatic history deletion.

## Unsupported assembly and qualification

The TypeScript v4 clients currently have no built-in remote pool-consume/top-up
service or raw QUIC assembly. The direct Node WSS listener is described above;
relay and datagram serving remain unavailable. The explicit v4 Session service,
execution and Controller APIs are described below; their availability does not
qualify every native provider or replace the default SDK entry points. Generated
result types and internal protocol primitives alone do not establish a public path.
WSS provides one ordered failure/progress domain and cannot satisfy independent
stream progress or input-isolation requirements.

Focused Node tests exercise the actual WSS/SQLite client. Chromium functional
tests exercise both crypto profiles over real WebSocket and strict IndexedDB,
stream echo, rekey/liveness, reopen conflict, cross-tab fencing, consumer-TLS
refusal and continuity loss. The browser fixture uses an explicit self-signed
test certificate exception and a test continuity authority. It does not qualify
public-CA deployment, independent rollback resistance, Go/browser interoperability
or Firefox/WebKit support. Those properties require separate evidence before a
deployment claims them.

## Typed message streams

`V4MessageStreamDefinition<A, B>` binds one stream kind and revision to two
local codecs: `A` travels from opener to acceptor, and `B` travels back. Each
`V4MessageDirection` fixes a 32-byte schema digest, codec revision and payload
limit of at most 1 MiB. The canonical definition digest binds OPEN metadata;
local callback functions, execution class and runtime allowances are not wire
fields. `v4BytesMessageCodec` and `v4UTF8MessageCodec` supply concrete SDK codecs.
`V4MessageCodec<T>` is their opaque local codec type.

```ts
const messages = new V4MessageStreamDefinition({
  kind: "example/text",
  revision: "v1",
  openerToAcceptor: v4UTF8MessageCodec({
    schemaDigest: requestSchemaDigest,
    revision: "v1",
    maxMessageBytes: 65536,
  }),
  acceptorToOpener: v4BytesMessageCodec({
    schemaDigest: responseSchemaDigest,
    revision: "v1",
    maxMessageBytes: 65536,
  }),
});
const stream = await session.openMessageStream(messages);
await stream.send("hello");
const response = await stream.receive();
if (!response.done) consumeResponse(response.value);
await stream.closeWrite();
```

`openMessageStream` returns `V4TypedMessageStream<B, A>`; the matching
`acceptMessageStream` returns `V4TypedMessageStream<A, B>`. Both prepare the
facade, fixed adapter budget and direction ownership before accepted
publication. Optional business metadata stays separate from the definition
binding and has at most 4006 encoded bytes within the 4096-byte OPEN envelope.
`asTypedMessages` converts an untouched, already accepted raw stream only when
its original OPEN carries that exact definition. It claims both directions
once; existing raw use or another adapter prevents conversion.

`V4MessageStreamOptions` sets assembly, send and cleanup timeouts. Assembly and
send default to thirty seconds, can be configured up to ninety seconds, and
remain constrained by original safety deadlines. Cleanup defaults to five
seconds and is capped at thirty seconds. Each message is a four-byte big-endian
payload length followed by that payload. Empty payload and clean EOF are
distinct. Invalid length or truncation resets that stream. These timeout
presets have not yet completed runtime or maximum-message qualification.

`send(value, V4MessageSendOptions)` defaults to bounded queued admission;
`admission: "try_now"` requires an idle publisher and immediately available
resources before encoding. A live explicit `V4ApplicationContext` also requires
immediate admission. At most eight actual entries and 2 MiB plus 32 bytes of
candidate output/backing are retained per send direction, subject to the
original root, Environment and tenant limits. SDK byte/UTF-8 encoders acquire
output segments as they grow; arbitrary application encoders reserve their
complete output and owned-copy capacity before entry. The publisher preserves
FIFO order and sends no prefix until encoding is sealed.

`V4MessageSendResult` records submission, accepted-byte snapshot, pending
publication and cleanup. `V4MessageStreamError` carries a bounded
`V4MessageFailure`, optional send progress and `application_input_delivered`.
Cancellation before the first accepted prefix byte permanently removes that
entry's publication right; an already running encoder retains its real charges
until it exits. Subsequent entries and FIN may proceed once that entry has no
publication responsibility. Cancellation after submission detaches the waiter
while the original owner finishes the message boundary. Successful Send means
local byte acceptance, not a peer or business acknowledgement.

`receive(V4MessageReceiveOptions)` and `receiveEncoded(...)` share one persistent
cursor and return `V4MessageReceiveResult<T>` with distinct `done` and value
cases. Only a legal length admits the complete per-message body budget. A
short canceled wait keeps the same prefix, body and assembly deadline; another
wait resumes that message. No next prefix is prefetched before the current
value or error is consumed. Encoded receive transfers the original payload
without invoking a decoder. Complete private payloads can survive normal I/O
termination under the same authorization; revocation, expiry and explicit
Close still fence undisclosed input. When the current message covers every
existing receive promise, the original queue backing transfers to that one
message interval. A fitting body reuses the rotated backing, including its
charged slack; a larger body reserves its real allocation and copy overlap
before retiring the old queue. If a promise crosses the body boundary, the
ring and body remain separately charged. Credit stops at the owned interval
until a separately paid queue is installed for the next message. The I/O alias
keeps the body charge until its actual release, independently of read waiting
or message cancellation. Maximum-size and mixed-stream capacity qualification
remains pending.

`v4ApplicationMessageCodec` captures a `V4ApplicationMessageCodec<T>` with
explicit `execution: "sync"` or `"async"`, encoder, decoder and positive
`applicationBytes` host allowance. Both callbacks receive the current explicit
application context. Synchronous codec returns are processed directly;
async callbacks retain their actual execution permit through Promise
completion. An encoder must return a real Uint8Array whose entire fixed,
unshared ArrayBuffer backing fits the directional maximum. The SDK makes one
owned snapshot before publication. Neither callback signatures nor the host
allowance certify the size of arbitrary application object graphs.

An application decoder runs only for a real typed receiver and complete input.
Its first invocation receives ownership of the isolated encoded bytes and
sets `application_input_delivered`; it runs only once for that message.
Canceling a waiter leaves that same decode completion available. After entry,
encoded receive returns `result_mode_conflict`; typed receive can still collect
the original value or bounded `decode_failed` outcome. A synchronous returned
business object is stored inside the non-thenable result shell without probing
its `then`. Subsequent revocation cannot recall disclosed input or the local
computation over it, while future stream I/O remains fenced. Explicit wrapper
Close cancels cooperatively and closes result collection. A callback that has
not actually exited remains charged; JavaScript callbacks cannot be forcibly
terminated by this SDK.

`closeWrite()` seals new sends and finishes accepted message boundaries before
FIN. `finish()` uses that same operation before awaiting peer drained proof.
`close()` aborts both directions. `cleanupStatus()` and
`waitCleanup(V4ApplicationWaitOptions)` preserve actual callback/provider tails;
a context that would wait on its own callback receives `dependency_unavailable`.

## Registered application handlers

`session.registerMessageStream(definition, authorizeOpen, handler, options)`
returns a `V4StreamRegistration`; `session.registerStream(kind, authorizeOpen, handler,
options)` is the raw counterpart. Pass `undefined` when no authorizer is needed. The
`V4StreamRegistrationOptions` require a positive `applicationBytes` allowance
and bound concurrent streams, authorization jobs and application duration.
Nonempty business metadata needs an explicitly allowed namespace/version.
`V4MessageStreamHandler` and `V4RawStreamHandler` receive the original
`V4ApplicationContext` and independent business metadata. Its
`V4AuthenticatedContext` contains the admitted tenant, audience, roles,
subjects and peer identity digest. `V4StreamOpenAuthorizer` sees those facts
and metadata once, before stream acceptance, without DATA or a usable facade.
Closing a registration seals future admission while accepted handlers retain
their original generation and cleanup responsibility.

Session Close cancels the SDK's wait for an authorizer or handler. The actual
invocation retains its original executor permit, metadata and application
allowance until it returns, including a late rejection. It also retains its
registration's authorizing or active slot; a canceled observer cannot refund
that slot or publish a late acceptance. After actual protocol, provider and
adapter I/O exit, raw stream handles keep only compact terminal observations.
Registration notification links are detached and the Environment keeps a
compact cleanup owner instead of the old Session and its transport/key graph.

The stable Close Promise uses the original five-second deadline. Cleanup may
report `core_cleanup: "complete"` while `pending_callbacks` remains positive;
overall `complete` requires those original duties to exit too. Send encoders
remain Session duties through actual callback and send cleanup. Complete
receive candidates already transferred to independent message results retain
their own authorization and accounting. Late callback completion changes only
its original cleanup/result state and never reopens Session I/O.

Handlers default to resident work; trusted local registration may select
short work. One actual ResourceRoot shares the ordinary service (26 running,
52 ready; resident limits 18 and 36) and Completion service (2 running with at
most 4 promotions per wake). Their respective service allowances are 7 MiB
and 256 KiB, counted once at the root and once in each participating account.
Dormant result descriptors hold no running decoder position. Ordinary direct
synchronous encoding may reuse its current permit with bounded nesting;
new asynchronous child work takes its own permit and inherits resident
ancestry. Explicit Completion dependencies require an immediately available
claim and complete message vector, with a fixed thirty-second maximum local
wait. These limits are implementation presets awaiting final qualification.

## Internal RPC composition

`V4MethodDefinition` and `V4ServiceDefinition` define immutable local service
types using the existing opaque message codecs. A method fixes its type ID,
shape, applicable semantics, revisions, restart behavior, finite size bounds
and error catalog. One service accepts at most 256 methods in the full preset
or 16 in the constrained preset. Explicit projections keep the same namespace,
type and codec facts. Duplicate types/export names and reserved TS client
members are rejected; `exportName` provides an explicit local name override.
Definitions confer no peer identity, contract installation or dispatch rights.

The internal application runtime has a canonical application header codec,
complete immutable service contract snapshots, admission offer window checks,
and the ordinary BEGIN/DATA/ABORT/STOP_OUTPUT fragment codec. The streaming
parser retains at most a BEGIN header and borrows DATA from the authenticated
Stream read. Execution request verification hashes the original complete
contract and request payload, including known-contract discard input. Responses
match the original request digest instead of hashing their own payload with it.

`ContractRoutes` installs at most eight exact contracts per predeclared method
and checks the complete definition, including restart/checkpoint and business
error schema facts. Captures retain their original registration generation and
complete body across updates. `ServiceInputs` consumes actual protected K+2
discard/hash positions before the channel runs. It tries to reserve complete
business input from the same root and accounts; capacity, unknown contracts
and unavailable methods select a bounded refusal. Known execution input still
verifies its complete request digest when discarded. Only complete captured
input can transfer the original method route to a dispatcher.

`ContractQueryCodec` validates the bounded canonical target list and holds each
local known contract's complete immutable body until the query owner releases
it. A remote known digest grants no local body ownership. Unchanged responses
must match that exact pinned body; available responses must match the original
namespace, type and optional wanted digest. `ContractSnapshotWriter` owns the
full 9 KiB-per-target response allocation. It encodes one bounded shell or at
most 4 KiB of contract bytes per step, and exposes no payload before the entire
response is complete. Full/unchanged and refusal fields are disjoint; execution
responses require a matching Offer with the separately configured window bound.
The output allocation and contract pins survive cancellation until its actual
publication borrow exits.

`ContractQueryExchange` binds the actual encoded request, original target owner,
absolute deadline and full `RPCCompletion` before channel submission. The query
keeps its full response responsibility through cancellation and late input; the
channel selects the existing pre-BEGIN cancel or ABORT/STOP_OUTPUT path. A
complete response can be claimed once, with the exact targets that produced its
request bytes.

`ContractSnapshotReader` borrows that original response exclusively and reuses
one bounded envelope arena, one contract arena and a small Offer decoder. Its
closed schema traversal parses one atom, validates one field or applies one
bounded registry rule per step. Embedded bodies never acquire schema authority
from the envelope alone. A complete ServiceContract is copied and hashed in
steps that touch at most 4 KiB, then retained as immutable canonical bytes with
compact root field spans. Snapshots do not retain a decoder arena each.

Every available target is checked against the original namespace/type and
wanted digest. Unchanged results retain the exact original known body. Execution
Offers must match that body's digest and the independently configured window;
other semantics reject Offers. The reader exposes only a fully validated batch,
checks the original exchange deadline during decoding/delivery, and releases its
input borrow after all decoder/capture references detach. Delivery positions
are prepaid separately from the still-live response and retain the same full
per-target responsibility for unchanged and refusal variants. This codec grants
no source authorization or installation permission.

`ContractRoutes` keeps one explicit advertisement per declared method, up to
8 exact bodies and up to 8 distinct execution Offers per body. Offer renewal
preserves exact windows; ordinary replacement/withdrawal cannot remove an
unexpired promise. Only the service authority's trusted lower time bound proves
expiry. A query's wanted digest selects its exact registration; known only
selects body elision. Captured query selections pin the original body and
registration generation through publication.

`ContractQueryAccess` stores a finite per-method permission view under the
original Session delivery authorization lease. Undeclared targets are denied;
declared targets start unavailable until the trusted host sets their current
access. The fixed SDK lane reads these decisions without calling an application
authorizer or external store. Permission changes wake the original service and
invalidate publication generations.

`ContractQueryService` provides two protected complete response positions and
two small pending input positions shared by all ordinary channels. `ServiceInputs`
can attach it once for the trusted fixed query tuple. Pending input does not
admit a full read; it moves to a complete output position only when that
position's original references are free. Source lookup, encoding and publication
advance in bounded steps. Malformed target CBOR closes its original channel;
source/authorization/deadline failure uses the existing bounded refusal path.
The publisher rechecks original query deadlines, permission and registration
at actual fragment admission. Its last source borrow remains charged through
physical fragment cleanup, after the logical ReplySlot may already be free.

Bindings with installed `bounded` methods check the source's current advertised
contract every 60 seconds by default. `contractCheckIntervalMS` can select a
finite interval of at least 30 seconds. One charged timer per binding coalesces
its methods into batches of at most eight. Checks use ordinary query capacity;
exact Offer renewal has priority and keeps its protected opportunity. Methods
without an installed snapshot do not start background discovery.

The existing Refresh/Update installation gate validates each candidate's full
contract, acceptance ranges, local response default, authority and applicable
Offer. An explicit Update supersedes the older candidate's install right while
its actual query still owns cleanup. Failed or capacity-deferred checks preserve
the old usable snapshot. The next check is measured from actual work completion.
No check acquires material, reconnects, or changes the binding's source.

Static bindings read only their original trusted local snapshot interface during
Refresh, Update and scheduled checks. They do not fall back to remote queries or
reserve remote renewal protection. Immutable static Offers retain their original
expiry; checking cannot extend them. Closing the static source prevents further
source reads while already captured contracts and operations keep their existing
ownership. New Prepare calls capture the latest installed exact contract; older
prepared or submitted operations retain their own original snapshot. Binding
Close cancels the shared timer and installation rights and joins real query tails.

The original `ApplicationExecutor` can protect two incoming fixed-query
positions per participating Session. Its shared SDK lane reserves 256 KiB,
executes one bounded step per host turn and admits at most four actual ready
descriptors. Eight finite incoming descriptors cover four Sessions, rotating
between groups and original positions. Remaining eligible work stays in that
index; blocked inputs use a coalesced wake or their original deadline. Attachment
fences manual stepping. Group shutdown stops new work and joins the actual
running step without releasing live output tails.

One `RPCNetwork` owns the Session-wide general and fixed-query associations.
Its channel generations, serial high-water marks and live slots provide reply,
abort and stop matching without completed-serial history. Full response backing
is obtained before publication. Request aborts retain their outstanding position
until the matching bounded SDK response; normal responses and response aborts
end the original network association only after authenticated terminal input.

`RPCChannelRuntime` attaches a single reader and publisher to an authenticated
class-I `flowersec.rpc.v4` Stream. The publisher selects fragments using the
Q/general and request/completion fairness bounds. Its current conservative batch
contains one fragment. A protected immutable Stream write position takes the
whole selected fragment at a private synchronous admission gate, which commits
its serial and offset. The original Stream sender then advances the fragment
through real credit, record tickets, rekey and provider completion. Public raw
Write progress continues to describe the actual accepted prefix.

The private services/execution Session assembly reserves bootstrap scope 1
before publishing its own READY. The original admission batch includes both
generations of direction keys, the fixed 16 KiB receive promise, termination,
initializer and prefix output responsibility. The client also checks out its
original native protocol position and both send accounts before consumption.
Noise creates one private initial epoch; successful dual READY transfers that
same epoch and makes the existing bootstrap owner live without resetting any
direction. The scope consumes the client class-I active/lifetime position and
positive terminal token, advances only the client's allocator, and contributes
to the accepted boundary and rekey barrier even before physical binding.

After dual READY, one client initializer sends the real prefix over WS or its
single native stream. The server authenticates the fixed kind, empty metadata,
limit and current epoch/sequence, then binds that original owner. Bootstrap
does not send or wait for OPEN_ACCEPT. Its SDK Stream becomes available only
after the prefix gate; duplicate prefixes, changed native associations and
unexpected ACCEPT are rejected. Rekey retains an unmaterialized zero frontier
and resumes the same prefix owner. STOP/Drain revoke unused initialization,
retain in-flight provider work and close the original frontiers through normal
termination and retirement. The transport profile retains ordinary scope-1
OPEN behavior.

The public fixed-Session unary service client uses these original components.
Explicit services client configuration admits the RPC application graph before
consumption and preserves the signed profile and general-call limit. Complete
application baseline, remaining ordinary channels, provider scheduling isolation
and workload qualification remain incomplete. The execution profile connects
notification/management and explicit Node SQLite execution history through the
same application graph.

## Browser HTTPS live authority

`createV4BrowserLiveHTTPS(environment, options)` from the browser entry provides
an Environment-owned `V4LiveAuthorizationConfig` for the WSS client's
`liveAuthority`. `V4BrowserLiveHTTPSOptions` fixes the control authority,
tenant, audience, an explicit bearer calling credential and its expiry,
concurrency, timeout and SDK/native allowances. It sends the same bounded CBOR
request as Node to `<baseURL>/live/authorize`. The authority must authenticate
that credential independently and authorize the original caller and selected
attempt; the credential confers no issuer or signing authority.

`V4BrowserLiveHTTPSDeployment` binds a canonical HTTPS base URL and the exact
current application origin to an independently qualified operator deployment,
revision, validity window and evidence reference. Every browser-facing TLS
terminator, including proxies, must enforce TLS 1.3 and no early data. Its
control response uses identity encoding, a finite Content-Length and no
trailers. Cross-origin deployments must allow the explicit Authorization/CBOR
request and expose all response framing headers through CORS. JavaScript
cannot observe the actual TLS version or inspect headers hidden by CORS; this
adapter provides the `controlled_terminator` deployment boundary.

Each invocation performs one Fetch with redirects refused, cache disabled,
credentials omitted and no referrer. Ambient cookies are not calling
credentials. HTTP success remains untrusted: the existing live credential
closure still validates the full signed activation proof against its original
attempt, candidate, route and identities before HELLO. Invalid framing,
overflow, cancellation and expiry clear the output and never trigger a retry
or a source-profile switch.

Only complete bounded response bytes are copied into the admitted destination.
The request, reader and provider allowance remain owned through actual native
completion and cancellation. Fetch may buffer TLS, headers or body data before
JavaScript receives it; `providerBytes` is the deployment's qualified native
allowance, not a browser-wide memory cap. Browser runtime qualification remains
part of the final acceptance work.

## Fixed-Session unary services

Set `services: V4ClientServicesConfig` on the Node WSS, browser WSS or browser
WebTransport configuration to select an application Session. Its `profile`
defaults to `services`; select `execution` explicitly for execution methods.
The signed Session profile must match this fixed configuration. The trusted
configuration declares the exact local service definitions, method/capture
limits and built-in query type ID and contract digest. These values come from
the deployment, not from remote discovery. A deployment may instead create
`createV4StaticServiceContracts(environment, definition, inputs, { target,
maximumOfferWindowMS })` and pass the resulting `contractSource` to
`bindService`. Each supplied canonical `ServiceContract` and applicable
`AdmissionOffer` is fully decoded and checked against the exact local method
before the source is published; the source owns bounded decoder/body positions
and never performs remote query or stores application aliases. Bind retains the
installed bodies before the source may be closed, so a transferred binding and
its operations remain charged to their original method owners. Missing initial
methods, extra, noncanonical, mismatched or expired static entries fail the whole
bind; omitted noninitial methods remain `not_ready`.
The original Environment reserves
the RPC inputs, fixed queries, result positions and bootstrap channel before
consuming authorization. Services require at least 16 KiB receive capacity and
maximum write size; insufficient configuration fails admission.

Bind a definition to an already authenticated Session with the trusted tenant,
audience, local subject, service authority and allowed peer identity digests:

```ts
const service = await session.bindService(definition, bindingOptions);
try {
  const operation = await service.prepareOperation(definition.methods.echo, "hello");
  try {
    const started = operation.start();
    if (started.status === "not_admitted") throw new Error(started.reason);
    const result = await operation.takeResult();
    try {
      if (result.kind === "value" && result.encoding === "typed") {
        console.log(result.value);
      }
      // Handle typed application errors, SDK errors and metadata outcomes here.
    } finally {
      if ("release" in result) result.release();
    }
  } finally {
    operation.close();
  }
} finally {
  service.close();
}
```

`service.call(method, request, options)` performs the same Prepare, Start and
result collection in one hidden scope. Its public Promise is the original
exchange's final recipient. No second result store, query or invocation is
created. Both forms use the exact installed contract, original resource
reservations and immutable request. Prepare alone sends no request.

`takeEncodedResult()` selects the complete encoded payload without entering an
application decoder. Typed and encoded collection share one payload; a result
cannot be delivered twice. The controlled result shell keeps the business
value or error in a field. Release the result after use, including when the
operation has already closed: its original backing stays charged until release.
Status observation does not consume a result.

Service Close ends its hidden convenience calls and local binding work. An
explicitly transferred operation keeps its independent lifetime and can Start
after the service closes while its original Session and deadline remain valid.
Neither service nor operation Close closes the borrowed Session or requests
remote execution cancellation. `refresh` and `updateContract` are explicit
contract-management calls; ordinary Call does not discover or silently refresh.

Inbound transient unary handlers use the original trusted Session application
plan, registered full contract and explicit per-method query permissions.
Query visibility defaults to unavailable and does not bypass the handler's
separate authorization. The handler and response codecs run in the original
application executor. Server streaming and durable Node notification execution
use that same executor and history owner. Controller integration, the complete
multi-channel ready-minimum and workload qualification remain implementation
work. Encrypted in-memory connectivity checks do not establish native-provider
or cross-language qualification.

### Volatile execution unary

An inbound execution method's trusted Session application plan supplies its
stable logical service tuple, caller authority domains, finite record/active
limits, result allowance, full volatile contract and exact AdmissionOffer.
The plan also maps this Session's authenticated peer certificate to a stable
caller authority and subject. A different current certificate may map to the
same principal; certificate fingerprints never enter the execution key.

The Environment retains one execution history per logical service across its
Sessions and bindings. First registration follows full input/digest validation
and current authorization, checks the original Offer, cutoff and horizon, and
reserves a history slot, active execution and complete retained result before
request decoding or handler entry. Duplicate key/digest requests join the same
record; they release their ordinary application permit while waiting. Changing
the payload, method, contract or immutable request options under the same key
returns `operation_conflict` and cannot dispatch another handler.

The original handler's encoded outcome enters history before response
publication. A later duplicate can read the retained outcome through its own
response position without another decoder/handler invocation. STOP_OUTPUT
only withdraws that response's output interest. Session Close preserves the
history and actual callback charges; it never grants the same key a new Start.
Failed or interrupted dispatched work remains unknown unless its actual result
was committed. Business errors preserve their original typed catalog code.

The wire deadline and admission cutoff stay fixed even when the Session
imposes an earlier local safety deadline; local lifetime cannot rewrite the
request digest or shorten the promised history anchor. History retention is
anchored to the original wire deadline. Result retention
starts at actual result formation. Bounded GC installs the original caller
domain's rejection floor before deleting eligible key details, and cannot
reclaim active callbacks or retained attempts. Resource pressure refuses new
registrations instead of discarding history. Environment Close seals this
owner, cooperatively closes active work and waits for real exit before refund.

Execution clients configure `localExecutionAuthority` as the trusted stable
caller domain. A prepared `V4ExecutionUnaryOperation` exposes `reference()`;
transient `V4UnaryOperation` has no reference method. The immutable reference
captures the original key/digests, wire deadline, execution/cancel policy and
trusted service destination. It retains no Session, request payload, Start or
replay capability. `session.queryOperation(reference)` and
`session.requestCancel(reference)` verify the chosen Session against that
original destination and its current authorization.

`createV4OperationReferenceCodec(environment)` owns a bounded canonical
persistence workspace. `export(reference, destination)` copies the complete
reference into caller-owned storage and returns its length. `import(bytes,
expectedDomain)` checks the fixed schema and the exact trusted local domain;
it returns only an immutable reference. The codec performs no storage I/O,
connection, Prepare or Start. Closing the codec does not invalidate references
already transferred to the caller.

A Session resolves imported references through its trusted
`services.referenceTargets` configuration, a bounded list of logical authority,
tenant, audience, local subject and permitted authenticated peers. These mappings
never come from saved bytes. A current configured mapping also replaces the
captured mapping for locally prepared references, allowing a new authorized
Session to use a configured certificate rotation. Ordinary current caller and
namespace authorization still apply. Unresolved imported domains are refused.
Reference fields are selectors, not proof that an execution exists or credentials
that grant access. Import rejects unknown versions, invalid shapes, zero identity
digests and inconsistent operation cutoff/deadline values.

For a different authenticated caller, configure explicit `executionDelegations`
on the outgoing and incoming Session plans. Each grant binds one direction,
namespace, authenticated principal authority/subject, original record caller
authority/subject, independent query/cancel permissions and `notAfterMS`.
Incoming plans additionally require the current certificate-bound
`executionIdentity` and the corresponding `executionPermissions`. At most 64
immutable grants are admitted per Session, with metadata charged at admission.
The signed Session authorization and trusted time cutoff are checked before
lookup, again at management publication, and for each retained-result fragment.
A reference never installs a grant or replaces its original caller in the lookup
key. To change an immutable plan's local grants, close that Session and establish
another with the explicitly chosen policy.

A new server Session attaches `executionServices` with the same Environment
namespace and configuration to use its existing execution history and retained
results; it need not register another business handler. This preserves history
across Session closure while that Environment remains alive. It does not recover
volatile records after Environment shutdown or process restart.

`service.prepareAndSave(method, value, store, options)` keeps an execution unary
candidate private until the store explicitly confirms durable persistence.
It returns `{ status: "prepared", operation, reference, save }` only after the
original deadline, caller cancellation and binding are checked again at public
handoff. The method does not Start. Otherwise it returns `not_prepared` with a
bounded reason, the known local save outcome, cleanup snapshot and any reference
already created. A saved reference never proves server registration or execution.
Transient methods are refused before encoding or invoking the store. Calls made
with a context holding an application execution permit return
`admission_mode_incompatible` before encoding or store entry; PrepareAndSave
does not wait on storage while holding that application permit.

Register an optional trusted application adapter with
`createV4OperationReferenceStore(environment, policy, save)`. The policy fixes its
target domain, `durable_create_or_compare` contract, application-owned storage,
record/canonical-byte quota, retention, concurrent saves, callback byte allowance
and ordinary work class. The application backend enforces its shared record and
byte limits, durable transactions, expiration and deletion; backend pages and
indexes remain application-owned. The SDK admits bounded actual callback jobs
and refuses excess concurrent saves before Start. This registration does not
provide a database or validate a backend's physical durability claims.

The callback receives only a query-only reference, its complete canonical bytes,
logical identity and fixed retention deadline. It atomically creates a missing
identity or compares all saved canonical bytes with the existing identity;
different bytes are a conflict. `confirmed` means the actual durable transaction
has completed, including an already committed identical value. Ambiguous commits
return `unknown`. Borrowed canonical bytes remain valid until the callback truly
settles; a backend that retains bytes must copy them into its own storage.

Cancellation, Session/binding Close, preparation expiry and adapter Close seal
the private candidate. They can return promptly with `unknown` after callback
entry while its original slot, buffers and application permit remain occupied.
Late confirmation cannot return or reactivate an operation. Closing the SDK
adapter does not delete application-owned saved records or invalidate an already
handed-off operation. Import remains query-only; no readback or background outbox
can recover Start authority. Ordinary volatile calls do not require this adapter.

The canonical persistence format has no response-limit field. An imported unary
read therefore reserves the full 1 MiB protocol result bound before BEGIN;
a local reference retains its original tighter bound. This may refuse locally
when full response capacity is unavailable. Imported streaming/notify references
can use Query/Cancel, but cannot request a unary retained-result read.

The execution profile initializes its fixed management channel after READY.
If M fails, one initializer waits for the previous generation's actual tasks,
physical resources and retirement proof before reusing its protected positions.
Each replacement consumes the next client ordinal, with at most 16 M allocations
per Session. A recovery cycle keeps its original 30-second deadline; Drain and
GOAWAY prohibit replacement. Ordinary RPC results remain independent of M.
BindService also waits under its original deadline for the preadmitted bootstrap
channel to become usable after its local publication tail exits.
It has separate pre-admitted M capacity, parser, two pending request positions,
two bounded replies and a protected Stream output. Query/cancel permissions
are trusted per-namespace grants and default to denied. They are independent
of contract visibility and handler admission; old records do not need a new
Offer. `executionServices` can attach the same Environment history even when
this Session advertises no corresponding business handler.

Query returns only bounded execution and retained-result metadata. A missing
volatile record returns `history_unknown` because a remote reference alone
does not establish uninterrupted RAM history. Cancel on a cooperative contract
confirms `requested` for the original existing record, then signals its handler;
it does not assert callback exit or retract results. A completed operation
returns `terminal`. Cancellation before registration creates no tombstone.
Close does not implicitly request remote execution cancellation.

Execution configurations can install `resultRead: { typeID, contractDigest }`
from the deployment's trusted fixed SDK contract. Then
`session.readOperationResult(reference, { timeoutMS, signal, context })` admits
one ordinary RPC read and returns a `V4OperationResultRead`. It uses general K
and the original complete response reservation before BEGIN. The reference's
locally captured original response limit supplies the bound; it is not a
result-availability promise. This path does not use management or contract-query
capacity and needs neither a current handler advertisement nor a new Offer.

`read.takeResult()` returns the fixed SDK method's `Uint8Array` value;
`read.takeEncodedResult()` returns the same original encoded business-result
bytes as `bytes`. Both compete for one result, with `kind: "retained_result"`
and an explicit `release()`. They do not select a business decoder or infer
success from arbitrary payload. QueryOperation supplies the original business
error code, digest and retention metadata when the application needs them.
Status/wait and Close reuse the original unary completion engine. Canceling a
result wait detaches that waiter; canceling the read or closing it stops only
this read, never the execution. A result already completely received retains
its independent local safety gate.

The server checks current query permission before exact original key/digest
lookup. It pins the immutable original result through actual publication tails
and repeats authorization, request deadline and retention checks before each
bounded fragment. Concurrent reads share that backing with separately charged
read metadata. Expiration before BEGIN returns `result_expired`; after BEGIN
it aborts that response. Missing or unfinished results use the fixed RPC
`service_unavailable` refusal; explicit Query distinguishes history observations.
A prior `result_available` observation does not reserve this later download.
Drain refuses new result reads while an existing M channel can still query or
request cancellation.

Inbound plans accept durable contracts only with the original Node SQLite
execution service capability and its persisted exact contract/Offer registration.
Checkpoint formats and retained stream-content promises require the matching
store configuration described below. Restart-flush additionally requires the
original bounded maintenance owner described below. Reference metadata lifetime
accounting, complete protection under saturation and workload/preset
qualification remain implementation work. Closing or losing a volatile
Environment does not preserve its RAM history or establish trusted absence.

## Observation notifications

A bound observation method supports `service.notify(method, value, options)` and
`service.prepareOperation(method, value, options)`. The latter returns a
`V4ObservationNotifyOperation` with `start`, `status`, `waitSubmission`, `close`
and `cleanupStatus`. It has no response decoder, result or execution reference.
`submitted` records complete local submission only; it does not confirm peer
receipt, handler entry or success.

Binding a definition containing notification methods prepares its Session's
fixed internal notification channel. The Environment reserves its original
channel resources before consuming connection authorization. Prepare and Start
use an existing channel and immutable method snapshot. Framing is a two-byte
big-endian canonical-header length followed by that header and its declared
payload. It does not allocate ordinary RPC reply/completion resources.

Closing an unsubmitted operation prevents publication. Once its prefix has
been admitted, the original owner preserves the complete serial message tail;
an actual publication failure terminates the channel. Receiver authorization
refusals and callback failures are local and produce no response or NACK.

`session.notifications.subscribe(method, handler, options)` registers a local
typed observer and returns `V4NotificationSubscription`. Incoming observation
methods can be declared in `services.notificationMethods` using their exact
definition, canonical contract bytes and current permission; no placeholder
business handler is required. A selector belongs to one incoming namespace.
Distinct methods with the same type ID in different namespaces remain isolated.
Registration sends no subscription frame and never replays an earlier event.

Each subscription decodes its own mutable input and runs serially. Optional
`project(context, value)` changes only that observer's value. Decoder, projection
and handler errors affect only that delivery and appear in `observationStatus()`.
The default `pendingPolicy: "drop_newest"` retains up to sixteen pending items.
`latest_pending` keeps one logical pending value and applies only to observation
methods whose values replace the token's entire observation domain. Filtering
inside a callback does not narrow that domain. Already entered application code
cannot be replaced; superseded tasks retain their resources until they exit.

`close()` and `unsubscribe()` seal dispatch immediately. `waitClosed()` is a
passive bounded wait: it never closes the subscription. Waiting from a callback
with its original `context` detects dependence on that callback's own exit.
The wait reports `dependency_unavailable` without marking the subscription's
eventual cleanup as failed. Closed registrations occupy their original slot
until actual tasks exit. Limits are 32 observer registrations per method and
128 per Session; the unique business handler has separate ownership.

```ts
const subscription = session.notifications.subscribe(definition.methods.changed,
  async (context, value) => render(value),
  { workClass: "short", applicationBytes: 4096n, authorization: "authenticated" });

subscription.close();
const closed = await subscription.waitClosed({ timeoutMS: 5000n });
```

## Execution notifications

A notification method declared with `notifySemantics: "execution"` uses its
exact execution contract and AdmissionOffer. `prepareOperation` returns
`V4ExecutionNotifyOperation`, adding a query-only `reference()` to the same
submission lifecycle. Its immutable ID contains the original admission cutoff,
and the request digest binds the contract, payload and deadline. The operation
has no result reader, response completion or reply allocation.

The receiver shares the Environment's execution history with unary and streaming
operations. A Node service may install the original SQLite store capability to
persist that history; ordinary volatile services require no database. After current authorization and complete-input validation,
the original key controls one business dispatch and one observer fanout.
Duplicates use the existing record; conflicting bytes cannot dispatch again.
Observers registered after complete-message admission receive no old event.
Handler success records `completed` with no result payload. Query and cooperative
Cancel use the existing management channel; a notification reference cannot be
used with `readOperationResult`. The original execution and local application
deadlines bound callback continuation, while cleanup follows actual exit.

`prepareAndSave(method, value, store, options)` also supports execution
notifications through the same registered ReferenceStore. Only confirmed
create-or-compare and a valid original delivery gate return the operation.
The caller explicitly invokes Start afterward. Export/import uses the canonical
reference format with notify shape, and does not grant Start or replay rights.

## Durable Node execution history

`openV4SQLiteExecutionStore` uses the same live execution owner for unary,
notification and server-streaming execution. Install each full contract and
its exact finite Offer windows through `installContract`; reopen assembly can
read the original bytes and windows with `readRegistration`. The frozen
`store.service` capability binds handler and management-only registrations to
that storage authority. It cannot be reproduced by copying configuration.

The store persists dispatch before application entry. Notification success
commits `completed` without inventing a result payload. Streaming success or
application error commits terminal execution metadata before EOF or error
publication. Error encoding and contract validation precede that transaction;
failed encoding cannot become a published business terminal. With
`stream_content_policy=none`, explicit reopen restores state and error code,
not stream items. A duplicate cannot replay the producer; use Query for its
original execution facts. Notification references and these streaming
references are not unary result-read capabilities.

Explicit reopen requires independent proof of complete history and settlement
or fencing of old actual work. Existing records preserve known outcomes;
unresolved dispatched work becomes unknown without new dispatch permission.
Within proven complete history, an atomic absent-record query above its domain
floor returns `not_found`, and cancellation returns `not_registered` without
writing a tombstone. The original request may still register later. A missing
record at or below the floor returns `history_unknown`; inability to obtain the
current authoritative read returns `unavailable`. Volatile absence retains its
separate continuous-owner requirements. A durable cancellation signal is
issued only after the original cancel marker transaction is confirmed.

The store's own close waits for live execution and publication tails. Disk
charges survive connection and Environment close while database files remain.
Qualified independent scheduling of synchronous SQLite I/O requires further
integration.


## Response publication and maintenance

A unary `MethodDefinition` can declare `restartFlush: true` with
`restartFlushDeadlineMS` in 1–120000 milliseconds. Create a bounded
`V4MaintenanceOwner` with `createV4MaintenanceOwner(environment,
maxObservations)` in the application's existing maintenance lifecycle, then
supply that same `maintenanceOwner` in the trusted inbound application plan.
Both Session roles use this capability. Registration rejects a missing, closed
or foreign owner before publishing the method. The owner reserves finite
observation capacity; it starts no maintenance task or background application
executor.

Before application entry, the original response budget acquires one pending
observation. `context.responsePublication` is the same read-only view on each
access; ordinary unary methods expose `not_applicable` and no maintenance
owner. A restart handler can call
`context.responsePublication.transferTo(context.maintenanceOwner)` once and
hand the view to its existing restarter before returning. Transfer reports
`success`, `already_transferred`, `owner_unavailable`, `expired` or `invalid`.
It grants observation and cleanup responsibility only. The handler must return
its normal result instead of waiting for its own response to be published.

After response encoding, the original publisher binds that view to the
selected response's final fragment. The fixed flush deadline begins at this
handoff to the original publication owner, bounded by the earlier request and
security deadlines. `state()` and `wait({ signal })` return `pending`,
`flushed` or `unknown`; wait cancellation only cancels that wait. Up to four
waiters share the original bounded cell.

`flushed` means the complete original response reached the local provider's
irreversible handoff callback. It does not prove peer application receipt.
SDK replacement responses, ABORT, publisher loss, expiration and publication
failure settle `unknown` with a finite cause. A later provider completion
failure cannot reverse an already observed `flushed`. No shared-channel idle
wait, extra flush frame, FIN or new transmission path is introduced.

The application chooses its own maintenance policy for `unknown` and retains
its own operation deduplication. Closing the maintenance owner ends observation
waits without changing the publisher's outcome. `cleanupComplete()` waits for
actual publication tails to leave before reporting completion. Transferred
views retain their bounded observation positions until the maintenance owner
closes; create its capacity for the actual maintenance workflow.


## Explicit retained stream content

An execution streaming method can declare `streamContent` with a
`schemaRevision`, the complete canonical application `canonical` bytes (up to
2048 bytes), and `readTypeID`. The definition describes content selection,
position/reference encoding and bounds, the existing unary read method and its
request, response, missing and expired semantics. Both peers hold the same
local definition and bind its exact bytes to the ServiceContract. The read
method belongs to the same service and original execution store.

Configure that store with `content: { methods, maxItemsPerOperation,
maxBytesPerOperation, maxItemBytes }`. Each retained contract must fit those
caps. The store reserves content workspace and combined content/checkpoint
disk capacity before accepting work. Its persisted configuration must match on
reopen; reopening never resets quotas or retention origins.

Within the streaming handler, call `saveV4StreamContent(context, position,
payload)` for explicitly selected bytes. Positions contain 1–256 bytes. Normal
`writer.write` does not save content. A successful save returns committed and
expiry timestamps, byte length and digest; saving the same position and bytes
returns the original observation without extending its lifetime. Conflicting
bytes at the same position fail. The retention origin is the original
operation admission or that position's first content commit, as declared in
the exact contract. Saved content does not make the stream a unary retained
result and does not replay the producer.

The declared execution unary reader calls `readV4RetainedContent(context,
target, position, destination)` after its normal authentication and invocation
admission. The target must belong to the current caller, tenant, audience and
namespace. The store checks the original operation and request/contract
digests, and the registered read method. Available bytes enter the supplied
buffer only after the transaction and current invocation guard succeed.
Missing positions and expired content have distinct observations; missing
history is an error. The application encodes these observations using its
shared content definition and normal response codec. Read/save capabilities
expire with their invocation. SDK event-source setup and mapper invocations
receive the same explicit save capability during their active application
phase.

This adapter supports durable content with an execution unary reader. Volatile
content, transient or delegated read methods, and their complete failure and
capacity matrices remain implementation work. Closing the store retains disk
charges until the original backing files have actually been removed.


## Explicit checkpoint issuance

A Node execution store may enable `checkpoint` with an independent application
`signingKey`: either `{ protection: "hmac_sha256", keyID, macKey }` or
`{ protection: "ed25519", keyID, seed }`. IDs are 16 bytes; MAC keys and Ed25519
seeds are 32 bytes. The simple `keyID`/`macKey` configuration also supports a
single MAC key. Never supply a Session or traffic secret as a recovery key.

The original SQLite store owns explicit token count, byte, per-operation and
issuance-window limits across Sessions and reopen. Reopen requires those same
limits, service identity and independent continuity proof. The trusted local
configuration may select a new issuance key and retain up to seven additional
`verificationKeys`: MAC entries carry `macKey`; Ed25519 entries carry only
`publicKey`. All eight possible key IDs must be distinct. Omitting a key revokes
its recovery authority; it does not erase historical results or sign replacement
tokens. Key changes do not reset generation, counts, token bytes or expiry.
Provision separate stores for separate service authorities.

Register the source execution method with its `checkpointFormat` and matching
ServiceContract. Register a separate durable unary issuance method using the
bytes response codec and enough response capacity for the complete token. In
that method's authorized handler, select the result with:

```ts
return issueV4Checkpoint(context, originalTarget,
  { format: "position-v1", position: retainedPosition },
  { durationMS: 60_000n, applicationDurationLimitMS: 60_000n,
    historyNotAfterMS: actualCheckpointAvailabilityDeadline });
```

`originalTarget` contains the original operation, request and contract digests,
stable caller authority and subject, tenant, audience and service namespace.
The current invocation must belong to that same caller and service. Its own
operation is distinct. The application is responsible for retaining the stated
business checkpoint. The SDK checks the original registered checkpoint format
and retained history before issuing the canonical `ResumeMACToken` or
`ResumeSignedToken` from the single wire registry.

Issuance requires the authenticated Session's selected application recovery
feature and signed resume policy. The SDK obtains those limits from verified
credentials; handler options cannot replace them. The token expires no later
than the trusted issuance lower bound plus the smallest requested, application
and signed duration, or the application checkpoint and original history
availability deadlines. Token bytes include the MAC or signature and must fit both policy
and ordinary response limits.

Token history, issuance counters and the issuing execution's complete token
result commit in one original transaction before publication. The invocation
cannot select another result or retry signing after an uncertain issuance.
Duplicate calls and `readOperationResult` return the same stored bytes without
renewal. Closing and explicitly reopening the Environment restores those bytes
and limits; an ambiguous commit remains unavailable until continuity is proved.
Result payload expiry cannot erase an unexpired token's original history.

Issuance and consumption use the store's single synchronous transaction
workspace. Independent SQLite provider scheduling remains unavailable through
this API.

## Recovering an accepted application Stream

Declare a separate durable execution unary method with SDK bytes request and
response codecs, at least 9,345 request bytes and 4,248 response bytes. Install
its contract, Offer, execution store and current authorization in the service's
unary registration. Bind the method to a trusted raw application kind with
`methods: [{ method: recover, resumeKind: "example/recover" }]` in `bindService`.
The remote token cannot supply this method or kind mapping.

On the receiving Session, register that raw kind with the same service method:

```ts
const registration = session.registerStream("example/recover", authorizeOpen,
  async (stream, context, metadata) => {
    const { checkpoint, generation } = v4RecoveryProgress(context);
    await continueBusiness(stream, checkpoint, generation, context, metadata);
  }, {
    applicationBytes: 8192n,
    resume: { namespace: serviceDefinition.namespace, method: recover },
  });
```

The SDK runs the recovery prelude before this raw handler. It uses the original
bounded request input and execution registration, verifies the independent MAC
and authenticated caller, then commits token consumption, generation advance,
actual transport context/Stream binding and the recovery result in one store
transaction. Only a newly accepted recovery enters the raw handler. The unary
business callback is not invoked for a reserved recovery request. A repeated
execution observes its original result and cannot dispatch another handler.

The caller explicitly opens the Stream before preparation:

```ts
const target = await session.openStream("example/recover");
const saved = await service.prepareResumeAndSave(recover, target, token, referenceStore);
if (saved.status !== "prepared") throw new Error(saved.reason);
const operation = saved.operation;
try {
  const started = operation.start();
  if (started.status !== "admitted") throw new Error(started.reason);
  const result = await operation.takeResult();
  try {
    if (result.kind === "value" && result.encoding === "typed" &&
        result.value.status === "accepted") {
      await continueClient(target, result.value.checkpoint, result.value.generation);
    }
  } finally {
    if ("release" in result) result.release();
  }
} finally {
  operation.close();
  await target.close();
}
```

`prepareResume` skips reference storage. `resume` composes the same preparation
and explicit Start and returns the same execution operation handle. Typed
results contain `accepted`, `rejected` or `unknown` and any confirmed checkpoint
and generation; `takeEncodedResult` returns the canonical `ResumeResult` bytes.
Preparation captures the exact bound Session and accepted Stream before making
an operation ID or saving a reference. It rejects existing raw I/O, cursors and
other message owners. It never creates, replaces or retries the target.

An unused preparation returns its target qualification on Close after actual
local work exits. Canceling a reference-save wait does not detach a still
running save task from that responsibility. After submission, Close abandons
result delivery while the original finite sender/response task retains the
message qualification. It returns that qualification only after one complete
request and one validated response, with actual I/O tails settled; malformed or
unsettled input terminates the target Stream. Complete recovery preserves
following application bytes and leaves the same target available to its owner.
Closing a completed operation does not reset it.

Saved references are query-only on import. Query and result-read return the
original recovery facts without consuming another token or binding a new target.
The independently configured verification keys and original store responsibility
survive an explicitly proven reopen. Existing tokens keep their original expiry
even when a new Session's issuance policy permits a shorter duration. The SDK
selects the canonical protection variant from the complete token; the consumer
requires both the matching trusted key ID and protection type before accessing
the original consumption transaction.


## Explicit Controller publication and fixed Session interactions

`createV4ConnectionController(environment, config)` borrows the original
Environment and its registered material source. `start()` begins the initial
connection attempt; `waitForSession()` observes publication without acquiring
materials. Canceling that wait only removes the waiter. `captureSession()`
returns the same authenticated, accepting public Session at the dispatch gate.
It performs no acquisition or OPEN. Use that captured Session for all RPC,
notification and Stream operations belonging to one fixed interaction.

```ts
const controller = createV4ConnectionController(environment, {
  source,
  requirements: {
    independent_reliable_read_progress: false,
    bound_stream_input_isolation: false,
    datagram: false,
    local_consumer_tls13_verification: false,
    application_profile: "services",
  },
});
controller.start();
const original = await controller.waitForSession({ signal });
const service = await original.bindService(definition, bindOptions);
const prepared = await service.prepareOperation(echoMethod, request);

const replacement = await controller.replaceSession({
  retirement: "retain",
  retainUntilMS: authorizedOverlapDeadlineMS,
  signal,
});
// The prepared operation and this service still belong to original.
prepared.start();
const result = await prepared.takeResult();
// Independent new interactions capture replacement.current.
```

`createV4ServiceClient` constructs the same typed service with explicit source
ownership. For an owned Controller, supply its configuration and the borrowed
Environment:

```ts
const service = await createV4ServiceClient(definition, {
  ownership: "owned",
  environment,
  controller: { source, requirements },
}, bindOptions);
const result = await service.call(echoMethod, request);
if ("release" in result) result.release();
service.close();
```

The factory reserves the actual binding, snapshot and initial query positions before source
acquisition, initializes through the Controller's original connection path once,
and binds through the existing Session query owner. The Bind timeout is the
whole initialization deadline, including acquisition and READY; the Controller
attempt may have a tighter deadline. Failure closes only this factory's binding
and Controller. Service Close seals the binding and closes its owned Controller;
Environment Close and cleanup observation remain with the application's
Environment owner. Closing the owned Controller also closes its Sessions.

For an existing Controller, use
`createV4ServiceClient(definition, { ownership: "borrowed", controller }, bindOptions)`.
This form performs the same passive Bind as `controller.bindService`: it never
starts acquisition and never closes the borrowed Controller. Returned operation
handles retain their ordinary independent lifecycle. Both forms expose all
methods from the original definition and honor the same `initialMethods`,
contract policies, typed results and explicit Prepare APIs.

For explicit interactive/bulk routing, use the same factory and provide one
route for every method. Routes are local configuration and never inferred from
names or payload sizes:

```ts
const service = await createV4ServiceClient(definition, {
  groups: {
    interactive: {
      ownership: "owned", environment,
      controller: { source: interactiveSource, requirements },
    },
    bulk: {
      ownership: "owned", environment,
      controller: { source: bulkSource, requirements },
    },
  },
  routes: [
    { method: statMethod, group: "interactive" },
    { method: downloadMethod, group: "bulk" },
  ],
}, bindOptions);
```

Each group can instead borrow an existing Controller. An optional group
`target` supplies its trusted peer mapping; authority, tenant, audience and
caller must match the service target. Missing, duplicate and foreign methods
are rejected before Bind. Each group owns only its assigned method slots,
initial snapshots and renewal memberships. `initialMethods` is intersected
with that subset: a group with no initial methods still establishes its owned
connection, and its methods need explicit Refresh before use.

Before either owned group acquires material, the factory reserves both actual
Session/preauth vectors, binding positions, initial query positions and declared
initializer resources. Connections initialize serially within the original
bounded deadline, allowing a shared Environment with one acquisition slot.
Both groups must finish before the service is delivered. A local reservation
failure spends no material; network or remote failures may occur after one
connection succeeds. Failure closes only factory-owned resources. Reservations
from separate Environments remain charged to their respective budgets.

Call, Prepare, Notify, contract refresh and updates use the assigned original
binding. A failed group never falls back to the other group. Resume retains
its original target owner checks. Service Close seals both binding gates before
closing their work and owned Controllers. Borrowed Controllers remain open,
and explicitly transferred operations retain their independent lifecycle.
Two method subsets share one public service-root limit in a shared Environment;
method, candidate and query limits remain aggregate. Two steady connections
consume two actual Session slots. This constructor does not reserve replacement
headroom: later replacement still requires actual available capacity.

Use `controller.bindService(definition, bindOptions)` when the application needs
one service handle across connection replacement:

```ts
const service = await controller.bindService(definition, bindOptions);
const prepared = await service.prepareOperation(echoMethod, request);
await controller.replaceSession({ retirement: "retain", retainUntilMS });
const currentResult = await service.call(echoMethod, request);
// This operation still starts on the Session captured by Prepare.
prepared.start();
const originalResult = await prepared.takeEncodedResult();
service.close();
```

Binding borrows the Controller. It never calls `start()`, `retryNow()`, or the
material source. With no accepting Session, Bind and queued calls passively
wait for existing Controller progress within their original deadline and bounded
waiter capacity. Cancellation removes only that wait. Calls made while an
initializer holds publication wait for its result; a blocked initializer rejects
new work. Calls with an application permit or `try_now` do not wait for a new
Session.

The binding retains its original method snapshots, target, local defaults and
acceptance policy. A new current Session does not approve a new exact contract.
`updateContract` explicitly approves a digest for future operations; submitted
and independently prepared operations retain their original Session and digest.
Remote refresh installation is checked against the source incarnation that
started it. Renewal membership keeps the same Controller group and authority;
Session query protection is reacquired from the selected Session rather than
reusing another Session's reservation. Session query deadlines are bounded by
both the caller's deadline and that Session's safety cap.

A newly published accepting incarnation wakes managed Offer memberships that
were blocked by the preceding source. The shared scheduler keeps the original
logical group, exact digest, method count, backoff and renewal deadline; it does
not bind again or acquire material. An old query must release its physical tail
before the pending source notification can start another renewal. A rejected
query leaves the prior exact snapshot installed and usable only within its
actual Offer window. Recovery on a new source installs only a valid Offer for
that same digest, through the normal method installation gate.

Explicit `preacceptStream` and `requiredForDispatch` streaming declarations
follow Controller publication. Once a new current is accepting, the binding
moves its demand to that Session's existing finite accepted pool, preserving the
captured kind, metadata and exact contract. The pool owns OPEN, replenishment and
physical cleanup. `try_now` only checks out a ready entry; it never creates a
pool or waits for a replacement entry. If migration cannot obtain capacity,
Start reports `not_ready`; an explicit refresh can retry the declared demand.
Previously transferred streams remain on their original Session and keep their
independent result and cleanup lifetime. Prepared notifications likewise retain
their original route; a new notification selects the published current.

Controller-bound `prepareResume`, `prepareResumeAndSave` and `resume` select the
Session that owns the supplied original target Stream. An explicitly retained
Session is eligible while it is still accepting and authorized. A current from
another Session cannot replace that target, even when identities match. The
original target qualification precedes operation ID creation and reference
saving; an unavailable target fails without acquiring a connection or retrying
on current. An initialization block still seals new Resume work.

Closing an old Session does not close a Controller-owned binding. Service Close
seals its new work and convenience calls, leaves explicitly transferred handles
independent, and does not close the borrowed Controller or Environment.

Replacement uses the original Environment connection path and a fresh material
acquisition. The Environment reserves a Session position before invoking the
source and transfers that position into preparation/admission. Each replacement
has one finite attempt timeout, defaulting to 90 seconds. The default retirement
is the original Session Drain with a 30-second timeout. Explicit `retain`
requires an absolute deadline within the original Session's safety cap and
keeps its accepting state until retirement or that deadline. It grants no new
remote authority or overlap permission. There is one retired position, including
its actual cleanup tails; another replacement fails before Acquire while that
position remains occupied.

An optional `initializeSession(context, candidate)` runs once on the fixed
candidate after authenticated READY and before current publication. It requires
an explicit `initializeApplicationBytes` allowance and uses the original root
application executor with `initializeWorkClass` (`short` by default). Before
Acquire, the attempt reserves one position in that executor's existing ordinary
and, when selected, resident limits. The reservation is not a running callback
and creates no ready-queue job. Other work cannot claim the reserved position.
If capacity is unavailable or existing ordinary work is queued, the attempt
fails locally with `resource_exhausted` before calling the source. After READY
and dependency preparation, callback entry converts the same position and group
reference into its running permit, without a second admission or queue wait.
Session admission reserves the cryptographic counter pairs for the fixed
bootstrap, notification, and enabled execution-management channels before
Acquire. Ordinary streams cannot consume these positions. Management rebuilds
reuse a pair only after both key generations and their actual work have exited;
releasing memory or closing a waiter does not reset cryptographic usage or the
per-epoch derivation history. Declared required streaming calls also prepare
their send and receive counter pairs before Acquire and transfer them through
the original OPEN path.

The initializer's actual callback retains its permit through asynchronous work and
cancellation. Candidate and attempt safety gates are checked again before
publication. `initializeServices` declares the fixed candidate methods available
as `context.services`. Required methods are prepared before the callback enters
its reserved position, using the original Bind, contract query and accepted
channel/Stream owners. `initializeStreams` is the corresponding declarative
path for raw application Stream handlers. Each entry supplies a canonical
`kind`, optional authorizer, handler, and the same `V4StreamRegistrationOptions`
used by `Session.registerStream`. The Controller validates the kind, handler,
metadata contract, resume binding, concurrency, and application caps before the
first Acquire. Each candidate prepays the original registration, application
executor positions, and accepted direction/termination/decoder/cursor resources
for its first `maxConcurrentStreams` incoming attempts. READY transfers these
owners to the private candidate through the existing Session registration before
publishing `current`. The original cryptographic ledger also exists before
Acquire: the declared initial send and peer-OPEN receive directions hold actual
counter positions for both key generations. These positions have no scope until
a real OPEN binds them, and preparation performs no key derivation. The peer-OPEN
positions belong to the Session because its encrypted kind is not known before
authentication; no remote kind can claim a different registration's authority. An exhausted declaration fails before source acquisition;
an unused preparation is released on failure. After this initial work is
consumed, further incoming attempts use normal Session admission. Registration cleanup remains owned by that
candidate Session; retirement closes the old handler generation according to
the selected retain/drain policy without moving or replaying accepted Streams.
Cancellation or Close revokes an unused callback position. Once entered, only
the callback's actual exit returns the running position; logical cancellation
does not refund it. An explicit replacement can retry a local capacity failure
after the application's chosen waiting or recovery policy.

While initialization runs, Capture is closed and passive Wait remains pending.
An initializer failure or cancellation blocks Capture and Wait publication;
previously captured Session handles continue only under their original gates.
`start()` never reruns an already started initialization. Application-controlled
recovery uses an explicit `replaceSession()` after resolving its own registration
facts. Initialization failure does not prove that a remote action was rolled
back. `status()` exposes attempts, pending/retired positions, initialization
blocking, a bounded error fact and cleanup state.

`close()` cancels the attempt and closes owned Sessions, preserving an accurate
`cleanup_incomplete` result if real work outlives its bounded wait.

Before the first current is published, a source/provider failure may carry an
absolute `retryAfterMS` (or `retryAfterUnixMS`) deadline. The controller combines
that trusted wall-clock gate with its deterministic 250 ms to 30 s backoff;
`retryNow()` can skip only the monotonic backoff and returns `false` while the
absolute gate is still in force. Every candidate attempt receives a monotonic
opaque source generation, while the published current generation is available
from `status()` for local handoff/observation bookkeeping.
`waitCleanup()` observes actual Controller cleanup; canceling it does not release
owned work. Retired positions are released by the Session's actual cleanup
completion notification, never by a timeout result from Session WaitCleanup.
Closing the Controller does not close its borrowed Environment. Close each
ServiceClient and transferred operation/result according to its own ownership.


### Candidate initializer service dependencies

A `v4ServiceDependency(definition, options)` is an immutable local declaration.
Select the exact typed methods visible to the callback and their original
binding configuration. `dispatchRequirements` defaults each selected method to
`required_for_dispatch`; `on_use` explicitly permits initialization to enter
without that method's snapshot or path. Neither setting changes the contract or
wire protocol.

```ts
const registration = v4ServiceDependency(controlDefinition, {
  binding: { target: controlTarget, maximumOfferWindowMS: 10000n },
  methods: { register: registerMethod, cachedLookup: lookupMethod },
  dispatchRequirements: { cachedLookup: "on_use" },
});
const controller = createV4ConnectionController(environment, {
  source,
  requirements,
  initializeApplicationBytes: 4096n,
  initializeServices: { control: registration },
  async initializeSession(context, candidate) {
    const result = await context.services.control.register(registrationRequest);
    try {
      if (result.kind !== "value") throw new Error("registration_failed");
      // Validate the application's authoritative registration result here.
    } finally {
      if ("release" in result) result.release();
    }
  },
});
```

The declaration supports at most 64 service aliases and 128 selected method
references. Compatible aliases for the same definition, target and binding
policy share a candidate binding; their required methods form one union.
Before Acquire, each distinct binding claims its original Environment method
positions, current snapshot backing and bounded delivery batch. Descriptor-only
bindings retain their local positions without querying optional methods. After
READY, Bind adopts the same reservation exactly once, checking the original
captured configuration and pool identity. A reservation cannot be reused for a
different binding or candidate. Failure closes unused positions; transferred
bindings remain under the original candidate's actual cleanup lifecycle.

The original preaccepted Stream pool checks its finite required target set. A
required method is checked again before initializer entry and before current
publication. These are structural checks, including exact local snapshots and
accepted paths; each actual child still competes for its original immediate
admission vector.

The invocation view exposes only the selected method functions. Unary functions
return the original typed unary result; Notify returns its submission progress;
Stream returns the original started streaming operation. Calls carry the live
parent context and its original attempt deadline, force `try_now`, and preserve
Completion ancestry. Missing `on_use` snapshots or accepted paths fail locally
before encoding, with no Query, OPEN, pool replenishment, Acquire or retry. An
existing exact stream-pool entry can be observed without adding demand. The
view exposes no Bind, Refresh, UpdateContract or source management operations.

The view is revoked when the callback actually exits. Escaped method functions
then reject with `invocation_closed` and retain only a compact revocation cell
and local method names. Already accepted operations and their results retain
their original owners. Candidate bindings remain attached to that candidate's
lifecycle, including when initialization fails after a real remote side effect.
These declarations currently integrate with the explicit Controller initializer;
other handler registrations retain their own assembly contracts.

`initializeWorkload` bounds the initializer's simultaneous child preparations and
retained results. `callsPerMethod` defaults to one and accepts 1 through 1024;
`inputBytes` optionally bounds retained input backing for each call, up to 1 GiB.
Without an explicit input bound, the SDK uses the greater of twice the declared
request codec maximum and its application byte allowance. Compatible aliases
share the same method positions. Optional methods reserve local call backing
without starting a remote query or creating an accepted path.

Before source Acquire, each attempt reserves the original request, preparation,
header, result and codec vectors, reusable aliases, and unary/streaming
Completion positions. Each response-bearing method also protects its configured
number of call positions in the candidate's original Session-wide K table;
notifications do not consume K. The configured K upper bound is reserved before
Acquire. Once verified material supplies the actual signed K, assembly checks
and binds that limit before credential consumption. If the declared positions
do not fit, assembly fails; it never clamps signed K. The original upper-bound
backing remains charged until actual cleanup.

An initializer call attaches those same reservations to
the candidate's actual accounts. It does not release and reacquire the root
budget. A position is reusable only when its operation, result, Completion and
all aliases have actually returned, including the K handle, wire association and
physical publication tails. Result delivery alone does not make a position
available. A call exceeding the declared input vector
fails with `configuration_capacity`; exhausted positions fail with
`resource_exhausted`. Failed local reservation does not call the source.

Callback exit closes unused workload positions. Accepted work retains its
original budget through actual cleanup, and Controller cleanup waits for that
return. A new attempt is refused with `resource_exhausted` while an earlier
initializer workload still has outstanding references. Multiple Controllers
share the original Environment and executor with distinct resource owners.
These reservations cover initializer call backing. Production connectors also
prepay the candidate Session/carrier plan and original account positions
described above. The initializer's callback and method binding positions are
also reserved before Acquire. The candidate's original application, first-channel
and notification groups, its protected Completion result position, and its two
incoming fixed-query positions are created in the same pre-Acquire admission.
Their ordinary, Completion and fixed-query service costs attach to the original
Environment accounts at this point. No application callback or query work starts
from this reservation. Assembly transfers the original groups and query protection
without acquiring replacement positions. After transfer, normal Session retirement
owns their cleanup, including independently retained results.

If required dependencies need remote initial contracts, the attempt also reserves
one original Environment J acquisition position, one position in the candidate's
original outgoing Q2 table, and one fixed SDK acquisition execution position
before Acquire. Distinct bindings and batches of at most eight methods use this
same reservation sequentially. Each batch waits for its actual J/Q and result
cleanup before reuse. Static-only and `on_use`-only declarations do not acquire
this initial-query reservation. The reservation issues no query until the
candidate is READY and its original channel is usable.

The original outgoing query owner holds its reader, table and request/exchange
primaries before Acquire. Assembly returns its identity-check aliases and converts
those same primaries into reusable protection, then binds the actual network,
codecs, delivery gate and deadline. Initial-query reservations share the original
position selector with ordinary work and exact execution-offer renewal, while
retaining separate capabilities: they do not broaden renewal's exact-target
restrictions or create additional J/Q capacity. After required bindings finish,
the attempt releases future use; later Refresh uses the binding's normal source.
Cancellation revokes future use and keeps actual query tails charged.

Required streaming declarations also reserve the original accepted-pool metadata
and each first entry's message reader, headers, output backing, adapter, error
backing and actual application group before Acquire. After the remote contract is
installed, the existing accepted pool takes those same resources for the matching
namespace, authority, Stream kind and metadata, then performs its ordinary
OPEN/accepted workflow. This reservation creates no Stream ID and conveys no
remote acceptance. Replenishment after consumption uses the pool's existing
admission rules. Unused preparations close with the candidate; transferred entries
and running Streams follow their original cleanup owners. Raw Stream direction,
OPEN and native-position admission remain separate gates.

Required notifications use the candidate's existing fixed notification vectors
and wait for that original channel before initializer entry. A returned
`submitted` notification status remains local submission, not remote handler
completion.
