# Flowersec Swift

Flowersec provides authenticated, encrypted sessions, typed service calls,
notifications, and reliable byte streams on macOS and iOS.

## Install

Add `https://github.com/floegence/flowersec.git` as a Swift Package dependency
and select the `Flowersec` library product. The repository's
[`toolchains.json`](../toolchains.json) defines the engineering toolchain.

## Supported Connections

`connect(source:requirements:)` establishes authenticated direct or tunneled WebSocket sessions with reliable streams, typed services, notifications, rekeying and cleanup. `ConnectionController` manages qualified reconnects while preserving the original Session owners.

## Establish a session

Create an `TransportEnvironment(configuration:)` with explicit trusted time, namespace
roots, numerical endpoints, application resource limits, and durable pool
history. Import the immutable application identity and create the SDK-owned
`ConnectionMaterialSource` with
`environment.makePreauthorizedPoolSource(credentials, identity: identity)`.
The source fixes the preauthorized activation profile and TransportEnvironment provider;
it holds a finite local pool and never issues or tops up authorization.
`connect(source:requirements:)` acquires one complete identity generation and
its matching issued record, then uses the original native Prepare, once-spend,
activation, and dual READY path. Static source creation and Connect both verify
the complete certificate/key/profile pair. `replacePoolGeneration` publishes
a complete snapshot and advances the local generation without caller counters;
already acquired material keeps its original key and generation. Closing a source ends future Acquire without closing established
sessions or changing once history. `connectMaterial(_:requirements:)` consumes
explicit material already owned by that TransportEnvironment. Connection requirements express
the guarantees the application needs. Inspect the resulting session's
information before relying on a transport capability.

For online issuance, use `makeLiveAuthoritySource(configuration, identity:)`
or `makeConnectionMaterialSource(.liveAuthority(configuration), identity:)`.
The configuration supplies independent issuer and activation HTTPS endpoints,
numerical routes, explicit CA roots, TLS client certificates/private keys,
the complete application certificates, activation signing key ID and application
profile. The TLS key authenticates control calls and is never an issuer key.
Acquire sends one `/issue/direct` request, or the configured tunnel issuance
path, for a fresh signed Artifact. After
native Prepare selects the carrier, the original attempt sends one
`/live/authorize` request. Only the original complete TxB proof, checked against
current namespace trust and the captured attempt/winner/route, can proceed to
FSB, Noise and dual READY. Failure does not retry the original issuance or
activation call. `replaceLiveConfiguration` publishes a complete new local
configuration/identity snapshot; in-flight material keeps its original assembly.
A live tunnel configuration supplies its future Grant scope, exact GrantLimits,
relay certificate and candidate index independently of the control response.
The original TxB response contains `live-tunnel-material-1`, the activation and
local signed Grant. Its full parent issuance, selected route and attempt, both
identity and leg digests, session contract, relay identity, trusted issuer and
namespace publication must match the captured preparation. Native WSS tunnel
connections use `/flowersec/v4/tunnel` with `flowersec.tunnel.v4`. The original
consumed carrier executes all four HOP_AUTH flights using its own fresh Prepare
incarnation and challenge. Relay possession verification opens Hello; Noise and
READY publication require that same original authenticated carrier.

For automatic pool replenishment, use
`makeManagedPreauthorizedPoolSource(configuration, identity:)` or the configured
`.managedPreauthorizedPool(configuration)` alternative. Supply a standalone
SourceAuthority mTLS endpoint and independently pinned owner-fence signing key,
a standalone TopUp/Ack endpoint, the authoritative source incarnation and fence
generation, the pool digest and complete signed client certificate, and an exclusive durable
refill journal with an independently supplied continuity check. The source owns
one worker, starts replenishing below its configured watermark, and verifies
every full signed lease and private-key pairing before atomically installing a
batch. HTTP/TLS success and response digest checking do not replace credential
verification. Complete material bundles retain all sorted candidate/role tunnel
pairs. Every local Grant and relay dependency is checked before journal install;
remote role material supplies no local trust authority. Acquisition chooses a
supported candidate from the original signed pool selection without dropping
other retained candidate/role material. Acquire only takes an already installed
local record and returns `source_exhausted` immediately when none is available;
it does not trigger or wait for background replenishment.

The refill journal is separate from once-spend history. Pending intents keep
their original operation and request deadline across lost responses; installed
batches retain their exact response for Ack recovery. Acquisition permanently
removes local availability before returning material. Replaying a recovered
batch cannot make an already acquired record available again, and Acquire still
uses the original separate native once-spend transaction. Ack recovery uses
installed history without reading expired material or old application keys.
An exclusively reopened installed journal can finish its original Ack even
when the supplied old application identity or certificate is no longer usable;
that source cannot acquire materials or start another TopUp with that identity.
Authenticated terminal receipts remain separate from installed response history.
An unretired receipt keeps its original operation occupied while the worker asks
for authoritative retirement. Only a retired, non-permanent receipt permits the
next operation; a permanent source fence stays closed across restart. Receipt
facts from an unknown committed batch never install material. Expired available
rows retire locally before watermark evaluation or acquisition, without spending
their separate once rights. New SourceAuthority binding or unresolved history
requires an explicit application decision. A local timeout never proves
retirement or authorizes a new operation.

A live-only TransportEnvironment can omit pool history because the remote SpendLedger
owns its authorization history. A preauthorized source requires its explicitly
configured durable local pool history.

`controller.captureSession()` captures the currently published, accepting
native Session immediately, with no Acquire or OPEN when current is absent.
The fixed reference retains its original work and authorization checks.

`ConnectionController(environment:source:requirements:)` owns connection
attempts and reconnection scheduling. An optional `initializeSession` callback
receives the exact candidate after READY and before current publication. Bind its
required business methods to that Session. Initialization failure or cancellation
closes the candidate and stops automatic replay; transport cleanup does not prove
that remote initialization work rolled back. Bind a service to the controller when
new operations should follow its current session. A prepared operation keeps
its original session, contract, deadline, and execution identity through a
handoff. Reconnection does not replay application work. A provider-confirmed
native disconnect waits for the old connection and callbacks to clean up before
acquiring fresh material; policy, authentication and generic application failures
retain their terminal disposition.

`replaceSession()` also supports a first Session before `start()` and explicit
recovery from initializer failure. Before recovery, the application resolves any
prior remote initialization effects through its own authority. A fresh candidate
gets fresh material and one initializer call. The Controller closes new dispatch
and capture when initialization starts, while already accepted old work retains
its original Session. With no previous Session, `previousSession` and `retirement`
are `nil`; no retirement position is fabricated.

The Apple native transport supports both endpoint roles, direct and tunnel
TLS 1.3 WebSocket connections, signed dialer and listener directions, both Noise profiles, CA verification or signed leaf-DER
pin policies, reliable streams, rekeying, liveness, and bounded stream metadata.
CA routes check the signed DNS name or exact IP subject alternative name;
connections keep the configured numeric endpoint and never perform SDK DNS.
A signed `local_loopback` direct route uses `/flowersec/v4/local` over HTTP,
checks the actual remote loopback address and exact signed Origin, and retains
the same once-spend, Noise and dual READY authentication. A TLS verification
requirement rejects local HTTP before a finite source releases its record.
The configured `preauthorized_pool` and `live_authority` variants share this
native path. Raw QUIC and WebTransport are unsupported in this Apple profile.

For a server endpoint, import its own application identity and pass `role: .server`
to `makePreauthorizedPoolSource`. The original route determines physical direction.
Use `environment.accept(source:)` for a signed listener, after configuring
`listenerTLS` with the local certificate chain and private key. The native listener
binds the exact signed host/port's configured numeric endpoint, enforces path,
subprotocol and Origin policy, and accepts one original connection. `accept` rejects
a dialer-only finite record before acquisition. A signed server dialer uses
`connect(source:)`. A server verifies complete FSB before its durable admission,
including on a tunnel. Logical endpoint role remains independent of socket direction.

`environment.serve(ServeOptions(...))` owns a bounded group of server admissions
and Sessions. Pass the closed server material source as `listener`, including a
live server source's `materialSource`; the signed route determines physical
socket direction. Fix the carrier, requirements, concurrency limit, optional
borrowed maintenance owner, and all five callbacks when constructing the options:

- `authorizeRequest` applies local policy before the aggregate acquires a source's
  original carrier/admission right. It receives configured carrier and requirements,
  without claiming that an unauthenticated request has a peer identity.
- `resolveHandlers` receives immutable metadata only after complete FSB verification.
  Its `HandlerPlan` freezes the stream and service registries before admission.
- `authorizeApplication` reserves the authority's original application lease after
  identity verification and before durable admission. It returns that lease owner;
  a canceled or failed candidate cannot reuse the authorization.
- `onSession` receives only a dual-READY Session. RPC, notification, service-stream
  and raw-stream dispatch wait for the same first business publication gate.
  Callback entry rechecks publication
  on the callback's own executor against the aggregate's Drain/Close gate.
- `release` runs after real Session and handler cleanup and the application's lease
  cleanup. Failures retain bounded cleanup facts and never claim completed release.

A failed request, application authorization, handshake or per-attempt deadline
cleans up only that admission. The accept loop continues with a bounded cadence;
healthy siblings keep their original Sessions. Confirmed source closure or a
fenced shared maintenance/resource owner closes the aggregate admission boundary.

The returned `ServeHandle` provides `drain`, `waitDrain`, `close`, `cleanupStatus`
and `waitCleanup`. Drain closes both admission and READY publication, then uses
each original Session's graceful drain with a fixed deadline. Close aborts the
owned group. Cancellation of a wait leaves the original cleanup owner intact.
The Environment, source, maintenance owner and registries remain borrowed.

`environment.makeLiveServerSource(configuration, identity:)` starts an independent
bounded mutual TLS server-allow listener. Configure its numerical address, TLS
server certificate/key, exact authority client certificate DER, independent
admission backing and maximum registrations. `registerOriginal` verifies the
original Artifact and identity pair, fixes the trusted attempt, recipient and
candidate, creates a new incarnation and prepays carrier/session resources before
returning a `TransportLiveServerBinding`. Publish that binding through the
application's trusted authority registration flow before authorizing the client.
For a tunnel, supply an independently trusted role-6 future Grant scope, original
relay certificate and exact Grant limits. The authority delivers the reference
`tunnel-server-allow-1` request to `POST /tunnel/server-allow`; it contains the
original server Grant and no activation proof. The native listener authenticates
that Grant, prepares the original carrier and returns deterministic CBOR true only
when the final ACK write can publish the prepared material into the Source.
An exact duplicate can acknowledge a retained original fact; it never prepares a
second carrier or recreates a consumed registration. The server obtains activation
inside the signed original FSB, verifies the complete endpoint closure and commits
its independent durable admission before sending FSA, Noise and READY. Acquire
transfers the same native carrier and prepaid owners. Closing the Source fences its
pending registrations and Acquire without canceling acquired materials or Sessions.

`environment.makeRelayHost(configuration, identity:)` creates a continuous relay
with its independent signing identity, one durable ledger and bounded queue.
For production live Sources, install `TransportLiveRelayRegistration` before
native client Prepare and configure the Source's `relayPreparation` endpoint.
Start `host.run()` and await `host.initialPublication.waitListening()` to join
local listener binding without consuming a child through a readiness probe.
The relay prepares listeners from the independently verified parent and future
Grant scopes. An endpoint listener announces `/tunnel/relay-ready` without
issuing authorization. After native Prepare, the Source fixes its original TxA
request with `/tunnel/relay-prepare` and then calls `/live/authorize`. The
original B-host publication installs its server activation and server Grant
through `/tunnel/relay-server-grant`; the client TxB callback then installs the
same activation and client Grant through `/tunnel/relay-activate-client`. The
RelayHost verifies the two Grants as a pair and releases HOP only after the
client-leg ACK is written. Each leg is fixed to the original request and accepts
only byte-identical confirmation; uncertainty or conflict retires the attempt.
A separate `preparationControl` can pin the preparation principal independently
of the TxB authority. `TransportLiveRelayPublication` accepts already final
original activation proof/signing-key binding and role Grants. Use
`publishOriginal(client:server:)`, `publishLiveOriginal(_:)` or
`registerLiveOriginal(_:)` for subsequent publications.

Every server and relay admission supplies a common `parentWinner` authority,
independently configured through `ParentWinnerAuthorityConfiguration`.
`environment.makeParentWinnerAuthority` creates its bounded secure SQLite owner.
If the TransportEnvironment's pool history was created without an adapter, install the
resulting `configuration` once with `environment.installParentWinnerAuthority`
before server-role pool consumption; the authority ID must match the history.
Share that same configuration with relay claims and live server admissions. A
qualified common service can instead be supplied when creating the history.
The parent key excludes candidate and attempt, while its selected fact fixes the
original proof, candidate set, candidate, route, attempt, identities, audience and
server authority. Both tunnel legs and logical server match that same fact.
Authenticated FSB or HOP possession precedes CAS, and the original local
admission COMMIT follows it. Original-claim refusals remain durable before CAS,
including when its result is lost. Conflict or uncertain COMMIT stops the run. Public
selection readback never reconstructs a native admission or forwarding right.

Each publication prepays its two native carrier owners and writes refusal rows
before entering the queue. A canceled or failed publication retains its refusal.
Each leg follows its signed physical direction. Both HOP possession proofs,
common ParentWinner and the paired claim COMMIT precede relay proofs and opaque
forwarding. Original total/rate/queue budgets continue across that claim.
a failed pair completes its own `RelayPublication` and leaves the daemon available
for the next independent publication. Use `waitCompletion()` on each ticket, or
cancel it with `close()`. Cancel `run()` or call host `stop()` to close and join
active native work and retire the shared ledger. Historical rows only refuse
replay; endpoint admission and dual READY remain endpoint responsibilities.

## Proxy HTTP and WebSocket traffic

`ProxyClient(session:)` captures one established Session. It opens ordinary
application Streams using the current proxy CBOR profile; it does not acquire
material, reconnect, or move an existing request after a Controller handoff.
Capture a fresh Session explicitly when starting work on another connection.

Use `open(HTTPProxyRequest(...))` to read the response through
`HTTPProxyExchange.readBodyPart()`, or `send(...)` for a bounded buffered body.
The response retains ordered field values as octets, content-coding labels and
separate trailers. A complete body requires its original `ProxyBodyEnd`; EOF
alone is a framing failure. Content-Length remains an integrity assertion.
Close each exchange when leaving its scope.

`openWebSocket(path:headers:)` returns a fixed `ProxyWebSocket`. Its `send` and
`receive` methods retain the original message operation and payload; ping, pong
and close are explicit messages. The selected subprotocol must have been
requested. The trusted remote proxy owns upstream authorization and its fixed
network policy; client request content does not select another upstream.

`ProxyServer(session:upstream:)` captures that same established Session on the
receiving endpoint. Register its HTTP and WebSocket stream kinds in the application's
`StreamHandlers` and pass each accepted stream to `serve`. It admits bounded concurrent
operations, validates complete current request framing and trailers before invoking
the upstream, and returns structured upstream failures. `close()` cancels active
operations, resets their original streams, and joins their real completion.

For a native fixed backend, create `NativeProxyUpstreamConfiguration` with an HTTP or
HTTPS origin, its numeric endpoint, explicit trust roots and proxy limits, then call
`environment.makeNativeProxyUpstream`. HTTPS verifies TLS 1.3 and the origin's original
DNS or exact IP identity. Request paths retain their percent encoding and cannot
choose another authority. Ordered octet headers, Content-Length, content coding and
trailers survive HTTP framing. `ProxyForwardingPolicy` controls retained headers,
cookie filtering and permitted external origins; its bounded cookie jar bridges HTTP
responses to later upstream WebSockets. Dial cancellation joins the original native
socket. A custom `ProxyUpstream` may instead implement the application's own backend
policy while preserving those response bounds and physical cleanup obligations.

## Bind and call a service

A `ServiceDefinition` declares named methods and their local
`MessageDefinition` codecs. Each `MethodDefinition` fixes the call shape,
semantics, request and response bounds, error catalogue, and applicable
streaming or execution commitments. `ServiceBindingTarget` fixes the trusted
authority, tenant, audience, local subject, and permitted peers.

Use `session.bindService(...)` or `controller.bindService(...)` with an
explicit contract source and acceptance policy. Fixed contract queries use
bounded cooperative parsing. The default exact policy requires an explicit
contract update for a changed digest; a bounded policy must declare the exact
numeric ranges it accepts. Each actual operation selects one exact contract.
Admission offers authorize the applicable execution window and do not replace
the stable service contract.

`ServiceClient.call(...)`, `notify(...)`, and `stream(...)` are immediate
convenience entries. Their `prepareOperation(...)`, `prepareNotify(...)`, and
`prepareStream(...)` counterparts return an original operation whose `start()`
can be delayed. Call options carry an absolute deadline and explicit request
admission choices. A streaming operation has one bounded initial request and
one dedicated result stream; `readNext(...)`, `readNextEncoded(...)`, and
`items()` advance that same original reader. Close the operation when leaving
its consumption scope.

Cancelling a result wait stops that wait. It does not prove remote work was
cancelled or create a second execution. Encoded-result APIs transfer owned
payload bytes and codec identity for explicit application-side decoding.
Typed calls retain their ordinary decoding workflow.

## Observe notifications

`ServiceClient.subscribe(...)` observes one original service binding.
`ConnectionController.subscribeNotifications(...)` observes current-session
handoffs through one root subscription, one bounded queue, and one serial
callback. Register roots before starting the controller so native attempts can
install their observation inputs before sending their own READY.

`currentOnly` admits callbacks from the published current source. `drainAware`
can also observe a retained authorized source and labels each notification
with its source generation and actual phase. Both policies expose explicit
handoff, attachment, expiry, coalescing, and delivery gaps. Candidate input
cannot invoke a decoder or handler before publication. `latestPending` owns
one pending slot across sources; a candidate cannot evict pending data from
an eligible current source. Subscription status remains readable after close.

## Register application handlers

Install a trusted `ServiceRegistry` through `TransportEnvironment.makeServiceRegistry`
before connecting. Registration fixes codecs, contracts, explicit caller
identities, and dispatch targets before the native READY gate. Unary, notify,
server-streaming, result-read, and Resume handlers use the real authenticated
session's inbound channels and accepted streams.

Handlers receive a borrowed `ApplicationInvocationContext` and
`ServiceServerInvocation`. Check cooperative cancellation during application
work. Streaming handlers use `ServiceServerStreamWriter` to encode and publish
one bounded item at a time. Normal completion sends FIN after accepted items;
a decoder or handler failure uses the declared business error or a bounded
SDK error response. Unsupported RPC types and lawful input-capacity failures
drain their original declared body and use the prepaid refusal slot. The
server stream uses one run clock from the first actual custom decoder or
handler body through encoding and publication; SDK byte and UTF-8 parsing
defer that clock until the handler body. Registered handlers retain their
executor isolation, so actor queue wait precedes the run clock.
`AsyncClosureMessageCodec` retains the actual custom async decoder isolation;
`EntryAwareAsyncMessageCodec` supplies an SDK-created entry that the decoder
signals with `try await entry.enter()` as its first body action after an actor
hop. Entry preserves the caller's executor while the original durable dispatch
prelude completes. Custom decoder effects and failures therefore belong to an
already dispatched execution; SDK parsing still defers dispatch until the
handler. Existing async codecs can
return an actor-isolated callback from `applicationDecodeCallback`, or call
`codec.serverRequestCodec(decode: { ... })` inside the decoder's actor to adapt
just the server request role while preserving its encoder and definition.
Callback parameters inherit the actor context in which the closure is created.
An actor method reference or a closure created elsewhere that forwards into
another actor does not preserve that actor's entry; use an actor-created
callback or the cooperating entry protocol. A server request registration without a concrete callback
or cooperating entry throws `asyncDecoderEntryUnavailable`; client, response, and output codecs keep their existing async behavior. Merely being
an actor is not proof of the decoder witness's isolation. Closing or cancelling
SDK work preserves resource charges
until the actual callback and transport cleanup return. Inbound RPC assembly
and accepted dedicated streams share the same Session K cap through input,
callback execution, and publication. Server notifications use their own finite
receiver admission positions and retain them until the original callback exits.

## Durable execution and recovery

Execution methods use an exact operation key and request digest. Install a
`SQLiteServiceExecutionStore` with an explicit private directory, store
identity, finite history and result quotas, continuity callback, and checkpoint
signing key. Reopening requires the same quotas and checkpoint key identity.
Each open store pins its private directory, database, and lock file and checks
those original identities during operations. Admission reserves applicable
result capacity before dispatch. A unary execution contract that omits
`result_retention_ms` records the original result digest, length, and error code
without storing its body; its immediate original response still publishes
normally. Fixed result-read methods reserve their registered contract's maximum
response size before copying a retained body.
Duplicate requests compare the original request and contract and do not
redispatch. Interrupted active work becomes unknown after reopening; bounded
history remains as tombstones rather than granting new execution rights.

Operation references are selectors. The query and cooperative cancel APIs
use a separately protected management lane. Retained unary result reads use
ordinary bounded reading. `SQLiteOperationReferenceStore` and
`prepareAndSave(...)` preserve an operation reference before its original
Start; importing a reference does not restore Start authority.

The Swift reference, execution, pool-spend, pool-refill journal, live-server
admission, ParentWinner and relay-claim SQLite transaction groups use physical
revision 2. Opening an existing group uses a read-only handle to validate its
fixed manifest header, configured identity, manifest revision, `user_version`,
current schema and bounded records together before changing storage settings.
The same backing is rechecked after reopening for writes. A rejected format raises `StorageFormatError` with a bounded
`storage_format_incompatible` projection: fixed transaction group and wire
identifiers, observed and required revisions, a finite reason, and exact
conversion availability. Unverifiable or inconsistent revision fields report
an unknown observed revision. The runtime ships no exact conversion tool and
does not migrate or rewrite a refused store; maintenance requires an explicitly
authorized host workflow. Independent transport work retains its normal lifetime.

A handler can issue a protected checkpoint only from its live dispatched
invocation with the negotiated Resume permission. Checkpoint issuance has a
finite durable count and interval per original operation: the defaults are
16 issues and at least 1000 ms between issues. The current session's signed
byte and duration limits apply when the handler issues the token. Its fixed
expiry is computed from the trusted time lower bound and remains within the
retained history. A later session's shorter issuance duration does not change
an already issued token's expiry; consumption still checks its current input
byte limit and the original signed validity window.

Resume requires the original checkpoint, exact caller and scope,
current token validity, durable generation consumption, and an exclusive real
accepted `ServiceResumeTarget` from the new session. The Resume RPC has its
own operation identity. Its accepted confirmation precedes the explicitly
registered resumed handler, which finishes the original result.
`registerStreamingResume` continues a durable typed stream with the original
request header, item limit, and persistently precharged output counters.
Content storage remains attached to the original execution and its fixed
retention anchors. Neither initial request bytes nor previous output items
are automatically replayed. Persisted
stream IDs cannot reconstruct a Resume target, and replayed checkpoint tokens
cannot consume the same generation again.

An independent, authorized durable application method can explicitly call
`invocation.reissueCheckpoint(reference, originalContract: contract,
previousToken: token, lifetimeMS: duration)` after a consumed Resume token's
confirmation was lost and the original continuation never entered. The store
requires the original execution to be unknown and inactive, authenticates the
exact last consumed token, and retains the original checkpoint, generation,
deadline, first dispatch run origin, item counters, and result capacity. Fresh
expiry and every continuation remain bounded by that original run limit.
Repeating that issuance with the
same previous token and lifetime returns the stored bytes and original expiry;
it creates no new nonce or retention window. A different lifetime conflicts,
and an expired receipt cannot renew itself. New issuance uses the configured
per-operation issue count, interval, signed session TTL, byte bound, and bounded
store row. QueryOperation remains read-only with respect to token issuance.
Resume consumption and its accepted operation result commit in one transaction.

Durable server streaming records execution facts and explicit checkpoints.
A signed retained-content policy must match the trusted local
`StreamContentDefinition` and its registered unary read method before READY.
The SQLite store reserves its full finite item and byte promise before dispatch.
`saveContent` explicitly commits a position and body; sending an item does not
save it. Re-saving the same position and bytes preserves its original expiry,
while conflicting bytes are rejected. Retention begins at the signed original
admission or content commit, and restart, Resume, completion, and repeated reads
do not renew it. Durable bodies survive reopening; volatile bodies require
the original store incarnation.

The definition's existing typed unary reader calls `readRetainedContent` with
an exact `StreamContentTarget`. Its application codec describes the position
and available, missing, or expired response. The SDK checks original caller,
authority, contract, and read method, reserves the caller's body bound before
copying, and verifies the stored digest. `prepareContentRead` uses that same
registered method and original operation reference.

Restart methods require an explicit `ServiceMaintenanceOwner`. Their
`ServiceServerInvocation.responsePublication` is pending before the handler
runs and observes only its selected original response. Its deadline starts
when that response enters publication. `flushed` requires all original bytes'
actual provider completion; it does not imply peer application receipt.
Supersession, STOP or ABORT, provider failure, owner loss, and deadline produce
`unknown`, and later events cannot regress `flushed`. Canceling `wait()` stops
only that waiter. Provider callbacks and production retain their original
capacity until both have actually exited.

## Resource and lifecycle ownership

`ApplicationResourceProfile` separates ordinary, resident, completion, fixed
query, and protected management work. Explicit client configuration also
bounds runtime items, reservations, references, and persistent application
bytes. Resource shortage rejects admission rather than creating an unbounded
queue. A timeout or logical close does not refund a running callback, an
unfinished publication, or a native cleanup tail.

Close service bindings and subscriptions when their own scope ends. Closing
a controller-bound service does not close its external controller. Close the
controller and TransportEnvironment at their owning scope and inspect cleanup status
when the application needs actual exit evidence.

See the [Swift cookbook](../examples/swift/README.md),
[Swift transport guide](../docs/SWIFT_TRANSPORT_V4.md),
[API contract](../docs/API_CONTRACT.md), and
[error model](../docs/ERROR_MODEL.md).
