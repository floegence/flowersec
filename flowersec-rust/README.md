# Flowersec for Rust

The `flowersec` crate is the Tokio-native SDK for end-to-end encrypted
sessions, RPC, notifications, and reliable byte streams. It supports Rust 1.88
or newer on Linux, macOS, and Windows and contains no Flowersec-authored
`unsafe`.

## SDK-owned connection sources

`LocalDirectMaterialSource::preauthorized_pool` captures signed credentials,
namespace verification owners, identity keys, the durable spend ledger and its
native WSS provider configuration as one opaque source. Ordinary applications
call the crate-root `connect(&environment, &source, request, cancellation)` or
`TransportEnvironment::connect` with that source and semantic
`ConnectionRequirements`. Both use one Acquire before entering the native TLS,
winner/spend, activation and dual-READY core. The acquired material always
keeps its captured identity and provider.

`replace_pool_generation` verifies a complete new batch before publication;
failed replacement leaves the previous snapshot intact. Closing a source stops
future Acquire calls, while an already acquired material or ready Session keeps
its original ownership. `acquire` and `connect_material` provide the explicit
advanced handoff of that same captured record. The Source validates the selected native carrier against independent input,
bound-stream isolation and datagram requirements before removing a record.

`LocalDirectMaterialSource::live_authority` captures the configured application
certificates, namespace trust, identity, Artifact issuer, activation signer and
two explicit mTLS control routes. `acquire_async` performs one issuance request
and retains the pending attempt. Native carrier preparation then precedes one live
authorization request. Only its verified proof completes the original account
and allows the handshake to reach READY. An uncertain authorization result is
`TransportConnectError::LiveAuthorizationUnknown`; it does not authorize an automatic
second authorization request. `replace_live_generation` atomically replaces a
fully verified configuration; acquired attempts keep their original generation.
Control requests use fixed numeric routes, explicit CA roots and client
credentials, TLS 1.3, bounded HTTP bodies and the Environment's trusted time.

`LocalDirectMaterialSource::live_tunnel_authority` extends the same source with
an explicitly configured relay identity, service, audience, and fixed relay
control owner. The tunnel Artifact is issued and prepared as a client leg;
TxB returns the activation proof and the client-leg Grant. The server
Grant is delivered independently through the retained B-host publication
capability; relay activation binds both one-shot legs to the same attempt. The client-side endpoint verifies its own Grant before the native
carrier sends HELLO, and the B-host consumes the one-shot server-leg material
through `LiveServerDeliveryHandle::next_tunnel_publication` before its carrier
is allowed to authenticate. An unavailable or uncertain publication cannot be
reopened or retried.

`ConnectionController` manages grouped owned or borrowed material
sources. Each attempt uses the ordinary `TransportEnvironment::connect` flow
once. A candidate becomes current after READY and the configured
`CandidateSessionInitializer` has completed once. Initialization failure or an
uncertain live authorization stops automatic attempts. `replace_session`
qualifies one replacement while the current Session stays usable.
`capture_session` returns that READY, accepting Session without acquisition or
OPEN. `replace_session_with_options` fixes Drain or an absolute bounded Retain
cutoff before acquisition and returns the previous owner's cleanup status. The
candidate's managed service bindings preserve the previously verified contract
baseline and complete before publication. Previously captured Session handles,
operations and Streams keep their original source; retention cannot extend its
authority. `ConnectionProgress::connection_facts` reports READY and spend evidence
separately from application publication, including initializer failure after
READY. The parent token, explicit Close and Environment
shutdown retire the original physical owners; cleanup remains observable when
native or callback tails are still active.

## Public connection and serving owners

The crate-root `Session` and `Stream` are the current concrete owners.
`ConnectionController`, `ConnectionControllerOptions`, `ConnectionSnapshot`,
and `ConnectionProgress` manage those same owners. `ConnectError` identifies
material-source failure separately from `TransportConnectError`, including
uncertain live authorization and failures after irreversible pool consumption.

Direct listener deployments use `TransportEnvironment::serve_wss`,
`serve_raw_quic`, or `serve_webtransport` with independent TLS identity,
namespace handles, an accepted material source and an admission authority.
Their `ServeHandle` retains the listener and every original accepted Session
through cancellation, Drain and observable cleanup. `HandlerPlan` freezes
raw-stream dispatch and the `ServicePlan` for unary calls, notifications,
streaming and resume before READY. `ServiceClient` prepares typed unary
operations through application-defined `MessageCodec` implementations;
`NotificationPeer` owns independent typed subscriptions. `ProxyServer` contributes
its HTTP and WebSocket raw-stream registrations to that same plan.

`RelayHost` and `RelayPublication` retain the independent physical relay legs,
verified hop authorization, bounded opaque forwarding and their actual cleanup.
Relay deployment is separate from endpoint material and Session publication.

## Install

```bash
cargo add flowersec
```

## Supported Connections

The crate-root `connect(...)` and `TransportEnvironment` support authenticated direct and tunneled WebSocket sessions with reliable streams, typed services, notifications, rekeying and bounded cleanup. Raw QUIC and native relay integrations remain available through the documented transport owners.

## Current native WSS connection

`TransportEnvironment::connect_pool_wss` establishes one direct network WSS
candidate from a preauthorized pool with the transport application profile.
The caller supplies an original trusted-time Environment, verified namespace
handles, generated identity keys, exact signed material, independent SQLite
continuity and one fixed numeric address. CA verification uses explicit roots;
DER pin verification uses only the signed active leaf certificates. Both modes
require and check TLS 1.3. The caller runs a Tokio multithread runtime.

The resulting `Session` supports reliable streams, rekey, authenticated
liveness, Drain and physical cleanup observation. Fixed handshake, record,
stream and rekey backing is reserved before irreversible SQLite consumption.
`TransportConnectError::Spent` explicitly identifies later connection failures.
`connect_pool_wss_with_handler_plan` captures the same immutable
`HandlerPlan` used by Serve before pool consumption. Its caller supplies
`ApplicationLimits`; registered raw-stream handlers or explicit manual
acceptance are ready at READY, and their work remains charged through actual
Session and callback cleanup.

`TransportEnvironment::serve_wss` also accepts direct pool WSS Sessions
through original trusted material and durable ParentWinner/AdmissionLedger
owners. `ServeHandle` owns bounded acceptance, Drain, Close and cleanup.
`WssServeOptions` fixes the five `ServeCallbacks`, application callback
budgets and parent cancellation. Application authorization reserves its original
lease after FSB authentication and before durable admission. Immutable
`HandlerPlan` declarations support registered raw-stream handlers or explicit
manual Stream acceptance. READY publication, callback exit, lease cleanup and
provider cleanup retain their original owners and resource charges.

The direct WSS sources support pool or configured live activation and material
Controller assembly. Candidate racing, relay/QUIC/WebTransport and datagrams
require their configured transport compositions. The resource ledger separately bounds all eleven SDK/provider/disk,
item, work, task, timer, connection, handshake, Session and native-handle
dimensions. Full provider/deployment qualification remains unfinished.
See [Rust transport v4](../docs/RUST_TRANSPORT_V4.md) for composition and bounds.

## Candidate trust and recovery guidance

CA candidates use platform or explicit DER trust roots; they do not accept a caller-selected trust store. Pin candidates use only the active artifact-bound leaf-certificate SHA-256 pins and never fall back to CA verification. A failed pin or CA candidate remains an explicit connection error with its original spend and cleanup facts. The equivalent explicit client setup is `ConnectorOptions::new().with_trust_roots_der(roots)`, where `roots` contains the DER trust roots.

## Durable services and explicit recovery

`ServicePlan` freezes unary, notification, streaming and Resume declarations
before READY. A `RegisteredResumeService` binds one durable original contract,
its existing `ExecutionService`, a separate unary Resume method, and an exact
business Stream kind and metadata. Unary recovery receives the same accepted
`Stream` after the Resume reader and sender have exited. Streaming recovery
publishes only the continuation with the original header, deadlines and
persistent cumulative item and byte bounds.

`ServiceClient::prepare_resume` captures an already accepted target without
opening a Stream or sending a request. `prepare_resume_and_save` confirms the
independent query reference before delivering the prepared operation. Its
`start_on` accepts only the captured Session; `try_start` reports a local
`NotAdmitted` result without replacing the ID, digest, deadline or target.
Repeated Start joins the same admitted operation. The caller retains the
original Stream throughout preparation and result handling.

Recovery uses independent application checkpoint signing or MAC keys and a
bounded durable issuance policy. The server durably registers the Resume
operation and atomically records token consumption, generation, target and
confirmation before publishing that confirmation or entering the original
callback. A lost confirmation preserves the consumed token and uncertain
progress. A separately authorized durable issuance handler can call
`ExecutionInvocation::reissue_checkpoint`; idempotent replacement retains the
same checkpoint and original execution horizon, and does not extend an
existing replacement token's TTL. Query never issues or consumes a token.
A replacement request with a different requested lifetime conflicts. A consumed
generation becomes ineligible for this replacement flow once its resumed
callback entry is durably recorded. The Resume transaction transfers its active
execution position to the original operation, including when the service allows
only one active execution.

`StreamingOperation::resume_state` captures an opaque bounded selector after the
current delivered item has settled. Save its exported bytes beside the original
query reference and application checkpoint; import it through
`TransportEnvironment::import_streaming_resume_state`. The selector retains the
original response identity, item limit, cumulative counters and run horizon,
and has no Start authority of its own. `ServiceClient::prepare_stream_resume`
prepares the Resume handle and typed continuation together. After an accepted
confirmation and actual exit of its reader, `take_continuation` returns the
reader on that same target. Closing the completed Resume result leaves the
continuation under its own Stream and deadline owner.

## Current server and provider composition

The current native server entry point is `TransportEnvironment::serve_wss`;
its `ServeHandle` owns bounded acceptance, application dispatch, Drain, Close
and cleanup. Current clients and servers share the same material source,
identity, provider, trusted-time, resource and application-profile owners. The
Rust v4 transport guide describes WSS, QUIC, WebTransport, tunnel and reverse
provider composition, including the guarantees each provider can expose.

See [Rust transport](../docs/RUST_TRANSPORT_V4.md), the
[API contract](../docs/API_CONTRACT.md), and the
[Rust example](../examples/rust/README.md).


`DuplexBridge::new(a, b, options)` takes complete ownership of two distinct,
unused accepted application `Stream` endpoints. Construction reserves both
original I/O owners before reading bytes. Call `start()` once; repeated calls
join the same operation. Each direction holds one bounded chunk, records the
source read frontier and the destination's original write acceptance, and
half-closes only its destination on EOF. The bridge waits for both Streams'
authenticated send completion after both pumps finish.

`wait()` observes the same operation. Dropping a wait future, including through
`tokio::time::timeout`, does not abort it. Use `abort()` for an explicit stop.
`progress()` and failures preserve each direction's accepted count and charged,
bounded `unaccepted_tail`; `cleanup_status()` distinguishes actual retirement
from a finite cleanup observation. `transfer_sealed` becomes true only after
both pumps exit; a cleanup timeout can return a still-live progress snapshot,
whose counts and tail may subsequently advance until that flag becomes true.
The configured overall timeout includes the
prepared period before `start()`. This facade supports Stream-to-Stream
bridging and `DuplexBridge::with_native_tcp(stream, endpoint, options)`. Create
the endpoint with `NativeTcpDuplex::connect(&environment, numeric_address,
NativeTcpDuplexOptions::default()).await` before handing it to the bridge.
The endpoint's two native descriptors, one TCP connection, and provider runtime
backing must fit the configured environment, tenant, and Session limits in
addition to the carrier's existing resources. Bridge construction transfers the
original environment charge into that same Session account before claiming I/O.
The endpoint must share the Stream's original environment; it exposes no raw
socket or descriptor and can be claimed only once. Existing facade clones can
observe diagnostics but cannot read, write, or close a claimed endpoint.
In-progress connection and prepared-endpoint waits are woken by environment
closure. Facade metadata remains independently charged until its last alias
is dropped, even when socket cleanup is already complete.

Each direction's `send_completion` distinguishes
`AuthenticatedStreamDrained` from `NativeTcpWriteShutdownQueued`. TCP completion
means the accepted local kernel queue precedes an actual write half-close;
it does not prove remote application consumption or authenticated drain.
`NativeTcpDuplex::info()` reports requested and observed OS socket buffer sizes,
with `kernel_queue_hard_bound` and `authenticated_send_drain` explicitly false.
Kernel queue configuration is not a whole-process memory guarantee. External
sockets and message endpoints are not accepted because their aliases and full
lifecycle ownership cannot be established by this helper.

## Durable application storage formats

The SQLite execution-history transaction group uses physical revision 2, and
the operation-reference transaction group uses physical revision 1. Opening an
existing store checks its bounded manifest declaration, configured identity,
manifest row and SQLite `user_version` together before configuring writable
storage. Only an accepted current header reaches the current schema and record
readers; every stored record and the configured quotas must pass in one read
snapshot on a read-only connection. The store then closes that connection,
reopens the same file for writing, and repeats full admission before configuration,
recovery or other writes can begin.

An incompatible store returns `ServiceError::storage_format()` with a detached
`storage_format_incompatible` projection. It contains only fixed transaction
group and wire identifiers, required and observed revisions, a finite reason,
and exact-conversion availability. Untrusted or contradictory revision facts
leave the observed revision unknown. The runtime provides no exact conversion
tool and does not migrate or rewrite a refused store.

## Production diagnostics

`TransportEnvironmentOptions::diagnostics` enables detailed production events.
The default is `None`. Set it to `DiagnosticSinkConfiguration::new(callback)` or
use `DiagnosticSinkConfiguration::cancellable(callback)` to receive a cancellation
token with each event. The sink owns a separate bounded callback lane and expiry
worker; it does not consume an ordinary application callback position or require
`ApplicationExecutorConfig::diagnostics`. `diagnostic_sink` remains available for
explicit manual observations. `configured_diagnostic_sink` returns a handle to
the sink selected by the Environment configuration.

Every event contains exactly `state`, `attempt_bucket`, `phase`, `code`,
`retry_disposition`, `duration_bucket`, and `correlation_id`. Correlation values
are independent random 16-byte values for original connection and application
operations. Result waits borrow the original operation; canceling a wait does
not report a new failure or replace its context. Controller selection preserves
the original application context. Native reply, notification, streaming and
write owners retain that context through their physical work.

Sampling defaults to 100 basis points (1%) and accepts values from 0 through 100.
Each UTC 15-minute bucket permits at most 1,024 IDs and 4,096 events, with a
512-byte encoded event ceiling and a 2 MiB queue limit. Bucket changes discard
undelivered events and replace IDs for live operations. The expiry worker remains
active while a callback is blocked. The SDK removes its retained queue and ID
state; applications own retention of copies made by their callbacks.

`diagnostic_counts()` returns unsampled finite totals, including transport,
storage, resource, rekey, datagram, sink-drop and cleanup failures.
`diagnostic_metric(DiagnosticMetric)` also returns fixed marginal counts accessed
through `state`, `phase`, `code`, `duration`, and `attempt` with the corresponding
enums. Counters saturate at `u64::MAX` and never use correlation IDs, peer or
application values as labels. These counters remain available with the sink
disabled or sampling set to zero. Capacity, TLS, identity and store failures are
counted at their original rejection boundary rather than at each propagated
application error.

Cloned sink handles share one lifetime. `close()` prevents further delivery,
clears queued events and requests cancellation of the active callback.
`wait_cleanup()` observes the original physical release for at most five seconds
without initiating close; `wait_cleanup_with_cancellation()` also permits
canceling that observation. A noncooperative callback keeps its prepaid resource
charge and prevents `complete` until it actually exits. Environment shutdown
also closes configured and manual sinks.
