# Flowersec Public API Contract

Flowersec exposes authenticated Sessions, registered byte Streams and service
operations through one current Transport API. An application configures a
`TransportEnvironment`, a material source, its required guarantees and an
application plan, then connects or accepts a Session under those original
owners. The environment retains shared resource accounting, clocks, namespace
trust and service state. Carrier adapters supply physical I/O; credentials,
private keys and carrier handles remain behind their owning boundaries.

Go uses `github.com/floegence/flowersec/flowersec-go/v6`, TypeScript uses its
package root and Node or browser exports, Rust uses its crate root, and Swift
uses the Flowersec module. Public names are unversioned. The authenticated wire
is strictly `flowersec/4`; a selected release does not negotiate another
Flowersec protocol or silently substitute a weaker access or TLS policy.
Language-specific API shapes preserve the same acquisition, consumption,
publication, cancellation and cleanup semantics.

## Environment and connection ownership

Finite resource limits and the original resource root are installed before
constructing an environment, source, listener or application executor. A
connection admits its complete future Session resource graph before source
acquisition, including actual execution, result, Completion and namespace
subscription positions. Local admission failure does not contact the source
or spend authority. Required carrier guarantees are checked before acquisition
and again against the authenticated material before consumption.

A source captures identity, namespace dependencies, generation, activation
profile and provider ownership. A `ConnectionMaterial` owns one immutable
identity/lease pair. The supported source profiles are `preauthorized_pool`
and `live_authority`; selecting either profile fixes its consumption authority.
Pool acquisition takes only verified, durably installed local material. Pool
maintenance uses the separate TopUp/Ack contract and its independently trusted
control path. Live acquisition and authorization use the configured
authenticated authority. Neither source implicitly falls back to another
provider or activation profile.

Durable consumption and remote admission are distinct facts. Public failures
preserve whether a durable operation was not submitted, committed, or remains
unknown. An uncertain outcome cannot make a possibly consumed credential
available again. Cancellation fences further publication and irreversible
work without undoing a completed action. `Close` stops new work;
`WaitCleanup` observes the actual provider, storage and carrier exit while the
original resource backing remains owned. A canceled observer does not replace
or detach that physical cleanup responsibility.

The optional `ConnectionController` owns long-lived connection attempts above
its configured source. It preserves the source incarnation, original attempt
deadline and admitted application plan, initializes a replacement before
publishing it, and retains the previous Session according to explicit
retirement policy. Pool replenishment and application retries do not become a
second connection scheduler. Supported runtime/carrier tuples and unsupported
reasons are declared in the current capability registry; availability does not
imply that every SDK exposes every carrier or that every pair has verified
interoperability. Engineering acceptance and release packaging are separate
workflows; release does not run tests.

## Sessions, Streams and service operations

Both connection and server admission return an authenticated Session after
material verification, activation, durable admission and the READY exchange.
A `Serve` owner aggregates ingress and child Sessions under the original
environment. The host attaches its configured listener exclusively to that
owner. Drain fences new ingress and preserves child outcomes; closing the
Serve owner does not close the shared environment. Tunnel and relay adapters
retain their own bounded admission, grant and carrier responsibilities while
preserving the same end-to-end Session protocol.

Applications fix stream kinds, metadata descriptors, service contracts and
handlers in the original application plan before READY. Authorization receives
the authenticated application context and bounded metadata before an incoming
Stream or operation is accepted. Reliable Streams preserve backpressure,
independent read/write closure and final status. Unreliable messages require an
explicit supported carrier capability and are not a substitute for reliable
Stream progress.

Service clients select registered methods and prepare unary, streaming or
notification operations under captured contract policy and admitted execution
and result capacity. Exact or bounded contract acceptance rejects unapproved
canonical field changes; explicit digest approval does not override bounded
policy. Operation handles retain separate execution, delivery, cancellation
and cleanup facts. A response becomes flushed only when the final encoded
record is handed to its original publication owner; a later carrier failure
cannot reverse that handoff. Maintenance, liveness, rekey and Drain retain
their original deadlines and owners.

Connection, Session and controller failures expose bounded structured facts
and redacted diagnostics. Application failures remain application-owned;
they cannot invent transport authorization, consumption or cleanup facts.
The following SDK sections describe the concrete public constructors and
runtime integrations for these contracts.

## Network TLS policy

Network direct and tunnel routes require their signed TLS policy. Native
providers enforce TLS 1.3 without early data, resumption or insecure fallback.
CA mode verifies the certificate chain and requested target identity using
platform or explicitly installed private roots. Pin mode authorizes only the
active complete leaf DER SHA-256 hashes and the applicable certificate profile
and private-key proof; it does not add CA or hostname authorization. A failed
pin cannot be bypassed with a CA candidate for that same endpoint and policy.
Namespace trust and application identity remain independent of outer TLS.

Browser WebSocket uses browser-managed CA verification. Browser WebTransport
supplies the active signed leaf hashes through `serverCertificateHashes` when
that browser profile supports them. JavaScript does not independently observe
TLS version, peer leaf SPKI or a P-256-only verifier. Required consumer TLS
verification is therefore rejected when the selected provider cannot actually
guarantee it. A controlled deployment's TLS termination policy cannot be
reported as an independent JavaScript verification result.

## Local browser bridge

The current signed `local_loopback` access class carries the same authenticated
Session, Stream and service protocol over an explicitly enabled same-machine
WebSocket bridge. Its route uses `/flowersec/v4/local` and subprotocol
`flowersec.local.v4`, a canonical numeric loopback address, an explicit port
and the exact corresponding HTTP Origin. Host, remote address, route and
Origin checks precede upgrade. The application must authorize the request;
same-origin alone does not authenticate a user or authorize bridge access.

Bridge tokens belong to the application. Independent namespace trust,
identity, activation, lifetime limits and single-use admission still apply.
The route reports consumer TLS verification as not applicable, so a
requirement demanding that guarantee rejects it before acquisition. It does
not authorize remote or DNS endpoints, tunnel routes, QUIC or WebTransport.
Host-instance guarantees may be claimed only when the actual host supplies
them. Adapter availability must be explicit; the access class does not imply
an implementation in every SDK. The same cancellation, replacement, Drain
and cleanup contracts apply. See [PRIVATE_LOOPBACK_V1.md](PRIVATE_LOOPBACK_V1.md).

## HTTP application integration

An application can carry HTTP bytes inside a registered Stream on a current
authenticated Session. Native stream adapters and the registered ProxyServer
HTTP and WebSocket kinds retain keep-alive, upgrade, backpressure, half-close
and the original Session ownership. The application fixes its stream kind and
validated metadata descriptor before READY and authorizes the specific
upstream and request target. Metadata projection does not replace user-session,
password or request-level authorization.

Managed Cookie sessions require explicit scope, authentication and lifecycle
policy; native credential passthrough is a separately selected policy. Cookie
control outcomes preserve confirmed invalidation independently of replacement
allocation or request delivery failure. Network establishment retains the
signed TLS policy, and a failed secure connection cannot select a plaintext
LAN or public HTTP listener. An explicit same-machine bridge uses
`local_loopback` with its independent application admission. See
[HTTP_DIRECT_V1.md](HTTP_DIRECT_V1.md) for the HTTP integration contract.

## Go

The `github.com/floegence/flowersec/flowersec-go/v6` module exposes the current
transport through `flowersec.NewTransportEnvironment`, `flowersec.Connect`,
`flowersec.ConnectMaterial`, `flowersec.ConnectPool` and
`flowersec.NewConnectionController`. Trusted host composition supplies finite
resources, a clock, namespace verification, immutable material sources and an
application plan. `flowersec.NewAcceptor` registers the original Serve aggregate;
current WebSocket, QUIC and WebTransport adapters attach to that owner.

`flowersec.ConnectionMaterial` captures an original authenticated
`flowersec.ArtifactLease` and `flowersec.ApplicationIdentity`. Static material,
preauthorized pool and live authority connection inputs use their explicit
consumption authorities. `flowersec.Session` owns authenticated Streams and
service operations; cancellation and cleanup observe the same original work.
`flowersec.ConnectionController` owns replacement, initialization and retirement
within its original `flowersec.TransportEnvironment`.

The `github.com/floegence/flowersec/flowersec-go/v6/controlplane` package exposes
current artifact issuing, activation, spend-query, pool TopUp and relay
publication owners. Its configured authority and durable SQLite history fix
issuance and admission independently of peer-supplied fields. Formatting and
error projections remain redacted; trusted policy selection, tenant decisions
and upstream routing belong to the host.

`flowersec.NamespaceReferenceFactory` is trusted online namespace composition.
`flowersec.NewNamespaceReferenceFactory` installs finite independently configured
trust roots, providers, clocks and allocation scopes. Both a cold visit and
same-slot recovery require complete independent bootstrap.
`(*flowersec.TransportEnvironment).VerificationNamespace` retains its original
preparation position and legal registry pin until provider and original context
cancellation actually return. Close cancels only that Environment's work and
leaves the shared registry/factory with its original owner.

`flowersec.NamespaceRetirementService` owns bounded pressure-driven independent
coverage proofs. Failed or unknown coverage retains occupied history. Existing
Sessions, signed map history and namespace reference backing are never evicted
only because a waiter canceled or a service is idle.

The root Go proxy server is an application protocol owner. TypeScript Node exports expose the corresponding `ProxyServer`
owner. `flowersec.NewProxyServer(...)` validates a fixed upstream and
resource/header policy; `flowersec.ProxyServer.RegisterStreamHandlers(...)` installs the HTTP
and WebSocket handlers in a carrier-neutral `StreamHandlerPlanConfig`. The browser/Node
peer uses the published TypeScript `/proxy` entrypoint. Carrier objects, JSON
metadata, proxy stream kinds, and WebSocket frames remain internal.

`ProxyServerOptions.AllowedUpstreamAddresses` fixes the permitted IP addresses or
canonical CIDRs for a named upstream. Numeric upstreams are pinned to their exact
normalized address, including explicit private/loopback deployments. Both HTTP
and WebSocket validate the entire bounded DNS answer before numeric dialing and
check the actual peer before HTTP credentials or body publication. TLS retains
the original logical hostname. The private HTTP/1 keep-alive pool uses one
`ClientConn.RoundTrip` per request and retains body owners through actual exit;
method names and idempotency keys never authorize implicit request replay.
Automatic redirects, ambient proxies and HTTP/2 connection coalescing are absent.
The standard resolver's internal allocation allowance remains a native runtime
qualification requirement; the 64-result acceptance limit alone does not prove
its allocation bound.

The Go private connection entrance captures bounded original HTTP/1 response
headers before native transfer normalization. Conflicting lengths, TE/CL mixes,
singleton conflicts and Connection nominations are checked using those facts.
The native HTTP implementation remains responsible for body/chunk/trailer
framing; the proxy preserves the original facts through application filtering.

The Node `ProxyServerOptions.allowedUpstreamAddresses` and Rust
`ProxyServerOptions::allowed_upstream_addresses` configure the same address/CIDR
boundary for their native HTTP and WebSocket adapters. Named upstreams require
explicit ranges in addition to hostname approval. Both adapters validate all
resolved candidates, normalize mapped IPv6, reject an out-of-policy answer as a
whole, use at most three numeric connection-preparation attempts, and check the
actual peer before exposing a socket to HTTP or WS. The original logical host
still controls Host and TLS identity. Each request owns its connection; no
redirect, ambient proxy, global agent or implicit request replay can bypass the
policy. Resolver and actual socket cleanup retain finite policy slots until
completion, including after the original waiter times out. Native resolver and
TLS internal allocation allowances still require host qualification.

Rust `ProxyServerOptions::max_concurrent_http_streams`,
`ProxyServerOptions::max_concurrent_event_streams`, and
`ProxyServerOptions::event_stream_idle_timeout` reserve separate finite HTTP and
event-stream capacity. Zero selects SDK defaults: at most 24 HTTP streams, an
event subset of at most 16, and a 45-second event idle deadline. An explicitly
accepted `text/event-stream` response uses that idle deadline and bounded chunks
instead of the ordinary response's lifetime/body limit. Content-Length remains
an integrity assertion even when Connection removes it from forwarded headers.
Other responses keep their original finite deadline. Reset, excess input or
cancellation ends only that request, and idle expiration releases actual native
I/O before its policy slot becomes available again.

`flowersec.ProxyCredentialPolicy` fixes explicit external credentials or
managed upstream cookie ownership. A `flowersec.ProxyCookieSession` binds the
original authenticated Surface scope; requests capture the original incarnation
before body or network work. `ClearUpstreamCredentials` invalidates that original
association before replacement allocation and preserves independently confirmed
invalidation even when replacement fails. Cleanup waits for actual native
transport and body methods to exit.

See `docs/GO_TRANSPORT_V4.md` and the current symbol inventory below for exact
component constructors and operation contracts.

## TypeScript

The supported package entrypoints are `@floegence/flowersec-core`,
`@floegence/flowersec-core/node`, `@floegence/flowersec-core/browser`, and
`@floegence/flowersec-core/proxy`. The public SDK uses the current TransportEnvironment and Session lifecycle. It does not select or downgrade to an older
wire profile.

The root entrypoint exposes `createTransportEnvironment(...)`, `connect(...)`,
`connectMaterial(...)`, `createConnectionController(...)`, `serve(...)`, and
the opaque TransportEnvironment, ConnectionMaterial, Session, Stream, result, resource,
and credential contracts. The `./node` and `./browser` entrypoints expose
runtime-specific `connect(...)` and `createConnectionController(...)` helpers
along with their supported current carrier configuration. Node additionally
provides current listeners, `Acceptor`, `ServeHandle`, and trusted tunnel
owners. Browser WebTransport and WSS require immutable deployment bindings for
facts the browser cannot independently inspect; those bindings do not constitute
interoperability evidence.

The `./proxy` entrypoint reexports the shared core facade and accepts a current
`Session`. Its browser composition helpers connect through the original
`TransportEnvironment`; the proxy wire, Service Worker protocol, candidate
selection, and native carriers remain private. Exact-origin browser bridges
expose bounded application messages and
return standard streaming Fetch responses.

`ServiceClient.contract(method).offer` returns the installed execution method's
frozen `AdmissionOffer`. Its `serviceContractDigest` is the same hexadecimal
digest as the containing `ServiceContract`; `notBeforeMS` and `notAfterMS` are
UTC bounds. The value owns no runtime verifier, binding, Session or execution
capability. Transient, observation and uninstalled methods omit `offer`.
Refresh leaves earlier values unchanged; `availability` separately describes
whether the installed advertisement is currently usable.

The `flowersec-ts-cli` binary consumes a trusted local ES module selected with
`--config`. The module configures the same current TransportEnvironment and either a
registered client source or a current server `Acceptor`; command-line values do
not supply credentials, trust roots, or peer-selected endpoint data.

See [TypeScript transport profile](TYPESCRIPT_TRANSPORT_V4.md) for supported
carrier tuples, storage ownership, callback lifetimes, and connection guarantees.

### Durable pool sources and proxy surfaces

The root, `./node`, `./browser` and `./proxy` entrypoints expose the durable pool source
contracts `PreauthorizedPoolSource`, `TopUpHandle`, `PoolSourceConfiguration`,
`TopUpOptions`, `TopUpState`, `TopUpResult`, `TopUpControlTransport`,
`TopUpExchangeResult`, `PoolControlReplyDecoder`, `TopUpError`,
`TopUpErrorCode`, `TopUpErrorScope`, `TopUpWireResult`, and `TopUpWriteAction`.
`createSessionPoolControl` binds the already authenticated Session methods 41006
and 41007 with bounded byte codecs and a host supplied reply decoder. The
source uses one original durable journal for pending intent, material
availability, Applied history and sequence frontier. `topUp` is explicit; the
source never performs an implicit managed refill.

A `TopUpHandle` contains only its immutable operation ID. Its `status` keeps the
original operation's proven state, adopted options and authoritative error even
when the source is closed, an observation is canceled, or a later operation is
started. `cleanupStatus` and `waitCleanup` observe only that operation's actual
proof, control and persistence tails. A stale handle never observes a later
operation. A lost 41006 response can be read with the same operation ID,
request digest and original append deadline under a separate bounded recovery
call. Installed Applied facts can be acknowledged after material consumption
without reparsing old identity keys or recreating a material. Recovery does not
renew the original append authority. A pending response containing already
expired material remains pending with `relink_required`; an authenticated
terminal response can retire the original intent. `registerDurablePoolSource`
on a configured Node or browser client binds the source to that client's
original SQLite or IndexedDB store and fixed signing/static DH owners.

| Operation | Public signature and ownership |
| --- | --- |
| `source.topUp(options?, wait?)` | Returns `Promise<TopUpResult>` for the original adopted intent; concurrent calls join that intent. |
| `source.topUpStatus(handle, wait?)` | Returns `Promise<TopUpResult>` with the original handle's proven facts and any observation error. |
| `source.recoverPendingTopUps(tenant, incarnation, wait?)` | Returns original pending handles after a current owner-fence proof. |
| `handle.cleanupStatus()` | Returns `CleanupStatus` for that original operation's callbacks. |
| `handle.waitCleanup(options?)` | Returns `Promise<CleanupStatus>`; observer cancellation does not cancel physical cleanup. |
| `createSessionPoolControl(client, topUpMethod, ackMethod, decoder, timeoutMS)` | Returns `TopUpControlTransport` for one fixed `ServiceClient<Methods>` and its transient unary byte methods. |

The Node entrypoint adds `ProxyCredentialPolicy`, `ProxyCookieScope` and
`ProxyCredentialAuthentication` for authenticated, per-surface credential
ownership. Cookie updates use bounded replacement storage and revoke the old
context before Clear allocates a successor. A failed successor allocation
preserves the independent `server_invalidated` fact in its error response.

The `./proxy` entrypoint exposes `createProxySurface`, `ProxySurface`,
`ProxySurfaceOptions`, `ProxySurfaceMode`, `ProxySessionBinding`,
`ProxySurfaceRequestPolicy`, `ProxyPublicationOwner` and `ProxyClearResult`.
A surface captures its original authenticated Session association, content
origin and publication generation before asynchronous work. Clear fences the
original worker and keeps cleanup observations tied to that worker; a canceled
or failed install does not claim that callbacks have already settled. Isolated
surfaces require an explicit path scope and do not disclose the Session or
credential owner to content code. Managed HTTP and WebSocket requests retain
credential copies until native write, response, socket and cancellation tails
have actually settled. `ProxyClearResult` reports server invalidation,
owned delivery fencing, successor installation, reuse readiness and physical
cleanup separately. Confirmed invalidation does not imply successor readiness
or completed callback cleanup.

## Swift

Applications `import Flowersec` from the `Flowersec` product. `TransportEnvironment`
fixes independent namespace/time trust, numerical endpoints, native TLS policy,
application resources and durable backing. `ConnectionMaterial` and the closed
SDK-owned `ConnectionMaterialSource` preserve their original identity generation
and activation profile. Connect with `connect(environment:source:requirements:)`,
`connect(environment:material:requirements:)` or the corresponding TransportEnvironment
methods. `ConnectionRequirements` expresses required guarantees before
consumption; `CleanupStatus` separates logical close from physical reclamation.

`ConnectError`, `SessionError` and `RetryDisposition` are the stable redacted
failure boundary. `ConnectionSourceFailure` retains its source code and retry
disposition. `ConnectionController` owns current acquisition, initialization,
retry and explicit replacement. Its configured initializer finishes before
current publication. An original fixed Session or prepared application handle
is not rebound after generation changes and is never replayed by the controller.
`ConnectionSnapshot.diagnostic` removes the live Session. A `retryAfter` deadline
cannot be bypassed by `retryNow()`.

`ConnectionAttemptFacts` records spend, admission, network readiness and
application publication as one-way observations. An uncertain or in-flight
admission remains unknown to callers; it cannot be retried automatically.
The TypeScript `LocalReport()` projection is available alongside the stable local report contract.
`AcceptedSession` identifies the accepted server session handed to application code.

`LocalReport` exposes only the stable constraint, available local facts and
cleanup actions, without a provider handle or protocol input. `Session.drain`
returns a stable `SessionDrainOperation`; repeated observations join the same
drain and a canceled wait does not reopen admission.

### Configured native transport

`TransportClientConfiguration`, `TransportTrustNamespace`,
`TransportPoolHistory` and the configured trusted-time adapter supply original
trust and once-spend continuity. `TransportApplicationIdentity` exposes public
keys and a close operation. `TransportPoolCredential` retains exact signed
pool material. `TransportConnectError` reports native establishment failures;
no decoded response, historical row or recovery lookup can construct a Session.

TransportEnvironment supports `makePreauthorizedPoolSource(_:identity:role:)`,
`makeLiveAuthoritySource(_:identity:)`,
`makeManagedPreauthorizedPoolSource(_:identity:)` and the closed
`TransportMaterialSourceConfiguration` variants. A finite source consumes
already issued local records. Live issuance/activation uses independent mTLS
`TransportControlHTTPSConfiguration` endpoints and a complete
`TransportLiveAuthoritySourceConfiguration`. Managed replenishment fixes
`TransportPoolSourceAuthorityConfiguration`,
`TransportManagedPoolSourceConfiguration` and
`TransportPoolRefillJournalConfiguration`; retained original intent controls
TopUp/Ack recovery. Managed Acquire takes only already installed local material
and returns `source_exhausted` immediately when empty, independently of the
configured background replenishment worker. Source replacement publishes a complete local snapshot;
already acquired material keeps its original one-use authority.

The native Apple profile implements direct and tunnel WebSocket dialers and
listeners, both Noise profiles and the transport/services/execution application
profiles. `accept(source:)` explicitly requires a listener; `connect(source:)`
uses the signed physical direction. Network listeners receive independent
`NativeListenerTLSConfiguration`. Explicit signed loopback HTTP routes use the
same endpoint handshake. Raw QUIC, WebTransport and datagrams are unavailable in
this profile; an unsupported requirement is refused without protocol fallback.

### Original live server and continuous relay

`TransportEnvironment.makeLiveServerSource(_:identity:)` starts the pinned authority mTLS
listener described by `TransportServerAllowHTTPSConfiguration` and
`TransportLiveServerSourceConfiguration`. An independently configured
`TransportLiveServerMaterial` is registered through
`TransportLiveServerSource.registerOriginal(_:)`, which returns its original
`TransportLiveServerBinding`. `LiveServerAdmissionStoreConfiguration` fixes
separate durable registration and admission history. Only the original final
ACK write publishes the prepared carrier; an exact duplicate request can
acknowledge that retained fact without another publication. Complete FSB
verification and the original admission COMMIT precede FSA and READY. Closing
the Source fences pending work without canceling a transferred material or Session.

`TransportEnvironment.serve(_:)` owns a bounded set of server admissions and
application callback tails. `ServeOptions` fixes the listener, requirements,
handler resolution, application authorization and release callbacks before an
admission begins. `ServeHandle.progress()` and `waitDrain()` report accepting,
pending sessions, outcome and cleanup; `close()` fences new work while each
admitted Session retains its own cleanup proof. Callback cancellation preserves
the original callback tail, and a release callback receives the authenticated
request context only after transport verification.

Original storage operations claim a finite execution slot under the Environment
gate, then perform durable work outside that gate. A late successful admission
COMMIT records admitted even when Drain, cancellation or expiry has already
fenced that original. Such a completion cannot publish FSA, READY or an
application Session. Physical storage close retains its original cleanup charge
until SQLite and file handles have actually closed.
Source and registration cleanup observers share the original close deadline.
Canceling an observer withdraws only that wait; the prepaid physical join and
its resource charge remain until native callbacks, control requests and storage
handles exit. Transferred material retains its original admission ledger
independently, so closing the Source does not wait for its future admission.
The ledger leaves the Source cleanup scope at that transfer. Releasing the last
material cannot make an already completed Source pending again; the Environment
continues to account for the ledger's physical close.
Closing an acquired live server material reports its remaining preparation,
carrier and control cleanup through the material's own status and bounded wait.
After a successful Session handoff, the Session owns its carrier independently.

`RelayHost`, `RelayHostConfiguration` and `RelayInitialPublication` own one
continuous relay and bounded queue. `RelayClaimStoreConfiguration` fixes its
independent ledger. `TransportLiveRelayRegistration` installs independent
future scopes and native carriers before client Prepare. Its pinned control
endpoints accept original `/tunnel/relay-ready`, `/tunnel/relay-prepare` and
`/tunnel/relay-activate` callbacks. Start `RelayHost.run()` concurrently and await
`RelayPublication.waitListening()` before connecting a live Source; this joins
local listener and control binding without consuming a physical child. Client and
server `relayPreparation` endpoints announce bound listeners without issuing
authorization. The client sends its
original TxA request only after native Prepare. Original TxB activation and role
Grants must match the frozen request; the native final ACK write releases HOP.
`TransportLiveRelayPublication` carries the original activation proof,
activation signing key ID, role Grants and independently fixed future scopes.
`publishOriginal(client:server:)`, `publishLiveOriginal(_:)` and
`registerLiveOriginal(_:)` admit subsequent independent originals. Both HOP
possession proofs and the paired durable claim precede relay proof and opaque
forwarding. Each leg uses its signed dialer/listener role.
`RelayPublication.waitCompletion()` reports the pair's actual result, while
cleanup joins its carriers and control callbacks. Stored refusals cannot restart
a pair or recover its original admission capability.

`ParentWinnerAuthorityConfiguration` independently binds one common CAS authority
across server and relay admission. Attach the same `parentWinner` configuration
to server-role `TransportPoolHistory`, `RelayClaimStoreConfiguration` and
`LiveServerAdmissionStoreConfiguration`. Server-role pool consumption uses this
same boundary for direct and tunnel candidates: it verifies the original FSB,
and tunnel HOP when present, then compares the same role-independent projection
before committing the local spend. Missing common CAS configuration refuses
server or relay admission; there is no candidate-local fallback. The complete
public `ParentWinnerSelection` is independent of local role and carrier; an exact
selection matches and a changed candidate, route or attempt conflicts.
`TransportEnvironment.makeParentWinnerAuthority(_:)` creates a secure bounded SQLite owner
from `ParentWinnerStoreConfiguration`; `ParentWinnerAuthority.configuration`
shares that authority. If server pool history was created without an adapter,
install the native configuration once through
`TransportEnvironment.installParentWinnerAuthority(_:)` before server-role pool
consumption; its authority ID must match the history. A qualified common service
adapter can instead be supplied in the history during TransportEnvironment creation.
Original authenticated FSB or both HOP possession proofs precede CAS; original
local admission or paired-claim COMMIT follows CAS. Pool-spend and
relay-claim ledgers persist an original-claim refusal before CAS. A live-server
registration is durably fixed before carrier preparation and remains a refusal
if admission later fails. A lost selection result cannot be resumed from decoded
material or history. Uncertainty stops the original run. Public readback and
durable history cannot mint a native admission capability.

### Named services and streams

A `Session` exposes reliable `ByteStream`, validated `StreamMetadata` and
`IncomingStream`. `encoded()`, `namespace`, `version` and
`byteValues` preserve canonical namespace bytes. `StreamHandlers` registers raw
application streams. `ReaderCursor` fixes independent read progress and
`WriteOperation` separates accepted bytes from completion. These original
stream owners do not move between Sessions.

`ServiceClient` and `ControllerServiceClient` bind a locally chosen service,
method, target, exact canonical contract and codec. `ContractAcceptance.exact`
or `ContractAcceptance.bounded(_:)` can restrict accepted contract changes to
explicit ranges without replacing the original binding. `ServiceContractSource`
refreshes contract snapshots through the ordinary invocation lane. Controller
bindings select current only before a new preparation. `ServiceOperation`,
`ServiceNotificationOperation` and `ServiceStreamingOperation` retain the
original request, Session and response obligations. `OperationReference` query
and cancellation observe original execution history without authorizing Start.
`OperationHandle` and `ServiceNotificationSubscription` retain their original
application owners. Controller notifications report their actual source
generation, phase and observation gaps without creating execution history.

See `docs/SWIFT_TRANSPORT_V4.md`, `flowersec-swift/README.md` and
`examples/swift/README.md` for current supported workflows.

## Rust

The `flowersec` crate exposes one current Rust client path through
`TransportEnvironment::connect(...)` and the crate-root `connect(...)`
convenience function. `ConnectionMaterialSource` captures identity, trust,
material and provider ownership; `ConnectionRequest` fixes semantic
requirements and an optional handler plan. `MaterialConnectionController`
provides bounded acquisition, candidate initialization and Session replacement.
The current server and application APIs use TransportEnvironment-owned Serve, Relay,
service, stream and operation owners. See [Rust transport](RUST_TRANSPORT_V4.md)
for their supported workflows.

`PreauthorizedPoolSource` captures `PoolTopUpConfiguration` and one original
source-owned operation. `TopUpOptions` bounds the request; `TopUpResult` and
`TopUpRecoveryResult` preserve local installation, acknowledgement and call
failure separately. `TopUpHandle` observes the retained original operation;
`TopUpError` and `TopUpErrorCode` do not grant replacement or replay authority.
Applied recovery verifies durable installation history and the current fence
without decoding consumed material or replacing the original identity.

`UnaryRequestContext::response_publication` returns the original
`ResponsePublication`; `UnaryRequestContext::maintenance_owner` borrows the
plan's `MaintenanceOwner`. `MaintenanceOwnerOptions` bounds observation slots.
`ResponsePublication::transfer_to` returns `ResponseTransferResult` and only
transfers observation and cleanup responsibility. `ResponsePublicationStatus`
keeps `ResponsePublicationState` and a finite `ResponsePublicationCause`;
`flushed` requires the complete original response's provider handoff and never
reverts because of a later carrier tail failure. `PoolSpendObservation` and
`PoolSpendState` preserve the original durable consume attempt's outcome without
providing another acquisition or connection right.

### Current Rust transport

The Rust original pool relay surface includes `SQLiteRelayBinding`,
`SQLiteRelayOptions`, `SQLiteRelayLedger`, `RelayPoolPublicationInput`,
`OriginalRelayPoolPublication`, `RelayParentRegistration`,
`ReverseTunnelProviderOptions`, `WssRelayLegOptions`, `WssRelayHostOptions`,
`WssRelayHost`, `WssRelayPublication`, `RelayOriginalIssuer`,
`RelayOriginalDeliveryOptions`, `RelayOriginalDeliveryHandle`,
`OriginalRelayDelivery` and `RemoteRelayPublication`. Live relay installation
uses `RelayLiveControlDeployment` and `RelayLivePreparationLimits`;
`RelayOriginalDeliveryHandle::live_forwarding_progress` and
`wait_live_completion` expose bounded aggregate `RelayLiveForwardingProgress`
observations from the retained original forwarding tasks without publication or
recovery authority. Fixed original mTLS delivery consumes the sealed pool publication through
`TransportEnvironment::original_relay_delivery`,
`OriginalRelayDelivery::register_pool_original` and
`RemoteRelayPublication::start_original`. Live tunnel delivery has a separate
`RemoteLiveTunnelServerPublication` capability: register the exact server-leg
Artifact, relay identity, service and audience before TxB, then publish the
confirmed proof and server Grant once. The client-facing live authorization
response carries only the activation proof and client-leg Grant; the server
Grant is never returned through that response. Registered JSON deployments
expose `RegisteredLiveTunnelSourceConfiguration` through
`LocalDirectMaterialSource::registered_live_tunnel_authority` and
`registered_live_reverse_tunnel_authority`; one installed original Artifact
owns one Acquire, physical preparation and signed authorization attempt. B uses
`OriginalLiveTunnelServerPublication::register_original_control` with
`RegisteredLiveServerControlConfiguration` and
`RegisteredLiveServerPreparation`, then consumes
`RegisteredLiveTunnelServerPublication::receive_original_publication` to verify
and acknowledge the exact original activation and server Grant on its retained
Account before Serve. External RelayHost control is independently fixed by
A's root `relay_preparation` and B's optional `relay_preparation`, with each
endpoint retaining its registered mTLS identity. A owns original readiness,
preparation and client activation; B owns reverse listener readiness; the
original authority TxB invocation owns server Grant delivery. Original Account
custody, transport backing and the occupied control position survive every
HTTP driver and final request-body view. The B-host consumes verified
material through `LiveServerDeliveryHandle::next_tunnel_publication`; this is a
bounded one-shot handoff with no status lookup or retry path. The dedicated host receiver binds
`WssRelayHost::serve_original_delivery` with independently installed issuer
identities and relay mappings. Registered continuations have no query, adoption,
reopen or retry surface. The original issuer captures the public
projection through `TransportEnvironment::relay_pool_publication`; the host
consumes it through `publish_pool`. The common protected parent authority fixes
one selection across direct admission and relay claims. Public rows and copied
Grant bytes cannot supply an original forwarding continuation. Physical WSS,
raw QUIC and WebTransport legs retain their actual cleanup owners and signed
resource bounds; native scopes remain opaque routing labels.


The `TransportEnvironment` publishes `identity_keys`, `namespace`,
`pool_connection_material`, `sqlite_pool_backing`, `connect_pool_wss`,
`connect_pool_wss_with_handler_plan` and `serve_wss`.
Its asynchronous `close` returns `Result<CleanupStatus, SessionError>` after a
bounded observation of the original cleanup operation. Actual tails remain
charged after `cleanup_incomplete`; an independent `wait_cleanup` timeout does
not close an active TransportEnvironment.
The supported production tuple is one direct network WSS candidate from a
preauthorized pool, the transport application profile, and no negotiated
optional features. It requires a Tokio multithread runtime. The original
TransportEnvironment provides trusted time, authorization subscriptions, finite resource
accounts, irreversible SQLite consumption and actual carrier cleanup.

Connection material and trust types are `IdentityKeys`, `Namespace`,
`NamespaceTrustRoot`, `PoolCredentialBytes`, `PoolConnectionMaterial`,
`WssConnectOptions`, `TransportConnectError` and `PostSpendFailure`. Private identity
keys stay in original handles; exact signed material is consumed once. Native
TLS validates TLS 1.3, the signed route and Origin policy, and either explicit
CA roots or the active complete DER pins. No platform-root fallback, DNS retry,
redirect, credential replay or fresh connection adoption occurs.

Durable pool types are `SQLitePoolBacking`, `SQLitePoolStore`,
`SQLitePoolOptions`, `SQLitePoolIdentity`, `SQLitePoolBinding`,
`SQLitePoolLimits`, `SQLitePoolContinuity`, `PoolStoreError`,
`PoolStoreFailure` and `PoolWriteState`. Continuity must come from independently
trusted host history. Closing a store does not release persistent disk backing;
`release_removed` requires the actual database and journal files to be removed.
A successful irreversible consume followed by connection failure is explicitly
`TransportConnectError::Spent`; it never grants retry authority.

Failed Connect attempts close undelivered Sessions and retain their original
control work reservation while observing cleanup. Each loser has five seconds
from its close request; the total cleanup deadline is ten seconds from the
first loser close or winner confirmation, whichever happens first. A timeout
returns `TransportConnectError::CleanupIncomplete` with the original finite
failure and `ConnectionAttemptFacts`. Physical owners keep their charges until
actual exit. The Controller exposes `CleanupIncomplete` and stops automatic
candidate acquisition for that attempt.

Accepted servers use `AcceptedMaterialSource`, `WssServeOptions`,
`WssServerIdentity`, `ServeHandle`, `SQLiteAdmissionBinding` and
`SQLiteAdmissionAuthority`. The material callback supplies lookup bytes;
the original namespace and accepted socket independently verify admission.
The authority retains distinct ParentWinner and AdmissionLedger facts in
SQLite revision 3. `ServeHandle` exposes `local_address`, `accept`, `drain`,
`wait_drain`, `close`, `cleanup_status` and `wait_cleanup`. A pending or late
READY cannot publish after Serve Drain/Close, and shared TransportEnvironment ownership
remains with the caller. Conflict results are `AdmissionConflict` and
`WinnerConflict` on `PoolStoreFailure`.

`WssServeOptions` fixes `ServeCallbacks`, `ApplicationLimits` and parent
cancellation. `authorize_request` accepts a bounded `ServeRequestContext` and
returns `RequestAuthorization` before upgrade. After authenticated FSB and
identity checks, `resolve_handlers` and `authorize_application` use
`AuthenticatedRequestContext` and its detached `ApplicationBinding`.
`reserve_lease` registers one `ApplicationAuthorizationLease` during the
original authorization callback, including late success. Only an authorized
`AuthorizeApplicationResult` with that lease reaches durable admission.
`ApplicationAuthorization` records not-started, authorized, rejected or
unknown authorization in the final `ServeReleaseContext`.

`TransportEnvironment::handler_plan` captures `HandlerPlanOptions` into an
immutable, TransportEnvironment-bound `HandlerPlan`. `StreamDispatch` selects explicit
manual acceptance or frozen `RawStreamRegistration` entries. Registered
`RawStreamHandler` implementations return `StreamAuthorization` and own
bounded authorization/handler work; public `next_open` cannot bypass this
dispatcher. Closing a plan seals future captures and preserves existing ones.
The Connect variant accepts the same plan with explicit `ApplicationLimits`,
captures it before durable pool consumption, and attaches it before returning
the READY Session. Connect cleanup waits for admitted handler work before
returning the original application charge.

After the original READY publication claim, `on_session` returns
`SessionAcceptance`: Retained, Queue (for `accept`) or Rejected. A later Close
cannot cancel the already-claimed call. `release` runs once after real cleanup
or an explicit incomplete observation. Cancellation closes a registered or
late lease once, without dropping its running authorizer. Incomplete lease
observations reuse that owner; an incomplete Release cannot be retried or
refunded. `ServeError` projects `ServeFailure` and actual cleanup without
application error strings. Callback futures must retain their own work until
exit; independently retained work belongs to the registered lease, whose
cleanup must not depend on Release starting. Error snapshots grant no new
background-work ownership. See [Rust transport profile](RUST_TRANSPORT_V4.md) for the
fixed limits and original callback/worker cleanup ordering.

`ServeDrainOperation` exposes `result` and `wait` over the original group
operation. `ServeDrainResult` contains the stable `outcome`, bounded `error`
and current `cleanup` view. Every child uses the earlier of its original Drain
deadline and the group's first absolute deadline. Existing physical tails
remain cleanup responsibilities; failures after group closure remain part of
the group result after the child exits. `wait_drain`, `wait_cleanup` and the
operation's `wait` return `Result` and share sixteen prepaid pending observer
slots; full capacity returns `TransportConnectError::Capacity`. Canceled observation
only releases its slot, and terminal observation requires no new slot.

The completed owner exposes `Session`, `Stream`, `OpenRequest`,
`Metadata`, `ProbeOutcome`, `ProbeResult`, `DrainOperation`,
`DrainOutcome` and `DrainResult`. Streams implement the existing `ByteStream`
contract. Probe, rekey, Drain, termination and cleanup share the original
Session and carrier. A successful publish waits for actual ordered I/O.
`ProbeResult` retains finite outcome, `submitted`, `complete` and optional
elapsed time from original admission. Eight probe owners share the original
maintenance budget; cancellation and timeout remove their matchers while real
provider tails retain ownership. Rekey interrupts ordinary samples. Optional
`AutomaticLivenessPolicy` on `TransportEnvironmentOptions::automatic_liveness`
reserves one of those owners and counts only fully published, unstalled samples
with a complete response budget. It defaults to disabled; a configured miss
threshold reports `SessionError::LivenessPathUnresponsive` without business replay.
`Stream::wait_peer_authenticated` waits for an already accepted offset to be
covered by a real ACK or normal DRAINED proof, retaining fulfilled observations
after retirement. Dropping `close_write` or `finish` waits does not revoke the
original FIN; aborted proof and missing stream state cannot report successful
Finish.

TransportEnvironment configuration and observations use `TransportEnvironmentOptions`,
`ResourceLimits`, `EnvironmentError`, `TrustedTimeSource`, `TrustedTimeSample`,
`TrustedTimeProfile`, `ConnectionRequirements` and `CleanupStatus`. The current
Rust resource ledger separately bounds all eleven local dimensions:
`sdk_bytes`, `provider_bytes`, `disk_bytes`, `items`, `work_slots`, `tasks`,
`timers`, `connections`, `tls_handshakes`, `sessions` and `native_handles`.
`ResourceLimits::DIMENSIONS` and `ResourceLimits::values` expose that fixed order.
Each reservation, split and release preserves the same original owner chain.
Provider runtime, SDK queues and retained disk backing have separate caps and
lifetimes. Full provider/deployment qualification remains unfinished; configured
bounds do not prove total host RSS or independently qualify every design profile.

Owned read/write helpers are `ReadProgress`, `ReadResult`, `ReadWaitStatus`,
`ReadStreamStatus`, `ReadCause`, `ReadError`, `ReadErrorCode`, `ReadErrorScope`,
`ReadRetryDisposition`, `ReadMethodFailure`, `ReadMethodFailureReason`,
`ReaderCursor`, `ReaderCursorOptions`, `ReaderCursorSnapshot`, `StreamReadOwner`,
`StreamReadPermit`, `ReadDeliveryAuthorization`, `StreamExt`, `WriteOperation`,
`WriteProgress`, `WriteRequestAdmission` and `WriteStagingOwner`. The public
`OperationHandle`, `OperationReference`, `OperationStatus`, `ResultPayload` and
`OperationNotificationSubscription` types do not imply a completed v4 RPC, service,
execution or notification transport. Those application assemblies,
candidate racing, live-authority,
tunnel, raw QUIC, WebTransport, datagrams and controller assembly remain outside
this Rust client entrance. See [Rust transport profile](RUST_TRANSPORT_V4.md).

## Cross-language semantics

Applications use the same authenticated Session, registered Stream and service
operation semantics across SDKs. A language-specific result type or convenience
codec does not select another wire protocol or acquire additional authority.
Service application errors use the method's declared code and payload codec;
transport errors remain separate. Invalid inbound errors fail at the Session
or protocol boundary, and invalid outbound handler errors are rejected before
publication. Application error taxonomies remain local to the captured service
contract.

Stream reads and writes retain the original admitted buffers, direction owner
and final status. Cancellation or timeout does not erase already accepted
bytes, FIN publication or a fulfilled authenticated delivery proof. A provider
failure is reported with its actual Stream or Session scope. Backpressure and
maintenance retain finite queue limits; a shared ordered carrier does not
promise independent progress for another Stream when one Stream stalls.

Application metadata uses a bounded, construction-validated envelope. Its
namespace, version and application byte values are captured before opening the
Stream; JSON convenience values additionally use an explicit local descriptor
with validated field, number, depth and size limits. Incoming Streams expose
the same envelope and application authorization boundary. A metadata projection
does not replace the original bytes or authorize an application request.

Unreliable messages are an SDK-profile capability. Go, TypeScript and Rust
expose `UnreliableMessageChannel` only when the authenticated Session selected
the signed feature on a complete supported datagram route. Accepted send means
local provider submission and does not prove delivery or remote application
consumption. Size, expiry, budget, receive availability and closure remain
bounded channel outcomes. Swift explicitly reports the capability as unsupported
and exposes no placeholder channel.

## Error Boundary

Public connection and Session failures expose stable bounded codes and the
original owner's detached facts, including consumption, admission, READY,
application publication and cleanup when known. They do not retain raw
credentials, credential-bearing URLs, tokens, peer payloads, private keys,
carrier handles or arbitrary provider error objects. `ConnectionDiagnostic`
is the monitoring projection of state, attempt, bounded failure phase and code,
retry disposition and already-recorded connection facts. Observation performs
no acquisition, reservation or provider I/O. Snapshot, update and subscription
APIs may coalesce intermediate states while preserving their latest recorded
view. Service application errors retain only the declared bounded code and
payload under their captured codec.

Controller retry decisions distinguish terminal refusal, retryable failure and
an absolute `retry_after` constraint. Each runtime's bounded scheduler retains
its original clock, retry policy and attempt deadline; an explicit retry cannot
bypass an authority's not-before constraint. Each attempt captures fresh source
preparation and its original identity, provider and generation. A committed
`ConnectionMaterial` is never silently reused for another attempt. The
controller does not migrate Streams or replay operations and writes.

### Durable consumption integration

The application or configured activation provider owns the durable record for
each one-use material acquisition. The Environment admits the complete Session
graph before acquisition; the selected pool or live source then performs its
single-use acquisition and reports whether the irreversible operation was not
submitted, committed, or remains unknown. A source does not fall back to another
provider after an uncertain result, and an unknown result cannot make the
possibly consumed material available again.

Provider integrations should persist the opaque consumption identity with one
of these patterns:

- **Database uniqueness:** insert the consumption identity under a unique
  constraint in the same durable transaction that authorizes the acquisition
  or attempt. Network activity may begin only after that transaction commits.
- **Atomic file:** create a record with create-new/no-overwrite semantics, write
  the complete record, sync the file, and sync its containing directory before
  allowing network activity.
- **Transactional state:** persist the consumed state or an idempotency record
  in the application's existing durable business transaction, and allow the
  connection attempt only after that transaction commits.

If a persistence commit has an uncertain outcome, fail closed and treat the
material as spent or unknown according to the provider's recorded fact. An
in-memory ledger is not an acceptable production default, and recovery logic
must never automatically reuse material whose durable consumption may have
committed. Pool TopUp is a separate authenticated maintenance operation; it does
not run from a failed Connect path or return consumed material to the pool.

## Version Scope

The maintained tree uses the current module paths and Flowersec transport,
session, control-plane, and proxy contracts.

Public changes follow `docs/API_CHANGE_POLICY.md`; stable failures follow `docs/ERROR_MODEL.md`, and the reviewed symbol inventory is `stability/api_contract_manifest.json`.

## Native HTTP application streams

`flowersec.ServeHTTPStream(...)` serves a single already-authorized ByteStream with
`flowersec.HTTPStreamOptions` header and idle admission limits. It owns HTTP
keep-alive, upgrades, and cancellation of hijacked connections without a listening
TCP port. Read deadline interruption preserves subsequent reads; write deadline
expiry terminates the stream. Product authorization and stream-kind registration
remain with the embedding application. There is no response-body transformation.

The Node-only `createByteStreamDuplex(...)` export adapts one ByteStream to a
bounded Node Duplex with half-close, 64 KiB write chunks, partial-write progress,
read backpressure, and abort/reset propagation. It never decodes HTTP or WebSocket
frames, reconnects, or replays application bytes. These embedding helpers do not
change wire identifiers, artifacts, or carrier selection.

The Node-only v4 `asNodeDuplex(...)` directly owns an accepted v4 Stream with a
finite producer profile and original Stream/Session resource admission.
`V4NodeDuplex`, `V4NodeDuplexOptions` and `V4NodeProducerProfile` describe its
native API and deployment bounds. `V4NodeDuplexError` carries a bounded
`V4NodeDuplexFailure` and stable partial write progress. Native writable finish
requires normal authenticated DRAINED; reverse reads continue independently.
Normal automatic cleanup is distinguished from caller destroy/abort, which
resets the Stream. Cleanup timeouts retain real native tails and report
`cleanup_incomplete`. See [the v4 Node adapter contract](TYPESCRIPT_TRANSPORT_V4.md#node-carrier-and-sqlite-store).

The v4 `asWebStreams(...)` export returns the standard pair described by
`V4WebStreams` and `V4WebStreamsOptions`, with exclusive original Stream I/O
ownership and finite native queue admission. `V4WebStreamError` exposes a bounded
`V4WebStreamFailure` and partial write progress. Readable cancel and writable
abort terminate their own direction; writable close requires authenticated
Finish while reverse reads continue. Standard pipe options keep their native
meaning. [The Web Streams contract](TYPESCRIPT_TRANSPORT_V4.md#closure-and-persistent-history)
describes the queue, backing and cleanup bounds.

## Go TransportEnvironment and operations

The public Go assembly is `flowersec.NewTransportEnvironment(...)`. Its
explicit clock, verification-continuity registry, executor, resource root and
same-root account handles are supplied by trusted host composition. The
TransportEnvironment hosts immutable connection material and admits its original bounded
Session position before acquisition, carrier preparation and spend. Source,
static material and preauthorized pool inputs share that implementation.

`ConnectSource` takes an immutable identity plus an original lease provider;
`ConnectMaterial` consumes TransportEnvironment-owned material; `ConnectPool` takes a
complete installed pool item after local admission. Pool acquisition never
starts a TopUp or falls back to live issuance. An uncertain or canceled Connect
cannot turn consumed material into a reusable attempt. Pool and live authority
inputs are explicit and mutually exclusive.

`Session` exposes authenticated `Info`, `Drain`/`WaitDrain`, `Rekey`,
`ProbeLiveness`, unary preparation, fixed-session service binding, and termination
and cleanup observation. `OperationHandle` retains the original request,
contract, publication and deferred result rights. Repeated Start joins the same
operation; TakeResult and TakeEncodedResult share one consumption right. Waiting
cancellation does not retry the operation or release active provider work.
`Cancel` ends local result interest; `RequestCancel` requests authenticated
business cancellation through the management path.

`MethodRoutes.InitialOffers` installs bounded, exact admission windows during
RPC assembly. `AdvertisedContract` selects one digest from that method's declared
contracts after its windows are installed. An execution advertisement requires a
currently usable window; construction does not issue or renew one. The immutable
connection recipe copies and charges these windows before material acquisition.

Durable service hosts use `SQLiteExecutions.ReadRegistration` to read the
original canonical contract and `SQLiteExecutionRegistration` from their
explicitly created or reopened execution database. The caller supplies bounded
contract storage and its original finite trusted registration guard. The result
contains the persisted revision, enabled state and at most eight unchanged
windows; it grants no execution rights. Hosts install only applicable original
windows and advertise only a currently usable one. Expired windows require an
explicit durable registration update before new admission can be advertised.
Reopening requires independent continuity evidence and never replays a handler.
`DurableServiceBinding` attaches the original durable owner to the shared
service registry; dispatch, duplicate joins and management reads use that owner.

Restart-flush unary handlers receive their original `ResponsePublication` before
execution and may transfer its observation once to the invocation's own
`MaintenanceOwner`. Only the original complete provider publication can report
flushed. Handler failure, STOP_OUTPUT, expiry, or owner unavailability cannot
manufacture that outcome.

`PreauthorizedPoolSource.TopUp` joins its one unresolved durable intent.
`RecoverPendingTopUps` reconstructs the original journal facts without appending
new material; `TopUpStatus` reads the exact opaque operation handle without
control I/O. Installed and acknowledged frontiers remain distinct. Caller wait
cancellation does not cancel the source worker. Source Close seals new work and
WaitCleanup joins actual provider tails.

TransportEnvironment cleanup retires its metadata only after original Session, material,
source and provider obligations finish. Shared clocks, resource roots, executors,
trust stores and durable stores remain caller-owned. See
[Go transport assembly](GO_TRANSPORT_V4.md) for construction and cleanup order.

Go aggregate diagnostic counters are available through
`(*flowersec.TransportEnvironment).DiagnosticCounts`. Detailed events are opt-in:
`flowersec.NewDiagnosticSink` requires the caller's original resource reservation
and an application executor, and delivers events on its independent diagnostic
lane. `flowersec.DiagnosticSinkCharge` computes the required reservation. Events
contain finite diagnostic fields and SDK-generated correlation IDs; raw errors,
URLs, credentials, payloads and caller-owned identifiers are excluded.

The sink bounds live operations and queued events. A nil sampling setting selects
1%; an explicit setting accepts 0 through 100 basis points. Close seals the sink;
WaitCleanup joins actual callback completion before its reservation is released.
The following table registers the diagnostic vocabulary and callable surface.

| Symbol | Declaration |
| --- | --- |
| `(*flowersec.DiagnosticOperation).Close` | method |
| `(*flowersec.DiagnosticOperation).Emit` | method |
| `(*flowersec.DiagnosticOperation).EmitDiagnostic` | method |
| `(*flowersec.DiagnosticOperation).GoString` | method |
| `(*flowersec.DiagnosticOperation).String` | method |
| `(*flowersec.DiagnosticSink).Begin` | method |
| `(*flowersec.DiagnosticSink).CleanupStatus` | method |
| `(*flowersec.DiagnosticSink).Close` | method |
| `(*flowersec.DiagnosticSink).Counters` | method |
| `(*flowersec.DiagnosticSink).Done` | method |
| `(*flowersec.DiagnosticSink).GoString` | method |
| `(*flowersec.DiagnosticSink).String` | method |
| `(*flowersec.DiagnosticSink).WaitCleanup` | method |
| `(*flowersec.TransportEnvironment).DiagnosticCounts` | method |
| `flowersec.DiagnosticAttempt` | func |
| `flowersec.DiagnosticAttemptAtLeastEight` | const |
| `flowersec.DiagnosticAttemptBucket` | type |
| `flowersec.DiagnosticAttemptBucket.String` | method |
| `flowersec.DiagnosticAttemptFourToSeven` | const |
| `flowersec.DiagnosticAttemptOne` | const |
| `flowersec.DiagnosticAttemptOther` | const |
| `flowersec.DiagnosticAttemptTwoToThree` | const |
| `flowersec.DiagnosticCleanupStatus` | type |
| `flowersec.DiagnosticCleanupStatus.Validate` | method |
| `flowersec.DiagnosticCode` | type |
| `flowersec.DiagnosticCode.String` | method |
| `flowersec.DiagnosticCodeCancelled` | const |
| `flowersec.DiagnosticCodeCleanupIncomplete` | const |
| `flowersec.DiagnosticCodeCurrentDatagramDropped` | const |
| `flowersec.DiagnosticCodeDiagnosticDropped` | const |
| `flowersec.DiagnosticCodeFreshnessExpired` | const |
| `flowersec.DiagnosticCodeFutureDatagramDropped` | const |
| `flowersec.DiagnosticCodeIdentityRejected` | const |
| `flowersec.DiagnosticCodeOK` | const |
| `flowersec.DiagnosticCodeOldDatagramDropped` | const |
| `flowersec.DiagnosticCodeOther` | const |
| `flowersec.DiagnosticCodeReservationConflict` | const |
| `flowersec.DiagnosticCodeResourceExhausted` | const |
| `flowersec.DiagnosticCodeRevoked` | const |
| `flowersec.DiagnosticCodeSlowConsumer` | const |
| `flowersec.DiagnosticCodeSpendUnknown` | const |
| `flowersec.DiagnosticCodeStoreUnavailable` | const |
| `flowersec.DiagnosticCodeTLSRejected` | const |
| `flowersec.DiagnosticCodeTimeout` | const |
| `flowersec.DiagnosticCounts` | type |
| `flowersec.DiagnosticDuration` | func |
| `flowersec.DiagnosticDuration100To999MS` | const |
| `flowersec.DiagnosticDuration10To99MS` | const |
| `flowersec.DiagnosticDuration1To9S` | const |
| `flowersec.DiagnosticDurationAtLeast10S` | const |
| `flowersec.DiagnosticDurationBucket` | type |
| `flowersec.DiagnosticDurationBucket.String` | method |
| `flowersec.DiagnosticDurationOther` | const |
| `flowersec.DiagnosticDurationUnder10MS` | const |
| `flowersec.DiagnosticEvent` | type |
| `flowersec.DiagnosticEvent.AppendJSON` | method |
| `flowersec.DiagnosticEvent.CorrelationID` | method |
| `flowersec.DiagnosticEvent.Fields` | method |
| `flowersec.DiagnosticEvent.GoString` | method |
| `flowersec.DiagnosticEvent.MarshalJSON` | method |
| `flowersec.DiagnosticEvent.RetentionDeadline` | method |
| `flowersec.DiagnosticEvent.String` | method |
| `flowersec.DiagnosticFields` | type |
| `flowersec.DiagnosticFields.Normalize` | method |
| `flowersec.DiagnosticMetric` | type |
| `flowersec.DiagnosticMetric.String` | method |
| `flowersec.DiagnosticMetricCleanupTimeout` | const |
| `flowersec.DiagnosticMetricConnectionAttempt` | const |
| `flowersec.DiagnosticMetricConnectionFailure` | const |
| `flowersec.DiagnosticMetricCount` | const |
| `flowersec.DiagnosticMetricCurrentDatagramDrop` | const |
| `flowersec.DiagnosticMetricDiagnosticDrop` | const |
| `flowersec.DiagnosticMetricFutureDatagramDrop` | const |
| `flowersec.DiagnosticMetricIdentityRejection` | const |
| `flowersec.DiagnosticMetricOldDatagramDrop` | const |
| `flowersec.DiagnosticMetricOther` | const |
| `flowersec.DiagnosticMetricRekeyPhaseCompleted` | const |
| `flowersec.DiagnosticMetricRekeyStarted` | const |
| `flowersec.DiagnosticMetricRekeySucceeded` | const |
| `flowersec.DiagnosticMetricRekeyTimeout` | const |
| `flowersec.DiagnosticMetricReservationConflict` | const |
| `flowersec.DiagnosticMetricResourceRejection` | const |
| `flowersec.DiagnosticMetricSlowConsumer` | const |
| `flowersec.DiagnosticMetricSpendUnknown` | const |
| `flowersec.DiagnosticMetricStoreFailure` | const |
| `flowersec.DiagnosticMetricTLSRejection` | const |
| `flowersec.DiagnosticOperation` | type |
| `flowersec.DiagnosticPhase` | type |
| `flowersec.DiagnosticPhase.String` | method |
| `flowersec.DiagnosticPhaseActivate` | const |
| `flowersec.DiagnosticPhaseApplication` | const |
| `flowersec.DiagnosticPhaseCleanup` | const |
| `flowersec.DiagnosticPhaseHandshake` | const |
| `flowersec.DiagnosticPhaseMaterial` | const |
| `flowersec.DiagnosticPhaseOther` | const |
| `flowersec.DiagnosticPhasePrepare` | const |
| `flowersec.DiagnosticPhaseRekeyConfirmation` | const |
| `flowersec.DiagnosticPhaseRekeyLocalPrepare` | const |
| `flowersec.DiagnosticPhaseRekeyPrepare` | const |
| `flowersec.DiagnosticPhaseRekeyProtocolPrepare` | const |
| `flowersec.DiagnosticPhaseRekeyRetire` | const |
| `flowersec.DiagnosticPhaseRekeySwitch` | const |
| `flowersec.DiagnosticPhaseSpend` | const |
| `flowersec.DiagnosticRetryDisposition` | type |
| `flowersec.DiagnosticRetryDisposition.String` | method |
| `flowersec.DiagnosticRetryOther` | const |
| `flowersec.DiagnosticRetryPreserveFacts` | const |
| `flowersec.DiagnosticSink` | type |
| `flowersec.DiagnosticSinkCharge` | func |
| `flowersec.DiagnosticSinkConfig` | type |
| `flowersec.DiagnosticState` | type |
| `flowersec.DiagnosticState.String` | method |
| `flowersec.DiagnosticStateClosed` | const |
| `flowersec.DiagnosticStateDraining` | const |
| `flowersec.DiagnosticStateFailed` | const |
| `flowersec.DiagnosticStateOther` | const |
| `flowersec.DiagnosticStateReady` | const |
| `flowersec.DiagnosticStateStarting` | const |
| `flowersec.NewDiagnosticSink` | func |

The following table registers the current public Go API, owner operations
and result vocabulary. Schema/provider qualification is a separate requirement
and is not implied by symbol availability.

| Symbol | Declaration |
| --- | --- |
| `(*flowersec.ConnectError).Code` | method |
| `(*flowersec.ConnectError).Error` | method |
| `(*flowersec.ConnectError).Is` | method |
| `(*flowersec.ConnectError).RetryDisposition` | method |
| `(*flowersec.ConnectError).Unwrap` | method |
| `flowersec.ConnectError` | type |
| `flowersec.ConnectErrorCode` | type |
| `flowersec.ConnectErrorCode.String` | method |
| `(*flowersec.ConnectionMaterial).Close` | method |
| `(*flowersec.ConnectionMaterial).WaitCleanup` | method |
| `(*flowersec.MaintenanceOwner).Close` | method |
| `(*flowersec.NotificationSubscription).CleanupStatus` | method |
| `(*flowersec.NotificationSubscription).Close` | method |
| `(*flowersec.NotificationSubscription).WaitClosed` | method |
| `(*flowersec.OperationHandle).AbandonResult` | method |
| `(*flowersec.OperationHandle).Cancel` | method |
| `(*flowersec.OperationHandle).CleanupStatus` | method |
| `(*flowersec.OperationHandle).Close` | method |
| `(*flowersec.OperationHandle).Progress` | method |
| `(*flowersec.OperationHandle).Reference` | method |
| `(*flowersec.OperationHandle).RequestCancel` | method |
| `(*flowersec.OperationHandle).Start` | method |
| `(*flowersec.OperationHandle).StartContext` | method |
| `(*flowersec.OperationHandle).Status` | method |
| `(*flowersec.OperationHandle).TakeEncodedResult` | method |
| `(*flowersec.OperationHandle).TakeResult` | method |
| `(*flowersec.OperationHandle).TakeResultContext` | method |
| `(*flowersec.OperationHandle).WaitCleanup` | method |
| `(*flowersec.OperationHandle).WaitStatus` | method |
| `(*flowersec.ReaderCursor).Close` | method |
| `(*flowersec.ReaderCursor).Progress` | method |
| `(*flowersec.ReaderCursor).ReadExactly` | method |
| `(*flowersec.ReaderCursor).ReadLine` | method |
| `(*flowersec.ReaderCursor).ReadUntil` | method |
| `(*flowersec.ReaderCursor).TakePrefix` | method |
| `(*flowersec.ResponsePublication).State` | method |
| `(*flowersec.ResponsePublication).TransferTo` | method |
| `(*flowersec.ResponsePublication).Wait` | method |
| `(*flowersec.ServeHandle).CleanupStatus` | method |
| `(*flowersec.ServeHandle).Close` | method |
| `(*flowersec.ServeHandle).Drain` | method |
| `(*flowersec.ServeHandle).WaitCleanup` | method |
| `(*flowersec.ServeHandle).WaitDrain` | method |
| `(*flowersec.TransportEnvironment).Close` | method |
| `(*flowersec.TransportEnvironment).Connect` | method |
| `(*flowersec.TransportEnvironment).ConnectMaterial` | method |
| `(*flowersec.TransportEnvironment).WaitCleanup` | method |
| `(*flowersec.TypedMessageStream).CleanupStatus` | method |
| `(*flowersec.TypedMessageStream).Close` | method |
| `(*flowersec.TypedMessageStream).CloseWrite` | method |
| `(*flowersec.TypedMessageStream).Finish` | method |
| `(*flowersec.TypedMessageStream).Receive` | method |
| `(*flowersec.TypedMessageStream).ReceiveEncoded` | method |
| `(*flowersec.TypedMessageStream).Send` | method |
| `(*flowersec.TypedMessageStream).WaitCleanup` | method |
| `(*flowersec.ConnectionMaterial).Close` | method |
| `(*flowersec.ConnectionMaterial).WaitCleanup` | method |
| `(*flowersec.TransportEnvironment).Close` | method |
| `(*flowersec.TransportEnvironment).Connect` | method |
| `(*flowersec.TransportEnvironment).ConnectMaterial` | method |
| `(*flowersec.TransportEnvironment).ConnectMaterialLiveSQLite` | method |
| `(*flowersec.TransportEnvironment).ConnectMaterialPool` | method |
| `(*flowersec.TransportEnvironment).ConnectPool` | method |
| `(*flowersec.TransportEnvironment).ConnectSource` | method |
| `(*flowersec.TransportEnvironment).ConnectSourceLiveSQLite` | method |
| `(*flowersec.TransportEnvironment).ConnectSourcePool` | method |
| `(*flowersec.TransportEnvironment).CreateMaterial` | method |
| `(*flowersec.TransportEnvironment).NewMaterialPool` | method |
| `(*flowersec.TransportEnvironment).Snapshot` | method |
| `(*flowersec.TransportEnvironment).WaitCleanup` | method |
| `(*flowersec.PreauthorizedPoolSource).Acquire` | method |
| `(*flowersec.PreauthorizedPoolSource).Close` | method |
| `(*flowersec.PreauthorizedPoolSource).GoString` | method |
| `(*flowersec.PreauthorizedPoolSource).MarshalJSON` | method |
| `(*flowersec.PreauthorizedPoolSource).RecoverPendingTopUps` | method |
| `(*flowersec.PreauthorizedPoolSource).String` | method |
| `(*flowersec.PreauthorizedPoolSource).TopUp` | method |
| `(*flowersec.PreauthorizedPoolSource).TopUpStatus` | method |
| `(*flowersec.PreauthorizedPoolSource).WaitCleanup` | method |
| `(*flowersec.ServiceClient).Call` | method |
| `(*flowersec.ServiceClient).Close` | method |
| `(*flowersec.ServiceClient).CleanupStatus` | method |
| `(*flowersec.ServiceClient).WaitCleanup` | method |
| `(*flowersec.ServiceClient).Dispatch` | method |
| `(*flowersec.ServiceClient).Prepare` | method |
| `(*flowersec.Session).AcceptStream` | method |
| `(*flowersec.Session).BindService` | method |
| `(*flowersec.Session).CleanupStatus` | method |
| `(*flowersec.Session).ConnectionAttemptFacts` | method |
| `(*flowersec.Session).ConnectionDiagnostic` | method |
| `(*flowersec.Session).LocalReport` | method |
| `(*flowersec.Session).Close` | method |
| `(*flowersec.Session).Drain` | method |
| `(*flowersec.Session).Info` | method |
| `(*flowersec.Session).OpenStream` | method |
| `(*flowersec.Session).PrepareUnary` | method |
| `(*flowersec.Session).ProbeLiveness` | method |
| `(*flowersec.Session).QueryOperation` | method |
| `(*flowersec.Session).Rekey` | method |
| `(*flowersec.Session).RequestOperationCancel` | method |
| `(*flowersec.Session).WaitCleanup` | method |
| `(*flowersec.Session).WaitDrain` | method |
| `(*flowersec.Session).WaitTermination` | method |
| `(*flowersec.WriteOperation).Cancel` | method |
| `(*flowersec.WriteOperation).CleanupStatus` | method |
| `(*flowersec.WriteOperation).Progress` | method |
| `(*flowersec.WriteOperation).Start` | method |
| `(*flowersec.WriteOperation).Wait` | method |
| `flowersec.ApplicationIdentity` | type |
| `flowersec.CleanupStatus` | type |
| `flowersec.ConnectionAttemptFacts` | type |
| `flowersec.ConnectionCleanupStatus` | type |
| `flowersec.ConnectionDiagnostic` | type |
| `flowersec.ConnectionDiagnosticFailure` | type |
| `flowersec.LocalReport` | type |
| `flowersec.CloseResult` | type |
| `flowersec.ConnectionMaterial` | type |
| `flowersec.ConnectionMaterialSource` | type |
| `flowersec.ConnectionMaterialSource.AcquireLease` | interface_method |
| `flowersec.ConnectionRequirements` | type |
| `flowersec.CopyOptions` | type |
| `flowersec.CopyResult` | type |
| `flowersec.CreateSQLite` | func |
| `flowersec.CreateSQLiteTopUpJournal` | func |
| `flowersec.DelimiterNotFound` | const |
| `flowersec.EncodePoolMaterial` | func |
| `flowersec.ErrAlreadyStarted` | var |
| `flowersec.ErrCleanupIncomplete` | var |
| `flowersec.ErrOperationClosed` | var |
| `flowersec.ErrOperationNotStarted` | var |
| `flowersec.ErrPublicationAlreadyTransferred` | var |
| `flowersec.ErrPublicationExpired` | var |
| `flowersec.ErrPublicationInvalid` | var |
| `flowersec.ErrPublicationOwnerUnavailable` | var |
| `flowersec.ErrReadInProgress` | var |
| `flowersec.ErrResponseLimitUnsupported` | var |
| `flowersec.ErrResultAbandoned` | var |
| `flowersec.ErrResultAlreadyDelivered` | var |
| `flowersec.ErrTransportUnavailable` | var |
| `flowersec.ErrMaterialNotReady` | var |
| `flowersec.ErrSpendNotObserved` | var |
| `flowersec.ErrStorageFormat` | var |
| `flowersec.ErrStorageUnavailable` | var |
| `flowersec.MaintenanceOwner` | type |
| `flowersec.MessageSendAdmission` | type |
| `flowersec.MessageSendOptions` | type |
| `flowersec.MessageSendQueued` | const |
| `flowersec.MessageSendResult` | type |
| `flowersec.MessageSendTryNow` | const |
| `flowersec.MessageStreamDefinition` | type |
| `flowersec.NewConnectionMaterial` | func |
| `flowersec.NewTransportEnvironment` | func |
| `flowersec.NewAge` | func |
| `flowersec.NewApplicationExecutor` | func |
| `flowersec.NewApplicationIdentity` | func |
| `flowersec.NewApplicationIdentityFromBytes` | func |
| `flowersec.NewArtifactLease` | func |
| `flowersec.NewArtifactLeaseFromBytes` | func |
| `flowersec.NewConnectionMaterial` | func |
| `flowersec.NewClock` | func |
| `flowersec.NewDeadline` | func |
| `flowersec.NewNamespaceDurableBootstrap` | func |
| `flowersec.NewNamespaceOnlineBootstrap` | func |
| `flowersec.NewNamespaceTrustAnchor` | func |
| `flowersec.NewPoolHTTPSTransport` | func |
| `flowersec.NewPoolMaterialDecoder` | func |
| `flowersec.NewPoolResultDecoder` | func |
| `flowersec.NewPreauthorizedPoolSource` | func |
| `flowersec.NewPreparedMessages` | func |
| `flowersec.NewPreparedStream` | func |
| `flowersec.NewResourceRoot` | func |
| `flowersec.NewSQLiteBacking` | func |
| `flowersec.NewSQLiteLiveMaintenance` | func |
| `flowersec.NewSQLiteLiveSpendRead` | func |
| `flowersec.NewServiceRegistry` | func |
| `flowersec.NewSessionPlan` | func |
| `flowersec.NewStreamHandlerPlan` | func |
| `flowersec.NewUnaryRegistration` | func |
| `flowersec.NewVerificationNamespaces` | func |
| `flowersec.NotificationSubscription` | type |
| `flowersec.OpenSQLite` | func |
| `flowersec.OpenSQLiteTopUpJournal` | func |
| `flowersec.OperationAccepted` | const |
| `flowersec.OperationCompleted` | const |
| `flowersec.OperationExecuting` | const |
| `flowersec.OperationFailed` | const |
| `flowersec.OperationHandle` | type |
| `flowersec.OperationManagementResult` | type |
| `flowersec.OperationObservation` | type |
| `flowersec.OperationPending` | const |
| `flowersec.OperationProgress` | type |
| `flowersec.OperationReference` | type |
| `flowersec.OperationReference.GoString` | method |
| `flowersec.OperationReference.MarshalJSON` | method |
| `flowersec.OperationReference.String` | method |
| `flowersec.OperationReference.Valid` | method |
| `flowersec.OperationStartResult` | type |
| `flowersec.OperationStatus` | type |
| `flowersec.OperationUnknown` | const |
| `flowersec.PrepareOperation` | func |
| `flowersec.PublicationCause` | type |
| `flowersec.PublicationFlushed` | const |
| `flowersec.PublicationNotApplicable` | const |
| `flowersec.PublicationPending` | const |
| `flowersec.PublicationStatus` | type |
| `flowersec.PublicationUnknown` | const |
| `flowersec.ReadCause` | type |
| `flowersec.ReadMethodError` | type |
| `flowersec.ReadMethodFailure` | type |
| `flowersec.ReadProgress` | type |
| `flowersec.ReadResult` | type |
| `flowersec.ReaderCursor` | type |
| `flowersec.ReaderCursorOptions` | type |
| `flowersec.ReaderCursorSnapshot` | type |
| `flowersec.ResponsePublication` | type |
| `flowersec.ResponsePublicationState` | type |
| `flowersec.RestoreNamespace` | func |
| `flowersec.Result` | type |
| `flowersec.ServeHandle` | type |
| `flowersec.Stream` | type |
| `flowersec.Stream.AsTypedMessages` | interface_method |
| `flowersec.Stream.Close` | interface_method |
| `flowersec.Stream.CloseResult` | interface_method |
| `flowersec.Stream.CloseWrite` | interface_method |
| `flowersec.Stream.Copy` | interface_method |
| `flowersec.Stream.Finish` | interface_method |
| `flowersec.Stream.PrepareWrite` | interface_method |
| `flowersec.Stream.Read` | interface_method |
| `flowersec.Stream.ReaderCursor` | interface_method |
| `flowersec.Stream.Reset` | interface_method |
| `flowersec.Stream.Write` | interface_method |
| `flowersec.Stream.WriteAll` | interface_method |
| `flowersec.StreamAborted` | const |
| `flowersec.StreamEOF` | const |
| `flowersec.StreamError` | const |
| `flowersec.StreamMetadata.Bytes` | method |
| `flowersec.StreamOpen` | const |
| `flowersec.StreamStatus` | type |
| `flowersec.TopUpErrorProjection` | func |
| `flowersec.TransportEnvironment` | type |
| `flowersec.TransportEnvironmentOptions` | type |
| `flowersec.TypedMessageStream` | type |
| `flowersec.UnexpectedEOF` | const |
| `flowersec.AdmissionOffer` | type |
| `flowersec.ApplicationBinding` | type |
| `flowersec.ApplicationExecutor` | type |
| `flowersec.ApplicationExecutorCharge` | func |
| `flowersec.ApplicationExecutorConfig` | type |
| `flowersec.ApplicationIdentity` | type |
| `flowersec.ApplicationIdentityBytesConfig` | type |
| `flowersec.ApplicationIdentityCharge` | func |
| `flowersec.ApplicationIdentityConfig` | type |
| `flowersec.ApplicationLease` | type |
| `flowersec.ArtifactLease` | type |
| `flowersec.ArtifactLeaseBytesConfig` | type |
| `flowersec.ArtifactLeaseCharge` | func |
| `flowersec.ArtifactLeaseConfig` | type |
| `flowersec.ConnectionMaterial` | type |
| `flowersec.AuthenticatedRequestContext` | type |
| `flowersec.AuthorizationAuthorized` | const |
| `flowersec.AuthorizationDenied` | const |
| `flowersec.AuthorizationOutcome` | type |
| `flowersec.AuthorizationUnknown` | const |
| `flowersec.AuthorizeApplicationResult` | type |
| `flowersec.AutomaticLivenessPolicy` | type |
| `flowersec.CarrierAttemptBudget` | type |
| `flowersec.CarrierPreparationRequest` | type |
| `flowersec.ClientToServer` | const |
| `flowersec.Clock` | type |
| `flowersec.ClockMark` | type |
| `flowersec.ClockProfile` | type |
| `flowersec.ClockRate` | type |
| `flowersec.ClockTick` | type |
| `flowersec.ConnectOptions` | type |
| `flowersec.ConnectionGuarantees` | type |
| `flowersec.ConnectionMaterialCharge` | func |
| `flowersec.Connections` | const |
| `flowersec.ConsumerCarrierFactory` | type |
| `flowersec.ContractQueryMethod` | type |
| `flowersec.ContractRoutesConfig` | type |
| `flowersec.CredentialPolicy` | type |
| `flowersec.CredentialScope` | type |
| `flowersec.CredentialSubscriptionsCharge` | func |
| `flowersec.CredentialValidation` | type |
| `flowersec.Deadline` | type |
| `flowersec.DecodeContext` | type |
| `flowersec.Direction` | type |
| `flowersec.DirectionAccount` | const |
| `flowersec.DiskBytes` | const |
| `flowersec.DrainDeadlineAborted` | const |
| `flowersec.DrainFailed` | const |
| `flowersec.DrainOutcome` | type |
| `flowersec.DrainPending` | const |
| `flowersec.DrainResult` | type |
| `flowersec.Drained` | const |
| `flowersec.DurableRestore` | const |
| `flowersec.EngineResourceOptions` | type |
| `flowersec.EnvironmentAccount` | const |
| `flowersec.EnvironmentCharge` | func |
| `flowersec.EnvironmentConfig` | type |
| `flowersec.EnvironmentSnapshot` | type |
| `flowersec.EstablishmentCharge` | func |
| `flowersec.EstablishmentLimits` | type |
| `flowersec.FeatureEnvelope` | type |
| `flowersec.HTTPSBootstrapCharge` | func |
| `flowersec.HTTPSBootstrapConfig` | type |
| `flowersec.HelloLimits` | type |
| `flowersec.HelloPolicy` | type |
| `flowersec.IdentitySigner` | type |
| `flowersec.InitialConfig` | type |
| `flowersec.InitialHello` | type |
| `flowersec.InitialLimits` | type |
| `flowersec.InitialMessages` | type |
| `flowersec.IssuerPermission` | type |
| `flowersec.Items` | const |
| `flowersec.LiveActivationFields` | type |
| `flowersec.LiveMaintenanceConfig` | type |
| `flowersec.LiveMaintenanceStatus` | type |
| `flowersec.LiveNamespace` | type |
| `flowersec.LiveProofVerification` | type |
| `flowersec.LiveSessionInput` | type |
| `flowersec.LiveSpendOwner` | type |
| `flowersec.LiveSpendReadAccess` | type |
| `flowersec.LiveSpendReadTarget` | type |
| `flowersec.LiveSpendRetirement` | type |
| `flowersec.LiveSpendRetirementPolicy` | type |
| `flowersec.LivenessResult` | type |
| `flowersec.MaintenanceIngressPolicy` | type |
| `flowersec.MaintenanceMessagePolicy` | type |
| `flowersec.MaintenanceReserve` | type |
| `flowersec.MapSigner` | type |
| `flowersec.MaterialAcquisitionCharge` | func |
| `flowersec.MaterialConnectConfig` | type |
| `flowersec.MaterialGeneration` | type |
| `flowersec.ConnectionMaterialSource` | type |
| `flowersec.MaterialLeaseRequest` | type |
| `flowersec.MaterialPool` | type |
| `flowersec.MaterialPoolCharge` | func |
| `flowersec.MaterialPoolConfig` | type |
| `flowersec.MaterialRequirements` | type |
| `flowersec.MethodRoutes` | type |
| `flowersec.NamespaceAllocation` | type |
| `flowersec.NamespaceBootstrapCharge` | func |
| `flowersec.NamespaceBootstrapLimits` | type |
| `flowersec.NamespaceBootstrapProvider` | type |
| `flowersec.NamespaceBootstrapRequest` | type |
| `flowersec.NamespaceContent` | type |
| `flowersec.NamespaceContinuityLimits` | type |
| `flowersec.NamespaceContinuityScope` | type |
| `flowersec.NamespaceContinuityStore` | type |
| `flowersec.NamespaceContinuityVersion` | type |
| `flowersec.NamespaceDurabilityCharge` | func |
| `flowersec.NamespaceDurabilityConfig` | type |
| `flowersec.NamespaceOnlineBootstrap` | type |
| `flowersec.NamespaceRules` | type |
| `flowersec.NamespaceTrustCharge` | func |
| `flowersec.NamespaceTrustLimits` | type |
| `flowersec.NamespaceTrustRoot` | type |
| `flowersec.NamespaceTrustStore` | type |
| `flowersec.NativeHandles` | const |
| `flowersec.OnlineBootstrap` | const |
| `flowersec.OpenLimits` | type |
| `flowersec.OperationOptions` | type |
| `flowersec.PoolAccount` | const |
| `flowersec.PoolControlResultDecoder` | type |
| `flowersec.PoolHTTPSConfig` | type |
| `flowersec.PoolHTTPSTransport` | type |
| `flowersec.PoolHTTPSTransportCharge` | func |
| `flowersec.PoolIdentityRestorer` | type |
| `flowersec.PoolLeaseDecoder` | type |
| `flowersec.PoolMaterialBundle` | type |
| `flowersec.PoolMaterialDecoder` | type |
| `flowersec.PoolMaterialDecoderCharge` | func |
| `flowersec.PoolMaterialDecoderConfig` | type |
| `flowersec.PoolResultDecoder` | type |
| `flowersec.PoolResultDecoderCharge` | func |
| `flowersec.PoolResultDecoderConfig` | type |
| `flowersec.PoolSessionInput` | type |
| `flowersec.PoolSourceCharge` | func |
| `flowersec.PoolSourceConfig` | type |
| `flowersec.PoolSpendFacts` | type |
| `flowersec.PreauthorizedPoolSource` | type |
| `flowersec.PreparedCarrier` | type |
| `flowersec.PreparedCarrierCharge` | func |
| `flowersec.PreparedCarrierConfig` | type |
| `flowersec.PreparedTunnelServerAllowProvider` | type |
| `flowersec.ProviderBytes` | const |
| `flowersec.QueryBinding` | type |
| `flowersec.RPCServicesConfig` | type |
| `flowersec.RPCServicesRequirements` | func |
| `flowersec.RawStreamHandlerConfig` | type |
| `flowersec.RekeyPhaseBudgets` | type |
| `flowersec.RequiredGuarantees` | type |
| `flowersec.ResourceAccount` | type |
| `flowersec.ResourceAccountKey` | type |
| `flowersec.ResourceAccountKind` | type |
| `flowersec.ResourceConfig` | type |
| `flowersec.ResourceOwnerKey` | type |
| `flowersec.ResourceReference` | type |
| `flowersec.ResourceRequest` | type |
| `flowersec.ResourceRoot` | type |
| `flowersec.ResourceVector` | type |
| `flowersec.SDKBytes` | const |
| `flowersec.SQLiteBacking` | type |
| `flowersec.SQLiteBackingCharge` | func |
| `flowersec.SQLiteContinuity` | type |
| `flowersec.SQLiteIdentity` | type |
| `flowersec.SQLiteLimits` | type |
| `flowersec.SQLiteLiveAuthority` | type |
| `flowersec.SQLiteLiveMaintenance` | type |
| `flowersec.SQLiteLiveMaintenanceCharge` | func |
| `flowersec.SQLiteLiveSpendCharges` | func |
| `flowersec.SQLiteLiveSpendRead` | type |
| `flowersec.SQLiteLiveSpendReadCharge` | func |
| `flowersec.SQLitePoolAuthority` | type |
| `flowersec.SQLitePoolSpendCharge` | func |
| `flowersec.SQLiteStore` | type |
| `flowersec.SQLiteStoreCharge` | func |
| `flowersec.SQLiteTopUpAuthority` | type |
| `flowersec.SQLiteTopUpConfig` | type |
| `flowersec.SQLiteTopUpJournal` | type |
| `flowersec.SQLiteTopUpJournalCharge` | func |
| `flowersec.ServeConfig` | type |
| `flowersec.ServeGroup` | type |
| `flowersec.ServerToClient` | const |
| `flowersec.ServiceBinding` | type |
| `flowersec.ServiceClient` | type |
| `flowersec.ServiceRegistry` | type |
| `flowersec.ServiceRegistryCharge` | func |
| `flowersec.ServiceRegistryConfig` | type |
| `flowersec.Session` | type |
| `flowersec.SessionAccount` | const |
| `flowersec.SessionAdmissionConfig` | type |
| `flowersec.SessionAdmissionRequirements` | func |
| `flowersec.SessionCoreConfig` | type |
| `flowersec.SessionInfo` | type |
| `flowersec.SessionPlan` | type |
| `flowersec.SessionPlanCharge` | func |
| `flowersec.SessionPlanConfig` | type |
| `flowersec.SessionPlanFactory` | type |
| `flowersec.SessionPlanFactory.Create` | method |
| `flowersec.SessionRekeyInProgress` | const |
| `flowersec.SessionResourceScope` | type |
| `flowersec.SessionStreamConfig` | type |
| `flowersec.SessionStreamHandlerConfig` | type |
| `flowersec.SessionTimeUnavailable` | const |
| `flowersec.Sessions` | const |
| `flowersec.SharedDiscardPolicy` | type |
| `flowersec.SignedMap` | type |
| `flowersec.SignedMapCodec` | type |
| `flowersec.SourceConnectConfig` | type |
| `flowersec.SourceLiveIssuance` | type |
| `flowersec.SourcePreparationCharge` | func |
| `flowersec.PoolSpendObservation` | type |
| `(*flowersec.PoolSpendObservation).Snapshot` | method |
| `flowersec.PoolSpendStatus` | type |
| `flowersec.SpendConsumed` | const |
| `flowersec.SpendReceipt` | type |
| `flowersec.SpendSpending` | const |
| `flowersec.SpendState` | type |
| `flowersec.StaticDH` | type |
| `flowersec.StorageFormatBackend` | const |
| `flowersec.StorageFormatError` | type |
| `flowersec.StorageFormatIdentity` | const |
| `flowersec.StorageFormatManifest` | const |
| `flowersec.StorageFormatNewer` | const |
| `flowersec.StorageFormatOlder` | const |
| `flowersec.StorageFormatProjection` | type |
| `flowersec.StorageFormatReason` | type |
| `flowersec.StorageFormatRevisionConflict` | const |
| `flowersec.StorageFormatState` | const |
| `flowersec.StorageRevision` | type |
| `flowersec.StreamHandlerPlan` | type |
| `flowersec.StreamHandlerPlanCharge` | func |
| `flowersec.StreamHandlerPlanConfig` | type |
| `flowersec.StreamOwnership` | type |
| `flowersec.StreamTerminationPolicy` | type |
| `flowersec.TLSHandshakes` | const |
| `flowersec.Tasks` | const |
| `flowersec.TenantAccount` | const |
| `flowersec.TimeInterval` | type |
| `flowersec.Timers` | const |
| `flowersec.TopUpAccess` | type |
| `flowersec.TopUpAcked` | const |
| `flowersec.TopUpControlTransport` | type |
| `flowersec.TopUpEntryFacts` | type |
| `flowersec.TopUpError` | type |
| `flowersec.TopUpErrorCode` | type |
| `flowersec.TopUpErrorCodeCapacityExhausted` | const |
| `flowersec.TopUpErrorCodeConfigurationCapacity` | const |
| `flowersec.TopUpErrorCodeFutureGeneration` | const |
| `flowersec.TopUpErrorCodeFutureOperation` | const |
| `flowersec.TopUpErrorCodeOperationConflict` | const |
| `flowersec.TopUpErrorCodePermissionDenied` | const |
| `flowersec.TopUpErrorCodeRelinkRequired` | const |
| `flowersec.TopUpErrorCodeSequenceGap` | const |
| `flowersec.TopUpErrorCodeSourceContractInvalid` | const |
| `flowersec.TopUpErrorCodeSourceExhausted` | const |
| `flowersec.TopUpErrorCodeSourceResetRequired` | const |
| `flowersec.TopUpErrorCodeSourceStateUnknown` | const |
| `flowersec.TopUpErrorCodeSourceUnavailable` | const |
| `flowersec.TopUpErrorCodeSpentUnknown` | const |
| `flowersec.TopUpErrorCodeStaleGeneration` | const |
| `flowersec.TopUpErrorCodeStaleOperation` | const |
| `flowersec.TopUpErrorCodeTopUpRequestExpired` | const |
| `flowersec.TopUpErrorScope` | type |
| `flowersec.TopUpErrorScopeOperation` | const |
| `flowersec.TopUpErrorScopeRequest` | const |
| `flowersec.TopUpErrorScopeSource` | const |
| `flowersec.TopUpExchangeResult` | type |
| `flowersec.TopUpFailure` | type |
| `flowersec.TopUpFenceAuthority` | type |
| `flowersec.TopUpFenceProvider` | type |
| `flowersec.TopUpHandle` | type |
| `flowersec.TopUpIdentityProvider` | type |
| `flowersec.TopUpInstalled` | const |
| `flowersec.TopUpOptions` | type |
| `flowersec.TopUpPending` | const |
| `flowersec.TopUpPermanentFenceEvidence` | type |
| `flowersec.TopUpPermanentFenceReceipt` | type |
| `flowersec.TopUpRecoveryResult` | type |
| `flowersec.TopUpRequestFacts` | type |
| `flowersec.TopUpResponseFacts` | type |
| `flowersec.TopUpResult` | type |
| `flowersec.TopUpServerSnapshot` | type |
| `flowersec.TopUpState` | type |
| `flowersec.TopUpTerminal` | const |
| `flowersec.TopUpTerminalEvidence` | type |
| `flowersec.TopUpWireResult` | type |
| `flowersec.TopUpWireResultCapacityExhausted` | const |
| `flowersec.TopUpWireResultConfigurationCapacity` | const |
| `flowersec.TopUpWireResultFutureGeneration` | const |
| `flowersec.TopUpWireResultFutureOperation` | const |
| `flowersec.TopUpWireResultOperationConflict` | const |
| `flowersec.TopUpWireResultPermissionDenied` | const |
| `flowersec.TopUpWireResultRelinkRequired` | const |
| `flowersec.TopUpWireResultReplay` | const |
| `flowersec.TopUpWireResultSequenceGap` | const |
| `flowersec.TopUpWireResultSourceContractInvalid` | const |
| `flowersec.TopUpWireResultSourceExhausted` | const |
| `flowersec.TopUpWireResultSourceResetRequired` | const |
| `flowersec.TopUpWireResultSourceStateUnknown` | const |
| `flowersec.TopUpWireResultSourceUnavailable` | const |
| `flowersec.TopUpWireResultSpentUnknown` | const |
| `flowersec.TopUpWireResultStaleGeneration` | const |
| `flowersec.TopUpWireResultStaleOperation` | const |
| `flowersec.TopUpWireResultSuccess` | const |
| `flowersec.TopUpWireResultTopUpRequestExpired` | const |
| `flowersec.TopUpWriteAction` | type |
| `flowersec.TopUpWriteActionNone` | const |
| `flowersec.TopUpWriteActionTerminal` | const |
| `flowersec.UnaryCodec` | type |
| `flowersec.UnaryMethod` | type |
| `flowersec.UnaryRegistration` | type |
| `flowersec.UnaryRequest` | type |
| `flowersec.UnaryRequest.MaintenanceOwner` | method |
| `flowersec.UnaryRequest.ResponsePublication` | method |
| `flowersec.UnaryResponse` | type |
| `flowersec.UnaryResultDecoder` | type |
| `flowersec.VerificationContinuity` | type |
| `flowersec.VerificationNamespaces` | type |
| `flowersec.VerificationNamespacesCharge` | func |
| `flowersec.VerificationNamespacesConfig` | type |
| `flowersec.WorkClass` | type |
| `flowersec.WorkResident` | const |
| `flowersec.WorkShort` | const |
| `flowersec.WorkSlots` | const |
| `flowersec.WriteOperation` | type |
| `flowersec.WriteOptions` | type |
| `flowersec.WritePhase` | type |
| `flowersec.WritePrepared` | const |
| `flowersec.WriteProgress` | type |
| `flowersec.WriteRunning` | const |
| `flowersec.WriteTerminal` | const |

`(*flowersec.Session).CleanupStatus` projects the original Session cleanup
observation. `flowersec.ErrCleanupIncomplete` means the fixed cleanup observation
deadline elapsed while physical work remains owned and charged; later observations
can report actual completion. Canceling one wait does not close or restart cleanup.

## Go owners and control adapters

These entries expose bounded original owners, connection assembly, authenticated
control transports, issuance authorities and read-only authorization facts. Each
capability retains its own admission and lifecycle gates. A receipt or reconciled
fact never grants callback dispatch or connection activation. See
[Go transport assembly](GO_TRANSPORT_V4.md) for construction and cleanup.

| Symbol | Declaration |
| --- | --- |
| `(*flowersec.LiveAuthoritySource).AcquireLease` | method |
| `(*flowersec.LiveAuthoritySource).Close` | method |
| `(*flowersec.LiveAuthoritySource).GoString` | method |
| `(*flowersec.LiveAuthoritySource).MarshalJSON` | method |
| `(*flowersec.LiveAuthoritySource).PreparationNamespaceSet` | method |
| `(*flowersec.LiveAuthoritySource).String` | method |
| `(*flowersec.LiveAuthoritySource).WaitCleanup` | method |
| `(*flowersec.MaterialAcquisition).Acquire` | method |
| `(*flowersec.MaterialAcquisition).Close` | method |
| `(*flowersec.MaterialAcquisition).WaitCleanup` | method |
| `(*flowersec.Session).AcceptStream` | method |
| `(*flowersec.StreamingResponse).SaveContent` | method |
| `flowersec.NewStreamMetadataFromBytes` | func |
| `flowersec.NewArtifactIssueSource` | func |
| `flowersec.NewCarrierSet` | func |
| `flowersec.NewLiveAuthorityMaterialAcquisition` | func |
| `flowersec.NewLiveAuthoritySource` | func |
| `flowersec.NewMaintenanceOwner` | func |
| `flowersec.NewMaterialAcquisition` | func |
| `flowersec.NewPreauthorizedPoolMaterialAcquisition` | func |
| `flowersec.NewPreparedRelayMessages` | func |
| `flowersec.NewPreparedRelayStream` | func |
| `flowersec.NewRelayHop` | func |
| `flowersec.NewRelayMessagePair` | func |
| `flowersec.NewRelayPair` | func |
| `flowersec.NewRelayParentProjection` | func |
| `flowersec.NewSQLiteRelayAuthorityTable` | func |
| `flowersec.NewSQLiteRelayAuthorityTableContext` | func |
| `flowersec.NewTunnelAcceptedEntrance` | func |
| `flowersec.NewTunnelServerAllowHTTPSService` | func |
| `flowersec.NewTunnelServerAllowHTTPSTransport` | func |
| `flowersec.NewTunnelServerAllowRecipient` | func |
| `flowersec.NewTunnelServerAllowRegistration` | func |
| `flowersec.AcceptedEntrance` | type |
| `flowersec.ActivationAuthority` | type |
| `flowersec.ActivationTrustBinding` | type |
| `flowersec.ArtifactIssueSource` | type |
| `flowersec.ArtifactIssueSourceCharge` | func |
| `flowersec.ArtifactIssueSourceConfig` | type |
| `flowersec.ArtifactIssueSourceTunnel` | type |
| `flowersec.ArtifactLeaseTunnel` | type |
| `flowersec.ArtifactLeaseTunnelBytes` | type |
| `flowersec.CarrierEndpoint` | type |
| `flowersec.CarrierSet` | type |
| `flowersec.CarrierSetCharge` | func |
| `flowersec.CarrierSetConfig` | type |
| `flowersec.ContentObservation` | type |
| `flowersec.AcceptedStream` | type |
| `flowersec.IncomingStream` | type |
| `flowersec.LiveAuthoritySource` | type |
| `flowersec.LiveGrantPreparation` | type |
| `flowersec.LiveServerAllowConfig` | type |
| `flowersec.LiveTunnelAuthorizationProvider` | type |
| `flowersec.MaintenanceOwnerCharge` | func |
| `flowersec.MaterialAcquisition` | type |
| `flowersec.MaterialNamespaceProvider` | type |
| `flowersec.MaterialNamespaceSet` | type |
| `flowersec.MaterialNamespaceSetProvider` | type |
| `flowersec.PoolTunnelMaterial` | type |
| `flowersec.PoolTunnelTrust` | type |
| `flowersec.RawStreamMetadataContract` | type |
| `flowersec.RawStreamMetadataField` | type |
| `flowersec.RawStreamMetadataType` | type |
| `flowersec.RelayClaimFacts` | type |
| `flowersec.RelayClaimFields` | type |
| `flowersec.RelayDeploymentBinding` | type |
| `flowersec.RelayGrantIssuer` | type |
| `flowersec.RelayGrantLimits` | type |
| `flowersec.RelayHop` | type |
| `flowersec.RelayHopCharges` | func |
| `flowersec.RelayHopConfig` | type |
| `flowersec.RelayHopReservations` | type |
| `flowersec.RelayIssuerMapping` | type |
| `flowersec.RelayMessagePair` | type |
| `flowersec.RelayMessagePairCharge` | func |
| `flowersec.RelayMessagePairConfig` | type |
| `flowersec.RelayPair` | type |
| `flowersec.RelayPairCharge` | func |
| `flowersec.RelayPairConfig` | type |
| `flowersec.RelayParentKey` | type |
| `flowersec.RelayParentProjection` | type |
| `flowersec.RelayParentProjectionBackingBytes` | func |
| `flowersec.RelayParentSelection` | type |
| `flowersec.SQLiteCommittedRelayLeg` | type |
| `flowersec.SQLiteCommittedRelayLegCharge` | func |
| `flowersec.SQLiteLiveRelayPublicationCharge` | func |
| `flowersec.SQLiteLiveRelayPublicationConfig` | type |
| `flowersec.SQLiteRelayAuthority` | type |
| `flowersec.SQLiteRelayAuthorityCharge` | func |
| `flowersec.SQLiteRelayAuthorityConfig` | type |
| `flowersec.SQLiteRelayAuthorityTable` | type |
| `flowersec.SQLiteRelayParentRegistration` | type |
| `flowersec.SourceCarrierCharge` | func |
| `flowersec.TunnelAcceptedEntranceRequirements` | func |
| `flowersec.TunnelServerAllowConfig` | type |
| `flowersec.TunnelServerAllowEndpoint` | type |
| `flowersec.TunnelServerAllowHTTPSConfig` | type |
| `flowersec.TunnelServerAllowHTTPSService` | type |
| `flowersec.TunnelServerAllowHTTPSServiceCharge` | func |
| `flowersec.TunnelServerAllowHTTPSServiceConfig` | type |
| `flowersec.TunnelServerAllowHTTPSTransport` | type |
| `flowersec.TunnelServerAllowHTTPSTransportCharge` | func |
| `flowersec.TunnelServerAllowPrepared` | type |
| `flowersec.TunnelServerAllowProvider` | type |
| `flowersec.TunnelServerAllowPublication` | type |
| `flowersec.TunnelServerAllowRecipient` | type |
| `flowersec.TunnelServerAllowRecipientCharge` | func |
| `flowersec.TunnelServerAllowRegistration` | type |
| `flowersec.TunnelServerAllowRegistrationCharges` | func |
| `flowersec.TunnelServerAllowRegistrationConfig` | type |
| `flowersec.TunnelServerAllowRequest` | type |
| `(*controlplane.ArtifactIssuer).Close` | method |
| `(*controlplane.ArtifactIssuer).GoString` | method |
| `(*controlplane.ArtifactIssuer).IssueArtifactBytes` | method |
| `(*controlplane.ArtifactIssuer).NamespaceClosure` | method |
| `(*controlplane.ArtifactIssuer).String` | method |
| `(*controlplane.ArtifactIssuer).WaitCleanup` | method |
| `(*controlplane.LiveRelayRegistrationService).CaptureRelayLeg` | method |
| `(*controlplane.LiveRelayRegistrationService).Close` | method |
| `(*controlplane.LiveRelayRegistrationService).WaitCleanup` | method |
| `controlplane.CreateSQLiteTopUpServer` | func |
| `controlplane.DeriveLiveGrantPreparation` | func |
| `controlplane.NewArtifactIssueHTTPSService` | func |
| `controlplane.NewArtifactIssuer` | func |
| `controlplane.NewLiveActivationPlan` | func |
| `controlplane.NewLiveArtifactHost` | func |
| `controlplane.NewLiveRelayRegistrationService` | func |
| `controlplane.NewPoolActivationPlan` | func |
| `controlplane.NewPoolBatchSigningIssuer` | func |
| `controlplane.NewPoolRelayFactory` | func |
| `controlplane.NewPoolService` | func |
| `controlplane.NewSQLiteLiveRelayPublication` | func |
| `controlplane.NewSQLitePoolRelayPublication` | func |
| `controlplane.NewTopUpCodec` | func |
| `controlplane.NewTunnelServerAllowHTTPSService` | func |
| `controlplane.OpenSQLiteTopUpServer` | func |
| `controlplane.ArtifactIssueAuthority` | type |
| `controlplane.ArtifactIssueFacts` | type |
| `controlplane.ArtifactIssueHTTPSConfig` | type |
| `controlplane.ArtifactIssueHTTPSService` | type |
| `controlplane.ArtifactIssueHTTPSServiceCharge` | func |
| `controlplane.ArtifactIssuePermit` | type |
| `controlplane.ArtifactIssueRequest` | type |
| `controlplane.ArtifactIssueRetention` | type |
| `controlplane.ArtifactIssuer` | type |
| `controlplane.ArtifactIssuerCharge` | func |
| `controlplane.ArtifactIssuerConfig` | type |
| `controlplane.ArtifactRetentionSlot` | type |
| `controlplane.ArtifactTunnelIssueConfig` | type |
| `controlplane.ArtifactTunnelLegIssueConfig` | type |
| `controlplane.AuthenticatedArtifactIssueClient` | func |
| `controlplane.LiveActivationConfig` | type |
| `controlplane.LiveActivationPlan` | type |
| `controlplane.LiveActivationPlanCharge` | func |
| `controlplane.LiveArtifactGrantConfig` | type |
| `controlplane.LiveArtifactHost` | type |
| `controlplane.LiveArtifactHostCharges` | func |
| `controlplane.LiveArtifactHostConfig` | type |
| `controlplane.LiveArtifactPolicy` | type |
| `controlplane.LiveArtifactServerMaterial` | type |
| `controlplane.LiveArtifactServerRegistration` | type |
| `controlplane.LiveArtifactServerResolver` | type |
| `controlplane.LiveArtifactTunnelConfig` | type |
| `controlplane.LiveGrantIssuance` | type |
| `controlplane.LiveGrantPreparationConfig` | type |
| `controlplane.LiveGrantProjection` | type |
| `controlplane.LiveRelayReadAccess` | type |
| `controlplane.LiveRelayRegistrationService` | type |
| `controlplane.LiveRelayRegistrationServiceCharges` | func |
| `controlplane.LiveServerAllowConfig` | type |
| `controlplane.LiveTunnelActivationConfig` | type |
| `controlplane.PoolActivationConfig` | type |
| `controlplane.PoolActivationPlan` | type |
| `controlplane.PoolActivationPlanCapacity` | func |
| `controlplane.PoolActivationPlanCharge` | func |
| `controlplane.PoolAttemptLimits` | type |
| `controlplane.PoolBatchIssuer` | type |
| `controlplane.PoolBatchSigningConfig` | type |
| `controlplane.PoolBatchSigningIssuer` | type |
| `controlplane.PoolBatchSigningIssuerCharge` | func |
| `controlplane.PoolIssuancePolicy` | type |
| `controlplane.PoolIssueResult` | type |
| `controlplane.PoolRelayFactory` | type |
| `controlplane.PoolRelayFactoryCharge` | func |
| `controlplane.PoolRelayFactoryConfig` | type |
| `controlplane.PoolRelayPublicationFactory` | type |
| `controlplane.PoolRelayRouteConfig` | type |
| `controlplane.PoolService` | type |
| `controlplane.PoolServiceCharge` | func |
| `controlplane.PoolServiceConfig` | type |
| `controlplane.PoolTunnelIssueConfig` | type |
| `controlplane.SQLiteLiveRelayPublication` | type |
| `controlplane.SQLiteLiveRelayPublicationCharge` | func |
| `controlplane.SQLiteLiveRelayPublicationConfig` | type |
| `controlplane.SQLitePoolRelayParent` | type |
| `controlplane.SQLitePoolRelayPublication` | type |
| `controlplane.SQLitePoolRelayPublicationCharge` | func |
| `controlplane.SQLitePoolRelayPublicationConfig` | type |
| `controlplane.SQLiteTopUpCommit` | type |
| `controlplane.SQLiteTopUpServer` | type |
| `controlplane.SQLiteTopUpServerAuthority` | type |
| `controlplane.SQLiteTopUpServerCharge` | func |
| `controlplane.SQLiteTopUpServerConfig` | type |
| `controlplane.TopUpAccess` | type |
| `controlplane.TopUpBatch` | type |
| `controlplane.TopUpCodec` | type |
| `controlplane.TopUpCodecBackingBytes` | func |
| `controlplane.TopUpIssueEntry` | type |
| `controlplane.TopUpRequestFacts` | type |
| `controlplane.TopUpServerCommitted` | const |
| `controlplane.TopUpServerEmpty` | const |
| `controlplane.TopUpServerPending` | const |
| `controlplane.TopUpServerRetired` | const |
| `controlplane.TopUpServerSnapshot` | type |
| `controlplane.TopUpServerTerminal` | const |
| `controlplane.TopUpSourceFence` | type |
| `controlplane.TunnelServerAllowHTTPSService` | type |
| `controlplane.TunnelServerAllowHTTPSServiceCharge` | func |
| `controlplane.TunnelServerAllowHTTPSServiceConfig` | type |
| `(*controlplane.SpendReceiptService).Close` | method |
| `(*controlplane.SpendReceiptService).QuerySpendReceiptBytes` | method |
| `(*controlplane.SpendReceiptService).QuerySpendReceipt` | method |
| `(*controlplane.SpendReceiptService).WaitCleanup` | method |
| `(*controlplane.DirectIssuer).Close` | method |
| `(*controlplane.DirectIssuer).GoString` | method |
| `(*controlplane.DirectIssuer).IssueArtifactBytes` | method |
| `(*controlplane.DirectIssuer).String` | method |
| `(*controlplane.DirectIssuer).WaitCleanup` | method |
| `(*flowersec.SQLiteLiveSpendRead).Cleanup` | method |
| `(*flowersec.SQLiteLiveSpendRead).Close` | method |
| `(*flowersec.SQLiteLiveSpendRead).Receipt` | method |
| `(*flowersec.SQLiteLiveSpendRead).ReconcileAuthorization` | method |
| `(*flowersec.SQLiteLiveSpendRead).RecoverExpired` | method |
| `controlplane.EncodeLiveAuthorizationRequest` | func |
| `controlplane.NewSpendReceiptService` | func |
| `controlplane.NewDirectIssueHTTPSService` | func |
| `controlplane.NewDirectIssuer` | func |
| `controlplane.NewLiveAuthorizationCodec` | func |
| `controlplane.NewLiveAuthorizationHTTPSService` | func |
| `controlplane.NewSQLiteDirectIssueAuthority` | func |
| `controlplane.SpendQueryFailure` | type |
| `controlplane.SpendReceiptServiceCharges` | func |
| `controlplane.SpendReceiptServiceConfig` | type |
| `controlplane.SpendReceiptService` | type |
| `controlplane.SpendReceipt` | type |
| `controlplane.AuthenticatedDirectIssueClient` | func |
| `controlplane.DirectIssueAuthority` | type |
| `controlplane.DirectIssueCommitted` | const |
| `controlplane.DirectIssueFacts` | type |
| `controlplane.DirectIssueHTTPSConfig` | type |
| `controlplane.DirectIssueHTTPSServiceCharge` | func |
| `controlplane.DirectIssueHTTPSService` | type |
| `controlplane.DirectIssueObligationState` | type |
| `controlplane.DirectIssuePermit` | type |
| `controlplane.DirectIssuePolicyConfig` | type |
| `controlplane.DirectIssuePolicyLimits` | type |
| `controlplane.DirectIssueRequest` | type |
| `controlplane.DirectIssueReserved` | const |
| `controlplane.DirectIssueRetired` | const |
| `controlplane.DirectIssuerCharge` | func |
| `controlplane.DirectIssuerConfig` | type |
| `controlplane.DirectIssuer` | type |
| `controlplane.IssueFailure.Error` | method |
| `controlplane.IssueFailure` | type |
| `controlplane.LiveAuthorizationAccess` | type |
| `controlplane.LiveAuthorizationCodecBackingBytes` | func |
| `controlplane.LiveAuthorizationCodec` | type |
| `controlplane.LiveAuthorizationHTTPSConfig` | type |
| `controlplane.LiveAuthorizationHTTPSServiceCharges` | func |
| `controlplane.LiveAuthorizationHTTPSService` | type |
| `controlplane.LiveAuthorizationHost` | type |
| `controlplane.LiveAuthorizationMaterial` | type |
| `controlplane.LiveAuthorizationRequest` | type |
| `controlplane.SQLiteDirectIssueAccess` | type |
| `controlplane.SQLiteDirectIssueAuthority` | type |
| `controlplane.SQLiteDirectIssueCharge` | func |
| `controlplane.SQLiteDirectIssueConfig` | type |
| `controlplane.SQLiteDirectIssueHost` | type |
| `controlplane.SQLiteDirectIssuePublication` | type |
| `controlplane.SQLiteDirectIssueStatus` | type |
| `flowersec.NewDirectIssueSource` | func |
| `flowersec.NewLiveHTTPSTransport` | func |
| `flowersec.NewWebSocketCarrierFactory` | func |
| `flowersec.AuthorizationNotStarted` | const |
| `flowersec.DirectIssueSourceCharge` | func |
| `flowersec.DirectIssueSourceConfig` | type |
| `flowersec.DirectIssueSource` | type |
| `flowersec.LiveAuthorizationFact` | type |
| `flowersec.LiveAuthorizationProvider` | type |
| `flowersec.LiveAuthorizationQuery` | type |
| `flowersec.LiveAuthorizationRequest` | type |
| `flowersec.LiveControlCharge` | func |
| `flowersec.LiveControlConfig` | type |
| `flowersec.LiveHTTPSConfig` | type |
| `flowersec.LiveHTTPSTransportCharge` | func |
| `flowersec.LiveHTTPSTransport` | type |
| `flowersec.WebSocketCarrierFactoryCharge` | func |
| `flowersec.WebSocketCarrierFactory` | type |
| `flowersec.WebSocketFactoryConfig` | type |
| `flowersec.WebSocketProviderOptions` | type |
| `(*flowersec.ServeHandle).AcceptWebSocket` | method |
| `(*flowersec.TransportEnvironment).Serve` | method |
| `flowersec.NewWebSocketServer` | func |
| `flowersec.AcceptedEntranceConfig` | type |
| `flowersec.AcceptedMaterialSource` | type |
| `flowersec.AcceptedMaterialSource.ResolveAcceptedMaterial` | interface_method |
| `flowersec.AcceptedSessionInput` | type |
| `flowersec.AcceptedWebSocketEndpoint` | type |
| `flowersec.AdmissionOwner` | type |
| `flowersec.SQLiteAdmissionAuthority` | type |
| `flowersec.ServeCharge` | func |
| `flowersec.ServeOptions` | type |
| `flowersec.WebSocketAcceptOptions` | type |
| `flowersec.WebSocketServer` | type |
| `flowersec.WebSocketServerCharge` | func |
| `flowersec.WebSocketServerConfig` | type |
| `flowersec.WebSocketUpgradeConfig` | type |
| `flowersec.QUICLimits` | type |
| `flowersec.QUICProviderOptions` | type |
| `flowersec.QUICFactoryConfig` | type |
| `flowersec.QUICCarrierFactory` | type |
| `flowersec.DefaultQUICLimits` | func |
| `flowersec.QUICCarrierFactoryCharge` | func |
| `flowersec.NewQUICCarrierFactory` | func |
| `(*flowersec.QUICCarrierFactory).PrepareCarrier` | method |
| `(*flowersec.QUICCarrierFactory).Close` | method |
| `(*flowersec.QUICCarrierFactory).WaitCleanup` | method |
| `flowersec.QUICServerConfig` | type |
| `flowersec.QUICServer` | type |
| `flowersec.QUICIngress` | type |
| `flowersec.QUICServerCharge` | func |
| `flowersec.NewQUICServer` | func |
| `(*flowersec.QUICServer).Accept` | method |
| `(*flowersec.QUICServer).Address` | method |
| `(*flowersec.QUICServer).Close` | method |
| `(*flowersec.QUICServer).WaitCleanup` | method |
| `(*flowersec.QUICIngress).Close` | method |
| `(*flowersec.QUICIngress).WaitCleanup` | method |
| `flowersec.QUICAcceptOptions` | type |
| `(*flowersec.ServeHandle).AcceptQUIC` | method |

## Go Connection Controller

The TransportEnvironment owns the optional Controller's current, candidate and one
retirement position. Source recipes transfer unused cleanup responsibility;
complete candidate headroom precedes Acquire. Verification waits reuse the
original attempt and namespace refresh owner. Initializer failure after entry
fences publication until explicit recovery. First-header publication is ordered
with current switching, and accepted tails stay on their original Session.
Public failures are redacted; cancellation and deadline identities remain stable.
See [Go transport v4 assembly](GO_TRANSPORT_V4.md#connection-controller) for
construction, retirement, ownership and the implemented dependency boundary.

| Symbol | Declaration |
| --- | --- |
| `flowersec.ControllerSource` | type |
| `flowersec.ControllerRequest` | type |
| `flowersec.ControllerPreparation` | type |
| `flowersec.ControllerRetirement` | type |
| `flowersec.ControllerReplaceOptions` | type |
| `flowersec.ControllerSourceError` | type |
| `flowersec.ControllerOptions` | type |
| `flowersec.ControllerReplaceResult` | type |
| `flowersec.ControllerSnapshot` | type |
| `(*flowersec.ConnectionController).ConnectionDiagnostic` | method |
| `(*flowersec.ConnectionController).LocalReport` | method |
| `flowersec.ConnectionController` | type |
| `flowersec.NewControllerSourceError` | func |
| `flowersec.ControllerCharges` | func |
| `flowersec.ControllerDrain` | const |
| `flowersec.ControllerRetain` | const |
| `flowersec.ErrControllerBusy` | var |
| `flowersec.ErrControllerInitialization` | var |
| `flowersec.ErrRetirementCapacity` | var |
| `(*flowersec.TransportEnvironment).NewConnectionController` | method |
| `(*flowersec.ConnectionController).Start` | method |
| `(*flowersec.ConnectionController).RetryNow` | method |
| `(*flowersec.ConnectionController).PrepareUnary` | method |
| `(*flowersec.ConnectionController).Dispatch` | method |
| `(*flowersec.ConnectionController).CaptureSession` | method |
| `(*flowersec.ConnectionController).WaitForSession` | method |
| `(*flowersec.ConnectionController).ReplaceSession` | method |
| `(*flowersec.ConnectionController).Snapshot` | method |
| `(*flowersec.ConnectionController).Close` | method |
| `(*flowersec.ConnectionController).WaitCleanup` | method |
| `(*flowersec.ConnectionController).CleanupStatus` | method |
| `flowersec.ControllerSource.PrepareConnection` | interface_method |

## TypeScript v4 owners and result registry

`createNodeWSSListener(...)` configures the single-use production Node WSS
listener consumed by `environment.serve(...)`. `createHandlerPlan(...)` captures
raw stream declarations and encoded service contracts with typed handlers.
Serve fixes `authorizeRequest`, `resolveHandlers`, `authorizeApplication`,
`onSession`, and `release` for the original listener lifetime. Authenticated
application authorization precedes the durable SQLite admission CAS; dual READY
precedes Session delivery. The opaque `ServeHandle` owns ingress, published
Sessions, and actual callback cleanup while borrowing its TransportEnvironment. Its
Drain outcome and cleanup status remain separate. Startup failures are opaque
`ServeError` values with the original cleanup snapshot. See
`docs/TYPESCRIPT_TRANSPORT_V4.md` for lease and Release responsibilities.

`createTransportEnvironment(...)` owns resources, trusted time, credential
namespaces, material acquisition and Session lifetime. `configureNodeWSS(...)`
and `configureBrowserWSS(...)` install the actual direct WSS client entrance
for explicitly selected `preauthorized_pool` or `live_authority` activation and
the `transport` application profile, or explicit `services`/`execution` with
`ClientServicesConfig`. `configureBrowserWebTransport(...)`
installs the browser direct WebTransport entrance with the same identity,
material-source and admission owners and independent native application streams.
Its current public guarantees remain conservative; required independent
progress, input isolation, datagrams and consumer TLS inspection are refused.
`environment.connect(...)` consumes a registered source;
`environment.connectMaterial(...)` consumes already verified material once.
Connection requirements and Controller requirements are optional. Omitted
guarantee booleans default to `false`; an omitted application profile does not
select `transport`. The installed client captures its compiled application
profile and requests that exact profile from the source. An explicit mismatch
is rejected with `connection_requirement_unavailable` before acquisition.
Verified signed material is checked against the same profile before connecting
or spending it; incompatible material is released. Unsupported required
guarantees return `required_guarantee_unavailable` before acquisition or I/O.
Both return a Session only after actual pool TxA-P or verified live authority
authorization, HELLO/FSB/FSA, KKpsk0 Noise and authenticated dual READY.

The root, `./node` and `./browser` package entrances export the connection
configuration types. `NamespaceOptions` configures `client.namespace(...)`;
`CredentialPolicy` and `CredentialProvider` configure live or pool material
sources. The provider fills borrowed `CredentialBuffers` and returns
`CredentialLengths`, ending every borrow when its promise settles, including
after cancellation. The resulting `ConnectionMaterialSource` is accepted by
both `environment.connect(...)` and `createConnectionController(...)`.

`LiveAuthorizationConfig` captures an independently authenticated host control
transport, finite concurrency and actual runtime/provider allowances.
`LiveAuthorizationProvider` receives one bounded `LiveAuthorizationRequest`
after carrier preparation and complete Session admission. The original attempt,
lease, identities and winner remain fixed. Its returned full signed proof is
independently validated before HELLO; an HTTP result or receipt alone is
insufficient. Live and pool sources do not fall back to one another. The SDK
does not implement an authority database inside a consumer, and the host must
provide the real authenticated control transport and authority durability.

`createBrowserLiveHTTPS` is the browser HTTPS control adapter.
`BrowserLiveHTTPSOptions` binds one authority, tenant, audience, explicit
bearer calling credential, expiry and bounded native/SDK allowances.
`BrowserLiveHTTPSDeployment` fixes the canonical endpoint and current
application origin with independent operator evidence for TLS 1.3, no early
data and observable response framing. Fetch omits cookies, refuses redirects
and performs one attempt. Signed activation validation remains in the original
credential owner. This is a controlled-terminator guarantee, not browser-side
inspection of the negotiated TLS version.

`Session.probeLiveness(...)` returns a finite `LivenessResult` with
`submitted`, `complete` and `elapsedMS`. Elapsed time starts at local acceptance
and includes queuing; an unavailable elapsed value is `null`. `LivenessError`
retains the same facts with a bounded `LivenessFailure`. Cancellation and
rekey interrupt only this wait; actual provider tails keep their original slot.
Eight independent owners are admitted, including one protected automatic slot
when an explicit `AutomaticLivenessPolicy` is configured. Automatic liveness
has no implicit default. Only complete timely publication followed by the full
response budget without known local stalls can count a miss.

`Session.drain` captures one original `DrainOperation`, with optional
`DrainOptions` whose `timeoutMS` is capped at thirty seconds. Repeated calls cannot
extend it. `DrainResult` preserves `DrainOutcome` (`pending`, `drained`,
`deadline_aborted` or `failed`) separately from actual cleanup status.
`DrainError` reports bounded observer failure; canceled waits do not reopen
admission. GOAWAY fixes the historical accepted frontier and pending OPENs
receive explicit rejection. Existing streams and necessary rekey continue.
`Session.waitCleanup` passively observes actual resource release, with one
five-second cleanup deadline after Close; deadline expiry reports incomplete
cleanup while retained native tails remain charged. Registered authorizers,
handlers and send encoders keep their execution permits and application
allowances until actual exit. Core I/O can finish independently, reported as
`core_cleanup: "complete"` with pending callbacks; the TransportEnvironment then retains
only the compact cleanup owner and any independently authorized results.

`MessageStreamDefinition` binds opener/acceptor message directions through
`MessageDirection` and opaque `MessageCodec` values. Built-ins are
`bytesMessageCodec` and `utf8MessageCodec`; `applicationMessageCodec`
captures explicit synchronous or asynchronous `ApplicationMessageCodec`
callbacks with a host allowance. The local execution choice does not change
the canonical definition or framing. `TypedMessageStream` is returned by
Session `openMessageStream`/`acceptMessageStream`, or by `asTypedMessages`
after exclusive conversion of a matching unused raw stream.

`MessageStreamOptions`, `MessageSendOptions` and
`MessageReceiveOptions` control the original adapter. `MessageSendResult`
keeps submission separate from cleanup; `MessageReceiveResult` keeps EOF
separate from empty payload and records `application_input_delivered` for
application decoding. `MessageStreamError` exposes a bounded
`MessageFailure`. Typed and encoded Receive use one cursor and one consumption
right. After an application decoder starts, encoded receive reports
`result_mode_conflict`; canceled typed waits join the same decode completion.
Complete private payloads retain original authorization after normal I/O exit.

`StreamRegistration` closes future raw or typed handler admission without
closing already accepted streams. `StreamRegistrationOptions` supplies
concurrency, work class, metadata policy and application allowance.
`StreamOpenAuthorizer`, `MessageStreamHandler` and `RawStreamHandler`
receive the original `ApplicationContext`, including its immutable
`AuthenticatedContext`. `ApplicationWaitOptions` carries explicit dependency
context for bounded cleanup waits. Root-shared ordinary and protected
Completion services retain actual running callbacks across cancellation.
Raw registrations may also provide a fixed `RawStreamMetadataContract`. The
contract names one metadata namespace/version and a data-only JSON field schema
with encoded/decoded caps. The runtime validates and projects the metadata
after OPEN authentication but before `authorizeOpen`; unknown, missing, or
mis-typed fields reject that pending stream through the ordinary rejection and
cleanup path. `StreamMetadata.descriptorValues()` exposes the immutable
projection to the authorizer and accepted handler while `encoded()` and
`byteValues()` retain detached copies of the original bytes. No custom decoder,
extra wire frame, or second registry is installed by this option.
See [typed message streams](TYPESCRIPT_TRANSPORT_V4.md#typed-message-streams)
for current limits, ownership and remaining qualification requirements.

The signed Session idle duration starts at the completed dual READY publication
gate. Only complete successful authenticated output or fully validated input
refreshes it. Zero disables the signed watchdog. An explicit positive local
idle policy may tighten the duration; rekey, drain and delayed timers do not
extend it. Local active stream capacity is bounded by the signed stream
allowance, the configured local limit and 1024.

| Current client capability | Node | Browser |
| --- | --- | --- |
| Durable pool adapter | Actual SQLite transaction | Optional explicit host IndexedDB adapter with strict durability |
| TLS | TLS 1.3; signed CA or leaf-DER pin policy | Browser CA plus trusted immutable terminator/deployment binding |
| TLS guarantee | `consumer_enforced` | `controlled_terminator` |
| Application operations | Reliable streams, transient/execution unary clients, rekey, liveness and lifecycle | The same operations |
| Crypto profiles | X25519/ChaChaPoly/Ed25519 and P-256/AES256GCM/Ed25519 | The same two profiles |
| WSS guarantees | `shared_ordered`, `shared_failure_scope`, no datagram | The same WSS guarantees |

SQLite APIs are Node-only; IndexedDB APIs are browser-only. Both require an
independent trusted continuity authority, stable store identity, original
fencing epoch and unique tenant/issuer/lease consumption. They retain actual
native/store tails and cannot activate unknown commits through later readback.
The browser path requires extractable WebCrypto keys and an independently
configured deployment that enforces the actual TLS/Origin policy. It rejects
pin mode and required consumer TLS verification before consume. The optional
IndexedDB integration does not require ordinary users to configure a database;
a remote pool-consume service adapter is not implemented.

The Node entrypoint provides `createSQLiteExecutionBacking` and
`openSQLiteExecutionStore` for durable execution history and unary results.
The store uses its own `flowersec-v4-node-execution` format and requires explicit
provisioning, stable identity, finite storage limits and an independent
`SQLiteExecutionContinuity` host proof. Reopening requires proof that the
previous owner's real business work has settled or been fenced; a database
file alone is insufficient. Missing or incompatible history is rejected.

`SQLiteExecutionStore.installContract` persists the exact canonical contract
and finite Offer windows using an expected registry revision. `readRegistration`
copies that original body into caller-supplied storage and returns
`SQLiteExecutionRegistration` with the original revision and windows; it does
not extend admission. Use the store's original frozen `service` capability as
the handler's execution configuration and in management-only `executionServices`.
Copying the configuration does not copy storage authority. The same TransportEnvironment
cannot replace an execution authority with another backend.

The original execution engine registers before handler entry, persists dispatch
before invoking business code, and commits the complete unary result before
response publication. An uncertain COMMIT fences that store instance. Explicit
reopen preserves committed results and marks unresolved dispatched work unknown;
it never recreates a Start capability or automatically reruns business work.
Imported references use the chosen Session's current permissions for Query,
Cancel and ordinary result reads. Notification and streaming execution restore
terminal metadata without replaying callbacks; streaming with content policy
`none` does not produce retained unary results. Application-error terminals are
committed after encoding validation and before publication. An authoritative
absence transaction above its domain floor returns `not_found`/`not_registered`
without creating a cancellation tombstone; absent records at or below that
floor remain `history_unknown`. Failed durable cancellation writes publish no
confirmed cancellation fact or cooperative signal. Result expiry removes the stored payload
without deleting identity/history; history collection advances its domain floor
in the same transaction as deletion. `close()` waits for the actual bound
execution owner; the backing retains disk charges until files are actually
removed and `releaseRemoved()` succeeds. SQLite execution and pool adapters
share bounded file/connection accounting, while keeping separate schemas and
transaction semantics. These Node adapters execute SQLite transactions in bounded dedicated workers.
Their original callback and worker lifetimes remain charged through cancellation;
independent scheduling and stall isolation require separate qualification.

`createNodeLiveHTTPS` with `NodeLiveHTTPSOptions` supplies an TransportEnvironment-owned
live control adapter for `liveAuthority`. It makes one direct mutual-TLS 1.3
POST to the independently configured authority's `/live/authorize` endpoint.
The bounded `live-authorization-1` request matches the Go control service.
Explicit CA trust, hostname/SAN, actual TLS version, client certificate and
trusted certificate time are checked before publication. It has no redirects,
automatic retries, ambient cookies, proxy or connection reuse. Response framing
is bounded HTTP/1.1 200 with an exact positive Content-Length and
`application/cbor`; signed proof verification remains with the original
credential owner. Cancellation retains request buffers and resource charges
until actual native callbacks and sockets exit. The adapter cannot be installed
in a different TransportEnvironment.

Node exposes `configureNodeRawQUIC`, `createNodeRawQUICListener`,
`configureNodeWebTransport` and `createNodeWebTransportListener` with an
explicitly configured current native provider. An absent or incompatible
provider fails with `NativeTransportUnavailableError`; a method's presence
alone is not evidence of carrier negotiation or interoperability. Current
Node WSS listeners and registered tunnel owners borrow the same original
Environment. `createConnectionController(...)` captures explicit source,
initialization and retry policy and does not replay application work from a
terminated Session. WSS retains shared ordered progress and does not provide
native datagrams. Browser deployment and independent native carrier guarantees
remain subject to their documented qualification boundaries.

Checkpoint/Resume and restart-flush execution APIs require their trusted
execution history, fixed method contract and explicit application callback.
They do not recreate a Start right or automatically rerun business work.
`createProxySurface` composes the supported proxy runtime with its original
Session binding and publication owners; its behavior and credential ownership
are specified in the TypeScript section above.

`Session.bindService(...)` returns a fixed-Session `ServiceClient` whose
`prepareOperation(...)` and `call(...)` share the original unary engine.
`ExecutionUnaryOperation.reference()` exposes a compact execution reference.
The chosen Session's `queryOperation` and `requestCancel` use the fixed M
channel with current identity and independent namespace permissions. Queries
return bounded result metadata. With the trusted fixed `resultRead` tuple,
`readOperationResult(reference)` returns an independently owned ordinary RPC
read. Its typed value is `Uint8Array` containing the original encoded result;
`takeEncodedResult()` exposes those bytes through the same once-only delivery
gate. It does not infer the original business error/success codec.
`createOperationReferenceCodec(environment)` exports/imports the canonical
reference without storage I/O. Import requires the expected local domain, and
Query/Cancel/read resolve it through the chosen Session's trusted
`services.referenceTargets` peer mappings. Import grants no Start or local
operation capability. Imported unary reads reserve the full 1 MiB result bound.
`createStaticServiceContracts` accepts complete canonical local
`ServiceContract` bodies and exact execution `AdmissionOffer` bytes for a
trusted definition/target. `bindService` can consume this source through
`contractSource`; all entries are decoded and checked before publication,
remote contract queries are not performed, and closing the source after Bind
is safe because the binding retains its original charged snapshots.

For observation notification methods, `ServiceClient.notify` composes the same
Prepare/Start/WaitSubmission/Close path. `prepareOperation` returns
`ObservationNotifyOperation`, exposing local submission and cleanup state with
no response or execution reference. Complete local `submitted` status does not
assert peer delivery or handler success. The Session owns the independently
framed fixed notification channel and its actual publication tails.

`Session.notifications.subscribe` returns a typed local
`NotificationSubscription` with serial delivery, isolated mutable decoding,
optional projection, observation status, idempotent Close/Unsubscribe and passive
bounded WaitClosed. Observation methods can be declared with trusted canonical
contracts without a business handler. `latest_pending` applies only to
observation methods and replaces only values that have not entered application
code. Closing a token retains its slot until actual callback cleanup completes.

Execution notification methods return `ExecutionNotifyOperation` from Prepare,
with the same submission lifecycle and a query-only execution reference.
PrepareAndSave composes the registered ReferenceStore before explicit Start.
The volatile receiver uses the original TransportEnvironment execution key and current
authorization for one business dispatch and one observer fanout. Handler success
updates queryable execution state without allocating a response or result
payload; Query/Cancel use M and result reads reject notification references.

`ServiceClient.prepareAndSave` uses an optional
`createOperationReferenceStore(environment, policy, save)` adapter. Only a
confirmed durable create-or-compare and the original live delivery gate return
an operation; the caller then explicitly invokes Start. Unknown/conflict/rejected
saves and cancellation return bounded metadata and any query-only reference,
while actual callback tails retain their resources. The application backend
owns persistent quotas, expiration and deletion. A context already holding an
application execution permit is refused before encoding/store entry with
`admission_mode_incompatible`.
Trusted `services.executionDelegations` bind the current authenticated principal
to the original caller, namespace, direction, independent query/cancel grants
and a fixed trusted-time expiry. Incoming access also requires the current
certificate-bound identity and namespace permissions. A new authorized Session
can use the original reference without impersonating the caller or changing its
key. An incoming `executionServices` registration reuses the same TransportEnvironment's
history and results without requiring another business handler.
A failed M channel can be reconstructed after
its original tasks, physical resources and retirement proof exit, within the
original recovery deadline and 16-allocation Session limit. Ordinary RPC reads
continue independently; complete native-provider saturation protection remains
unqualified.

`DuplexBridge` is the bounded TypeScript bridge for two accepted Flowersec
Streams in the core, browser and proxy entrypoints. The Node entrypoint also
supports one explicitly owned Node `net.Socket` or `tls.TLSSocket` paired with
one accepted Flowersec Stream. It exposes `start`, `wait`, `abort`, `progress`, `cleanupStatus` and
`waitCleanup`, preserves one bounded unaccepted tail per direction, and uses
the original endpoint gates for read/write/half-close/finish/reset. Wait signal
cancellation is passive; an operation signal, finite timeout or `abort()` resets
both owned endpoints. A Node native socket must be unused, use binary mode,
set `allowHalfOpen: true`, have no flowing `data` listener or queued writes,
and keep both high-water marks at or below `readChunkBytes`. The Node bridge
charges four chunks of native staging/queue capacity plus a separate detached
result tail against the paired Stream's resource owner. Browser Web Streams,
WebSockets and other adapters are not native endpoints.

`UnaryOperation` provides explicit Start, typed/encoded result collection,
metadata status and local Close. See the linked construction guide for result
ownership and the current application-profile qualification boundary.
Generated operation/result types describe observations, not executable support
or activation authority. Functional Chromium coverage uses explicit test trust;
public-CA deployment, independent continuity and Go/browser interoperability
remain separate qualifications. See
[TypeScript Transport v4](TYPESCRIPT_TRANSPORT_V4.md) for construction, cleanup
and the exact support boundary, and
[the implementation binding](TRANSPORT_V4_BINDING.md) for schema/release gates.

| Symbol | Package subpaths |
| --- | --- |
| `AdmissionOffer` | `.`, `./node`, `./browser`, `./proxy` |
| `ApplicationProfile` | `.`, `./node`, `./browser`, `./proxy` |
| `BoundStreamInputIsolation` | `.`, `./node`, `./browser`, `./proxy` |
| `BrowserWSSClient` | `./browser` |
| `BrowserWSSClientConfig` | `./browser` |
| `BrowserWSSClientLimits` | `./browser` |
| `BrowserWSSDeployment` | `./browser` |
| `BrowserWSSOptions` | `./browser` |
| `BrowserWebTransportClient` | `./browser` |
| `BrowserWebTransportClientConfig` | `./browser` |
| `BrowserWebTransportClientLimits` | `./browser` |
| `BrowserWebTransportDeployment` | `./browser` |
| `BrowserWebTransportOptions` | `./browser` |
| `CleanupState` | `.`, `./node`, `./browser`, `./proxy` |
| `CleanupStatus` | `.`, `./node`, `./browser`, `./proxy` |
| `ClockRate` | `.`, `./node`, `./browser`, `./proxy` |
| `CloseResult` | `.`, `./node`, `./browser`, `./proxy` |
| `ConnectionGuaranteeAssumptions` | `.`, `./node`, `./browser`, `./proxy` |
| `ConnectionGuaranteeScope` | `.`, `./node`, `./browser`, `./proxy` |
| `ConnectionGuarantees` | `.`, `./node`, `./browser`, `./proxy` |
| `ConnectionMaterial` | `.`, `./node`, `./browser`, `./proxy` |
| `ConnectionRequirements` | `.`, `./node`, `./browser`, `./proxy` |
| `ConsumerTLS13Verification` | `.`, `./node`, `./browser`, `./proxy` |
| `CoreCleanup` | `.`, `./node`, `./browser`, `./proxy` |
| `Direction` | `.`, `./node`, `./browser`, `./proxy` |
| `DuplexBridge` | `.`, `./node`, `./browser`, `./proxy` |
| `DuplexBridgeDirectionProgress` | `.`, `./node`, `./browser`, `./proxy` |
| `DuplexBridgeError` | `.`, `./node`, `./browser`, `./proxy` |
| `DuplexBridgeFailure` | `.`, `./node`, `./browser`, `./proxy` |
| `DuplexBridgeOptions` | `.`, `./node`, `./browser`, `./proxy` |
| `DuplexBridgeProgress` | `.`, `./node`, `./browser`, `./proxy` |
| `DuplexBridgeResult` | `.`, `./node`, `./browser`, `./proxy` |
| `DuplexDirectionResult` | `.`, `./node`, `./browser`, `./proxy` |
| `DuplexEndpointKind` | `.`, `./node`, `./browser`, `./proxy` |
| `DuplexOutcome` | `.`, `./node`, `./browser`, `./proxy` |
| `DuplexResult` | `.`, `./node`, `./browser`, `./proxy` |
| `DuplexSendResult` | `.`, `./node`, `./browser`, `./proxy` |
| `DurableExecutionService` | `./node` |
| `EnvironmentClockConfig` | `.`, `./node`, `./browser`, `./proxy` |
| `EnvironmentConfig` | `.`, `./node`, `./browser`, `./proxy` |
| `ErrorCode` | `.`, `./node`, `./browser`, `./proxy` |
| `ErrorScope` | `.`, `./node`, `./browser`, `./proxy` |
| `ExecutionNotifyOperation` | `.`, `./node`, `./browser`, `./proxy` |
| `ExecutionStoreError` | `./node` |
| `IndexedDBPoolBacking` | `./browser` |
| `IndexedDBPoolContinuity` | `./browser` |
| `IndexedDBPoolError` | `./browser` |
| `IndexedDBPoolFailure` | `./browser` |
| `IndexedDBPoolIdentity` | `./browser` |
| `IndexedDBPoolLimits` | `./browser` |
| `IndexedDBPoolOpenOptions` | `./browser` |
| `IndexedDBPoolStore` | `./browser` |
| `LifecycleObjectKind` | `.`, `./node`, `./browser`, `./proxy` |
| `LifecycleReason` | `.`, `./node`, `./browser`, `./proxy` |
| `LifecycleResult` | `.`, `./node`, `./browser`, `./proxy` |
| `LifecycleState` | `.`, `./node`, `./browser`, `./proxy` |
| `MaintenanceOwner` | `.`, `./node`, `./browser`, `./proxy` |
| `MessageStreamDefinition` | `.`, `./node`, `./browser`, `./proxy` |
| `MethodDefinition` | `.`, `./node`, `./browser`, `./proxy` |
| `NodeLiveHTTPSOptions` | `./node` |
| `NodeWSSClient` | `./node` |
| `NodeWSSClientConfig` | `./node` |
| `NodeWSSClientLimits` | `./node` |
| `NodeWSSOptions` | `./node` |
| `NotificationSubscription` | `.`, `./node`, `./browser`, `./proxy` |
| `ObservationNotifyOperation` | `.`, `./node`, `./browser`, `./proxy` |
| `OperationHandle` | `.`, `./node`, `./browser`, `./proxy` |
| `OperationReference` | `.`, `./node`, `./browser`, `./proxy` |
| `OperationReferenceCodec` | `.`, `./node`, `./browser`, `./proxy` |
| `OperationReferenceStore` | `.`, `./node`, `./browser`, `./proxy` |
| `OperationStatus` | `.`, `./node`, `./browser`, `./proxy` |
| `PoolStoreError` | `./node` |
| `PoolStoreFailure` | `./node` |
| `PublicationTransferResult` | `.`, `./node`, `./browser`, `./proxy` |
| `ReadCause` | `.`, `./node`, `./browser`, `./proxy` |
| `ReadMethodFailure` | `.`, `./node`, `./browser`, `./proxy` |
| `ReadMethodFailureReason` | `.`, `./node`, `./browser`, `./proxy` |
| `ReadProgress` | `.`, `./node`, `./browser`, `./proxy` |
| `ReadResult` | `.`, `./node`, `./browser`, `./proxy` |
| `ReadTerminal` | `.`, `./node`, `./browser`, `./proxy` |
| `ReaderCursor` | `.`, `./node`, `./browser`, `./proxy` |
| `ReaderCursorSnapshot` | `.`, `./node`, `./browser`, `./proxy` |
| `ReliableProgress` | `.`, `./node`, `./browser`, `./proxy` |
| `ResourceRoot` | `.`, `./node`, `./browser`, `./proxy` |
| `ResourceRootConfig` | `.`, `./node`, `./browser`, `./proxy` |
| `ResourceVector` | `.`, `./node`, `./browser`, `./proxy` |
| `ResponsePublication` | `.`, `./node`, `./browser`, `./proxy` |
| `ResponsePublicationCause` | `.`, `./node`, `./browser`, `./proxy` |
| `ResponsePublicationState` | `.`, `./node`, `./browser`, `./proxy` |
| `ResponsePublicationStatus` | `.`, `./node`, `./browser`, `./proxy` |
| `RetryDisposition` | `.`, `./node`, `./browser`, `./proxy` |
| `SQLiteExecutionBacking` | `./node` |
| `SQLiteExecutionContinuity` | `./node` |
| `SQLiteExecutionIdentity` | `./node` |
| `SQLiteExecutionLimits` | `./node` |
| `SQLiteExecutionOptions` | `./node` |
| `SQLiteExecutionRegistration` | `./node` |
| `SQLiteExecutionStore` | `./node` |
| `SQLitePoolBacking` | `./node` |
| `SQLitePoolBinding` | `./node` |
| `SQLitePoolContinuity` | `./node` |
| `SQLitePoolIdentity` | `./node` |
| `SQLitePoolLimits` | `./node` |
| `SQLitePoolOpenOptions` | `./node` |
| `SQLitePoolStore` | `./node` |
| `ServiceClient` | `.`, `./node`, `./browser`, `./proxy` |
| `ServiceContract` | `.`, `./node`, `./browser`, `./proxy` |
| `ServiceDefinition` | `.`, `./node`, `./browser`, `./proxy` |
| `Session` | `.`, `./node`, `./browser`, `./proxy` |
| `SessionInfo` | `.`, `./node`, `./browser`, `./proxy` |
| `Stream` | `.`, `./node`, `./browser`, `./proxy` |
| `StreamStatus` | `.`, `./node`, `./browser`, `./proxy` |
| `StreamingOperation` | `.`, `./node`, `./browser`, `./proxy` |
| `TopUpError` | `.`, `./node`, `./browser`, `./proxy` |
| `TopUpErrorCode` | `.`, `./node`, `./browser`, `./proxy` |
| `TopUpErrorScope` | `.`, `./node`, `./browser`, `./proxy` |
| `TopUpWireResult` | `.`, `./node`, `./browser`, `./proxy` |
| `TopUpWriteAction` | `.`, `./node`, `./browser`, `./proxy` |
| `TransferProgress` | `.`, `./node`, `./browser`, `./proxy` |
| `TransportEnvironment` | `.`, `./node`, `./browser`, `./proxy` |
| `TypedError` | `.`, `./node`, `./browser`, `./proxy` |
| `TypedMessageStream` | `.`, `./node`, `./browser`, `./proxy` |
| `UnaryOperation` | `.`, `./node`, `./browser`, `./proxy` |
| `WaitStatus` | `.`, `./node`, `./browser`, `./proxy` |
| `WriteOperation` | `.`, `./node`, `./browser`, `./proxy` |
| `WritePhase` | `.`, `./node`, `./browser`, `./proxy` |
| `WriteProgress` | `.`, `./node`, `./browser`, `./proxy` |
| `WriteTerminalReason` | `.`, `./node`, `./browser`, `./proxy` |
| `configureBrowserWSS` | `./browser` |
| `configureBrowserWebTransport` | `./browser` |
| `configureNodeWSS` | `./node` |
| `connectionAssurance` | `.`, `./node`, `./browser`, `./proxy` |
| `createIndexedDBPoolBacking` | `./browser` |
| `createNodeLiveHTTPS` | `./node` |
| `createSQLiteExecutionBacking` | `./node` |
| `createSQLitePoolBacking` | `./node` |
| `createTransportEnvironment` | `.`, `./node`, `./browser`, `./proxy` |
| `openIndexedDBPoolStore` | `./browser` |
| `openSQLiteExecutionStore` | `./node` |
| `openSQLitePoolStore` | `./node` |
| `topUpErrorProjection` | `.`, `./node`, `./browser`, `./proxy` |
| `transportAPIResultsSchemaSHA256` | `.`, `./node`, `./browser`, `./proxy` |
## Go WebTransport and unreliable messages

These entries expose bounded original owners, connection assembly, authenticated control transports, issuance authorities and read-only authorization facts. Each capability retains its own admission and lifecycle gates. See [Go transport assembly](GO_TRANSPORT_V4.md) for construction and cleanup.

| Symbol | Declaration |
| --- | --- |
| `(*flowersec.ServeHandle).AcceptWebTransport` | method |
| `(*flowersec.Session).UnreliableMessages` | method |
| `(*flowersec.WebTransportIngress).Close` | method |
| `(*flowersec.WebTransportIngress).WaitCleanup` | method |
| `(*flowersec.WebTransportServer).Accept` | method |
| `(*flowersec.WebTransportServer).Address` | method |
| `(*flowersec.WebTransportServer).Close` | method |
| `(*flowersec.WebTransportServer).WaitCleanup` | method |
| `flowersec.DefaultWebTransportLimits` | func |
| `flowersec.NewWebSocketCarrierSet` | func |
| `flowersec.NewWebTransportCarrierFactory` | func |
| `flowersec.NewWebTransportServer` | func |
| `flowersec.UnreliableMessageReceiveDisabled` | const |
| `flowersec.UnreliableMessageTemporarilyBlocked` | const |
| `flowersec.WebSocketCarrierSet` | type |
| `flowersec.WebSocketCarrierSetCharge` | func |
| `flowersec.WebSocketEndpoint` | type |
| `flowersec.WebSocketSetConfig` | type |
| `flowersec.WebTransportAcceptOptions` | type |
| `flowersec.WebTransportCarrierFactory` | type |
| `flowersec.WebTransportCarrierFactoryCharge` | func |
| `flowersec.WebTransportFactoryConfig` | type |
| `flowersec.WebTransportIngress` | type |
| `flowersec.WebTransportLimits` | type |
| `flowersec.WebTransportProviderOptions` | type |
| `flowersec.WebTransportServer` | type |
| `flowersec.WebTransportServerCharge` | func |
| `flowersec.WebTransportServerConfig` | type |

## Go owners and control adapters

These entries expose bounded original owners, connection assembly, authenticated control transports, issuance authorities and read-only authorization facts. Each capability retains its own admission and lifecycle gates. See [Go transport assembly](GO_TRANSPORT_V4.md) for construction and cleanup.

| Symbol | Declaration |
| --- | --- |
| `(*controlplane.NamespaceHTTPSService).Close` | method |
| `(*controlplane.NamespaceHTTPSService).ServeHTTP` | method |
| `(*controlplane.NamespaceHTTPSService).WaitCleanup` | method |
| `(*controlplane.NamespacePublisher).Close` | method |
| `(*controlplane.NamespacePublisher).GoString` | method |
| `(*controlplane.NamespacePublisher).Publish` | method |
| `(*controlplane.NamespacePublisher).String` | method |
| `(*controlplane.NamespacePublisher).WaitCleanup` | method |
| `(*controlplane.SQLitePublicationStore).Close` | method |
| `(*controlplane.SQLitePublicationStore).GoString` | method |
| `(*controlplane.SQLitePublicationStore).ReadPublished` | method |
| `(*controlplane.SQLitePublicationStore).ReplaceState` | method |
| `(*controlplane.SQLitePublicationStore).Retire` | method |
| `(*controlplane.SQLitePublicationStore).String` | method |
| `(*controlplane.SQLitePublicationStore).WaitCleanup` | method |
| `controlplane.CreateSQLitePublicationStore` | func |
| `controlplane.NewNamespaceHTTPSService` | func |
| `controlplane.NewNamespacePublisher` | func |
| `controlplane.OpenSQLitePublicationStore` | func |
| `controlplane.NamespaceHTTPSConfig` | type |
| `controlplane.NamespaceHTTPSService` | type |
| `controlplane.NamespaceHTTPSServiceCharge` | func |
| `controlplane.NamespacePublicationScope` | type |
| `controlplane.NamespacePublicationVersion` | type |
| `controlplane.NamespacePublisher` | type |
| `controlplane.NamespacePublisherCharges` | func |
| `controlplane.NamespacePublisherConfig` | type |
| `controlplane.PublicationAuthority` | type |
| `controlplane.PublicationFailure` | type |
| `controlplane.PublicationFailure.Error` | method |
| `controlplane.SQLitePublicationConfig` | type |
| `controlplane.SQLitePublicationStore` | type |
| `controlplane.SQLitePublicationStoreCharges` | func |

## Go owners and control adapters

These entries expose bounded original owners, connection assembly, authenticated control transports, issuance authorities and read-only authorization facts. Each capability retains its own admission and lifecycle gates. See [Go transport assembly](GO_TRANSPORT_V4.md) for construction and cleanup.

| Symbol | Declaration |
| --- | --- |
| `(*flowersec.ProxyServer).StreamHandlers` | method |

## Rust carrier binding selection

`BindingMode`, `BindingMode::DirectExporter` and
`BindingMode::AuthenticatedContext` select the signed transport binding.
`WssConnectOptions::binding_mode` and `WssServeOptions::binding_mode` fix
that choice before the original irreversible admission or spend. Native direct
exporter mode derives its value independently at each actual TLS endpoint.
See [Rust transport v4 assembly](RUST_TRANSPORT_V4.md).

## Go owners and control adapters

These entries expose bounded original owners, connection assembly, authenticated control transports, issuance authorities and read-only authorization facts. Each capability retains its own admission and lifecycle gates. See [Go transport assembly](GO_TRANSPORT_V4.md) for construction and cleanup.

| Symbol | Declaration |
| --- | --- |
| `(*flowersec.NotifyOperationHandle).Close` | method |
| `(*flowersec.NotifyOperationHandle).Reference` | method |
| `(*flowersec.NotifyOperationHandle).Start` | method |
| `(*flowersec.NotifyOperationHandle).SubmissionStatus` | method |
| `(*flowersec.NotifyOperationHandle).WaitCleanup` | method |
| `(*flowersec.NotifyOperationHandle).WaitSubmission` | method |
| `(*flowersec.StreamingOperationHandle).AbandonResult` | method |
| `(*flowersec.StreamingOperationHandle).Close` | method |
| `(*flowersec.StreamingOperationHandle).Items` | method |
| `(*flowersec.StreamingOperationHandle).ReadNext` | method |
| `(*flowersec.StreamingOperationHandle).ReadNextEncoded` | method |
| `(*flowersec.StreamingOperationHandle).Reference` | method |
| `(*flowersec.StreamingOperationHandle).Start` | method |
| `(*flowersec.StreamingOperationHandle).Status` | method |
| `(*flowersec.StreamingOperationHandle).WaitCleanup` | method |
| `(*flowersec.StreamingOperationHandle).WaitStatus` | method |
| `(*flowersec.StreamingStartError).Error` | method |
| `(*flowersec.StreamingStartError).Unwrap` | method |
| `(*flowersec.ConnectionController).GoString` | method |
| `(*flowersec.ConnectionController).MarshalJSON` | method |
| `(*flowersec.ConnectionController).String` | method |
| `(*flowersec.ServiceClient).CallMethod` | method |
| `(*flowersec.ServiceClient).Contract` | method |
| `(*flowersec.ServiceClient).DispatchMethod` | method |
| `(*flowersec.ServiceClient).NotifyMethod` | method |
| `(*flowersec.ServiceClient).PrepareMethod` | method |
| `(*flowersec.ServiceClient).PrepareNotifyMethod` | method |
| `(*flowersec.ServiceClient).PrepareStreamingMethod` | method |
| `(*flowersec.ServiceClient).Refresh` | method |
| `(*flowersec.ServiceClient).StreamMethod` | method |
| `(*flowersec.ServiceClient).UpdateContract` | method |
| `(*flowersec.Session).BindMethods` | method |
| `(*flowersec.Session).BindUnaryService` | method |
| `(*flowersec.Session).PrepareNotify` | method |
| `(*flowersec.Session).PrepareStreaming` | method |
| `(*flowersec.StreamingResponse).SendItemEncoded` | method |
| `flowersec.ErrContractPolicyRejected` | var |
| `flowersec.ErrContractUpdateInProgress` | var |
| `flowersec.NewStreamRegistration` | func |
| `flowersec.NotificationResult` | type |
| `flowersec.NotificationSubmission` | type |
| `flowersec.NotifyOperationHandle` | type |
| `flowersec.StreamingItem` | type |
| `flowersec.StreamingOperationHandle` | type |
| `flowersec.StreamingProgress` | type |
| `flowersec.StreamingStartError` | type |
| `flowersec.BoundedContractAcceptance` | func |
| `flowersec.CallNotify` | const |
| `flowersec.CallServerStreaming` | const |
| `flowersec.CallUnary` | const |
| `flowersec.ContractAcceptance` | type |
| `flowersec.ContractBounded` | const |
| `flowersec.ContractExact` | const |
| `flowersec.ContractRange` | type |
| `flowersec.ContractSnapshot` | type |
| `flowersec.MethodSelector` | type |
| `flowersec.NotifyMethod` | type |
| `flowersec.ServiceBindOptions` | type |
| `flowersec.ServiceDefinition` | type |
| `flowersec.ServiceMethod` | type |
| `flowersec.ServiceMethodWorkload` | type |
| `flowersec.SessionMethodWorkload` | type |
| `flowersec.StreamRegistration` | type |
| `flowersec.StreamingMethod` | type |
| `flowersec.StreamingRequest` | type |
| `flowersec.StreamingResponse` | type |
| `flowersec.UnaryServiceDefinition` | type |
| `flowersec.UnaryServiceMethod` | type |

## Go owners and control adapters

These entries expose bounded original owners, connection assembly, authenticated control transports, issuance authorities and read-only authorization facts. Each capability retains its own admission and lifecycle gates. See [Go transport assembly](GO_TRANSPORT_V4.md) for construction and cleanup.

| Symbol | Declaration |
| --- | --- |
| `(*flowersec.OperationReferenceCodec).Close` | method |
| `(*flowersec.OperationReferenceCodec).Export` | method |
| `(*flowersec.OperationReferenceCodec).Import` | method |
| `(*flowersec.ResumeCodec).Close` | method |
| `(*flowersec.ResumeCodec).DecodeResult` | method |
| `(*flowersec.ResumeCodec).ImportToken` | method |
| `(*flowersec.SQLiteReferenceStore).Binding` | method |
| `(*flowersec.SQLiteReferenceStore).Close` | method |
| `(*flowersec.SQLiteReferenceStore).SaveOperationReference` | method |
| `(*flowersec.SQLiteReferences).Close` | method |
| `(*flowersec.SQLiteReferences).Collect` | method |
| `(*flowersec.SQLiteReferences).GoString` | method |
| `(*flowersec.SQLiteReferences).List` | method |
| `(*flowersec.SQLiteReferences).Load` | method |
| `(*flowersec.SQLiteReferences).MarshalJSON` | method |
| `(*flowersec.SQLiteReferences).Retire` | method |
| `(*flowersec.SQLiteReferences).Save` | method |
| `(*flowersec.SQLiteReferences).String` | method |
| `(*flowersec.SQLiteReferences).WaitCleanup` | method |
| `(*flowersec.ServiceClient).PrepareMethodAndSave` | method |
| `(*flowersec.ServiceClient).PrepareNotifyMethodAndSave` | method |
| `(*flowersec.ServiceClient).PrepareStreamingMethodAndSave` | method |
| `(*flowersec.Session).PrepareNotifyAndSave` | method |
| `(*flowersec.Session).PrepareResume` | method |
| `(*flowersec.Session).PrepareResumeAndSave` | method |
| `(*flowersec.Session).PrepareStreamingAndSave` | method |
| `(*flowersec.Session).PrepareUnaryAndSave` | method |
| `(*flowersec.Session).Resume` | method |
| `flowersec.CreateSQLiteReferences` | func |
| `flowersec.ErrOperationReferenceExpired` | var |
| `flowersec.ErrReferenceSaveUnknown` | var |
| `flowersec.NewOperationReferenceCodec` | func |
| `flowersec.NewResumeCodec` | func |
| `flowersec.NewSQLiteReferenceStore` | func |
| `flowersec.OpenSQLiteReferences` | func |
| `flowersec.OperationReferenceCodec` | type |
| `flowersec.OperationReferenceCodecCharge` | func |
| `flowersec.OperationReferenceSaveResult` | type |
| `flowersec.OperationReferenceStore` | type |
| `flowersec.OperationReferenceStore.SaveOperationReference` | interface_method |
| `flowersec.ReferenceSaveConfirmed` | const |
| `flowersec.ReferenceSaveOutcome` | type |
| `flowersec.ReferenceSaveUnknown` | const |
| `flowersec.ReferenceStoreBinding` | type |
| `flowersec.ResumeAccepted` | const |
| `flowersec.ResumeCheckpoint` | type |
| `flowersec.ResumeClaims` | type |
| `flowersec.ResumeCodec` | type |
| `flowersec.ResumeCodecCharge` | func |
| `flowersec.ResumeMACToken` | const |
| `flowersec.ResumeMethod` | type |
| `flowersec.ResumeRejected` | const |
| `flowersec.ResumeResult` | type |
| `flowersec.ResumeSignedToken` | const |
| `flowersec.ResumeToken` | type |
| `flowersec.ResumeUnknown` | const |
| `flowersec.SQLiteReferenceConfig` | type |
| `flowersec.SQLiteReferenceStore` | type |
| `flowersec.SQLiteReferenceStoreCharge` | func |
| `flowersec.SQLiteReferences` | type |
| `flowersec.SQLiteReferencesCharge` | func |

## Go owners and control adapters

These entries expose bounded original owners, connection assembly, authenticated control transports, issuance authorities and read-only authorization facts. Each capability retains its own admission and lifecycle gates. See [Go transport assembly](GO_TRANSPORT_V4.md) for construction and cleanup.

| Symbol | Declaration |
| --- | --- |
| `(*flowersec.ConnectionController).BindMethods` | method |
| `(*flowersec.ConnectionController).BindUnaryMethods` | method |
| `(*flowersec.RecoveryMACKey).Close` | method |
| `(*flowersec.RecoveryMACKey).GoString` | method |
| `(*flowersec.RecoveryMACKey).MarshalJSON` | method |
| `(*flowersec.RecoveryMACKey).String` | method |
| `(*flowersec.RecoveryVerifier).Close` | method |
| `(*flowersec.RecoveryVerifier).GoString` | method |
| `(*flowersec.RecoveryVerifier).MarshalJSON` | method |
| `(*flowersec.RecoveryVerifier).String` | method |
| `(*flowersec.ResumeCodec).CaptureCheckpoint` | method |
| `(*flowersec.Session).QueryServiceContracts` | method |
| `flowersec.CreateSQLiteExecutions` | func |
| `flowersec.ImportRecoveryMACKey` | func |
| `flowersec.NewDurableExecutions` | func |
| `flowersec.NewRecoveryVerifier` | func |
| `flowersec.NewResumeRegistration` | func |
| `flowersec.OpenSQLiteExecutions` | func |
| `flowersec.AdmissionOfferBounds` | type |
| `flowersec.CheckpointIssuanceOptions` | type |
| `flowersec.ContractQueryRefusal` | type |
| `flowersec.ContractQuerySnapshotInfo` | type |
| `flowersec.ContractQuerySnapshots` | type |
| `flowersec.DurableExecutionConfig` | type |
| `flowersec.DurableExecutions` | type |
| `flowersec.DurableExecutionsCharge` | func |
| `flowersec.DurableServiceBinding` | func |
| `flowersec.ExecutionPrincipal` | type |
| `flowersec.ExecutionService` | type |
| `flowersec.ExecutionSessionIdentity` | type |
| `flowersec.ExecutionTarget` | type |
| `flowersec.RecoveryKey` | type |
| `flowersec.RecoveryMACKey` | type |
| `flowersec.RecoveryMACKeyCharge` | func |
| `flowersec.RecoveryVerifier` | type |
| `flowersec.RecoveryVerifierCharge` | func |
| `flowersec.RecoveryVerifierConfig` | type |
| `flowersec.ResumeStreamBinding` | type |
| `flowersec.SQLiteExecutionConfig` | type |
| `flowersec.SQLiteExecutionContinuity` | type |
| `flowersec.SQLiteExecutionMethod` | type |
| `flowersec.SQLiteExecutionRegistration` | type |
| `flowersec.SQLiteExecutionService` | type |
| `flowersec.SQLiteExecutions` | type |
| `flowersec.SQLiteExecutionsCharge` | func |
| `flowersec.ServiceAuthority` | type |
| `flowersec.ServiceContractPolicy` | type |
| `flowersec.ServiceContractTarget` | type |

Owned snapshot, checkpoint and execution storage aliases preserve their original methods:

| Symbol | Declaration |
| --- | --- |
| `(*flowersec.SQLiteBacking).Limits` | method |
| `(*flowersec.UnaryResponse).IssueCheckpoint` | method |
| `(*flowersec.ContractQuerySnapshots).Count` | method |
| `(*flowersec.ContractQuerySnapshots).Item` | method |
| `(*flowersec.ContractQuerySnapshots).CopyCanonical` | method |
| `(*flowersec.ContractQuerySnapshots).Close` | method |
| `(*flowersec.SQLiteExecutions).InstallContract` | method |
| `(*flowersec.SQLiteExecutions).ReadRegistration` | method |
| `(*flowersec.SQLiteExecutions).Close` | method |
| `(*flowersec.SQLiteExecutions).WaitCleanup` | method |
| `(*flowersec.SQLiteExecutions).Retire` | method |
| `(*flowersec.SQLiteExecutions).SupportsCheckpoints` | method |
| `(*flowersec.SQLiteExecutions).SupportsContent` | method |
| `(*flowersec.DurableExecutions).Close` | method |
| `(*flowersec.DurableExecutions).CleanupComplete` | method |

## Go owners and control adapters

These entries expose bounded original owners, connection assembly, authenticated control transports, issuance authorities and read-only authorization facts. Each capability retains its own admission and lifecycle gates. See [Go transport assembly](GO_TRANSPORT_V4.md) for construction and cleanup.

| Symbol | Declaration |
| --- | --- |
| `flowersec.ServiceContractSource` | type |
| `flowersec.ServiceContractsRemote` | const |
| `flowersec.ServiceContractsStatic` | const |

## Go owners and control adapters

These entries expose bounded original owners, connection assembly, authenticated control transports, issuance authorities and read-only authorization facts. Each capability retains its own admission and lifecycle gates. See [Go transport assembly](GO_TRANSPORT_V4.md) for construction and cleanup.

| Symbol | Declaration |
| --- | --- |
| `flowersec.ErrContractDenied` | var |
| `flowersec.ErrContractUnavailable` | var |

## Go owners and control adapters

These entries expose bounded original owners, connection assembly, authenticated control transports, issuance authorities and read-only authorization facts. Each capability retains its own admission and lifecycle gates. See [Go transport assembly](GO_TRANSPORT_V4.md) for construction and cleanup.

| Symbol | Declaration |
| --- | --- |
| `flowersec.ErrContractRenewalQualification` | var |
| `flowersec.ContractRenewalPolicy` | type |
| `flowersec.ServiceOfferRefresh` | type |
| `flowersec.ServiceOfferRefreshExplicit` | const |
| `flowersec.ServiceOfferRefreshManaged` | const |

## Go owners and control adapters

These entries expose bounded original owners, connection assembly, authenticated control transports, issuance authorities and read-only authorization facts. Each capability retains its own admission and lifecycle gates. See [Go transport assembly](GO_TRANSPORT_V4.md) for construction and cleanup.

| Symbol | Declaration |
| --- | --- |
| `flowersec.NewServiceDependency` | func |
| `flowersec.DispatchRequirement` | type |
| `flowersec.InvocationService` | type |
| `flowersec.InvocationService.CallMethod` | method |
| `flowersec.InvocationService.NotifyMethod` | method |
| `flowersec.InvocationService.PrepareMethod` | method |
| `flowersec.InvocationService.PrepareNotifyMethod` | method |
| `flowersec.InvocationService.PrepareStreamingMethod` | method |
| `flowersec.InvocationService.StreamMethod` | method |
| `flowersec.InvocationServiceFromContext` | func |
| `flowersec.OnUse` | const |
| `flowersec.RequiredForDispatch` | const |
| `flowersec.ServiceDependency` | type |
| `flowersec.ServiceDependencyMethod` | type |

Go ordinary stream metadata preserves the exact v4 application namespace,
version and byte map. `flowersec.NewStreamMetadataEnvelope` captures opaque
application bytes; `flowersec.StreamMetadata.Namespace`,
`flowersec.StreamMetadata.Version`, and `flowersec.StreamMetadata.ByteValues`
return detached projections. `flowersec.StreamMetadata.JSONValues` recognizes
only the optional `application/json` version 1 convenience codec. Nonempty
metadata is canonical CBOR; an empty metadata value uses zero bytes.

## Go namespace composition and managed credentials

These constructors install trusted roots and bounded original owners. A lookup
cannot choose its own trust provider or restore authority from cached history.
A retirement operation requires independent signed coverage before it can
release the exact predecessor backing. Cancellation retains the original pin
and preparation position until the unique host cancel/stop invocation exits.

| Symbol | Declaration |
| --- | --- |
| `flowersec.NamespaceReferenceConfig` | type |
| `flowersec.NamespaceReferenceFactory` | type |
| `flowersec.NamespaceReferenceFactoryCharge` | func |
| `flowersec.NewNamespaceReferenceFactory` | func |
| `(*flowersec.NamespaceReferenceFactory).Resolve` | method |
| `(*flowersec.NamespaceReferenceFactory).PrepareNamespaceRetirement` | method |
| `(*flowersec.NamespaceReferenceFactory).Close` | method |
| `(*flowersec.NamespaceReferenceFactory).WaitCleanup` | method |
| `(*flowersec.TransportEnvironment).VerificationNamespace` | method |
| `flowersec.NamespaceOnlineRetirement` | type |
| `flowersec.NamespaceOnlineRetirementCharge` | func |
| `flowersec.NewNamespaceOnlineRetirement` | func |
| `flowersec.NamespaceRetirementFactory` | type |
| `flowersec.NamespaceRetirementServiceConfig` | type |
| `flowersec.NamespaceRetirementServiceStatus` | type |
| `flowersec.NamespaceRetirementService` | type |
| `flowersec.NamespaceRetirementServiceCharge` | func |
| `flowersec.NewNamespaceRetirementService` | func |
| `flowersec.MaterialAcquisitionBatch` | type |
| `flowersec.NewMaterialAcquisitionBatch` | func |
| `(*flowersec.MaterialAcquisitionBatch).Acquire` | method |
| `(*flowersec.MaterialAcquisitionBatch).Close` | method |
| `(*flowersec.MaterialAcquisitionBatch).WaitCleanup` | method |
| `flowersec.ProxyCredentialMode` | type |
| `flowersec.ProxyCredentialsNone` | const |
| `flowersec.ProxyCredentialsExternal` | const |
| `flowersec.ProxyCredentialsCookieSession` | const |
| `flowersec.ProxyCredentialPolicy` | type |
| `flowersec.ProxyCredentialScope` | type |
| `flowersec.ProxyCookieSession` | type |
| `flowersec.ProxyCredentialClearResult` | type |
| `flowersec.ErrProxyCredentialScope` | var |
| `flowersec.ErrProxyCredentialUpdate` | var |
| `(*flowersec.ProxyServer).NewCookieSession` | method |
| `(*flowersec.ProxyCookieSession).Attachment` | method |
| `(*flowersec.ProxyCookieSession).ClearUpstreamCredentials` | method |
| `(*flowersec.ProxyCookieSession).Close` | method |
| `(*flowersec.ProxyCookieSession).CleanupStatus` | method |
| `(*flowersec.ProxyCookieSession).WaitCleanup` | method |
| `(*flowersec.ProxyCookieSession).String` | method |
| `(*flowersec.ProxyCookieSession).GoString` | method |
| `(*flowersec.ProxyCookieSession).MarshalJSON` | method |

Credential scope is supplied by the authenticated host registration. Private
association values never authorize a different tenant, principal, content
origin or Surface. Each content request captures one original incarnation.
Clear fences that incarnation before replacement allocation and retains its
confirmed invalidation result on failure. Actual native body and transport
cleanup is independent of a successful logical response.

## Go original tunnel server registration

`flowersec.TunnelServerRegistrationOptions` fixes the authenticated original
server material, existing resource root and accounts, registered allow provider
and complete HOP entrance. `flowersec.TunnelServerRegistrationCharge` and
`flowersec.NewTunnelServerRegistration` preadmit this composition before
advertising its binding or preparing its native carrier.
`flowersec.TunnelAcceptOptions` supplies one fresh original application plan.

| Symbol | Declaration |
| --- | --- |
| `flowersec.TunnelServerRegistrationOptions` | type |
| `flowersec.TunnelServerRegistration` | type |
| `flowersec.TunnelAcceptOptions` | type |
| `flowersec.TunnelServerRegistrationCharge` | func |
| `flowersec.NewTunnelServerRegistration` | func |
| `(*flowersec.TunnelServerRegistration).Handler` | method |
| `(*flowersec.TunnelServerRegistration).Binding` | method |
| `(*flowersec.TunnelServerRegistration).ReserveOriginalLivePublication` | method |
| `(*flowersec.TunnelServerRegistration).Accept` | method |
| `(*flowersec.TunnelServerRegistration).Close` | method |
| `(*flowersec.TunnelServerRegistration).WaitCleanup` | method |
| `(*flowersec.TunnelServerRegistration).String` | method |

Allow dispatch, HOP possession, local admission, FSA, Noise and READY retain
one original registration and carrier. A taken recipient transfers to the
original Serve/Environment ingress; closing the registration cannot refund
that physical work. Cleanup joins the original control and preparation calls.



Remote application failures are semantically separate from transport failures. TypeScript declares bounded `ApplicationErrorDefinition`; its handlers throw `ServiceError`. Swift exposes `ServiceApplicationError`, and Rust exposes `ServiceError`.


## Current manifest symbol index

The following symbols are part of the current public manifest.

| Symbol | Declaration |
| --- | --- |
| `(*flowersec.ConnectionController).SubscribeNotification` | manifest entry |
| `(*flowersec.DuplexBridge).Abort` | manifest entry |
| `(*flowersec.DuplexBridge).CleanupStatus` | manifest entry |
| `(*flowersec.DuplexBridge).Progress` | manifest entry |
| `(*flowersec.DuplexBridge).Start` | manifest entry |
| `(*flowersec.DuplexBridge).Wait` | manifest entry |
| `(*flowersec.MessageDefinitionCodec).Close` | manifest entry |
| `(*flowersec.MessageDefinitionCodec).Define` | manifest entry |
| `(*flowersec.MessageDefinitionCodec).ImportDefinition` | manifest entry |
| `(*flowersec.NativeTCP).CleanupStatus` | manifest entry |
| `(*flowersec.NativeTCP).Close` | manifest entry |
| `(*flowersec.NativeTCPDial).Cancel` | manifest entry |
| `(*flowersec.NativeTCPDial).CleanupStatus` | manifest entry |
| `(*flowersec.NativeTCPDial).Wait` | manifest entry |
| `(*flowersec.NotificationSubscription).ObservationStatus` | manifest entry |
| `(*flowersec.NotificationSubscription).Release` | manifest entry |
| `(*flowersec.NotificationSubscription).ReplaceDependencies` | manifest entry |
| `(*flowersec.NotificationSubscription).Status` | manifest entry |
| `(*flowersec.ProxyServer).Close` | manifest entry |
| `(*flowersec.ProxyServer).RegisterStreamHandlers` | manifest entry |
| `(*flowersec.QUICServer).InstallAcceptedRoute` | manifest entry |
| `(*flowersec.QUICServer).InterruptConnections` | manifest entry |
| `(*flowersec.QUICServer).InterruptTransport` | manifest entry |
| `(*flowersec.QUICServer).PrepareTunnel` | manifest entry |
| `(*flowersec.Session).OpenMessageStream` | manifest entry |
| `(*flowersec.Session).ReplaceServiceDependencies` | manifest entry |
| `(*flowersec.Session).SubscribeNotification` | manifest entry |
| `(*flowersec.SessionError).Code` | manifest entry |
| `(*flowersec.SessionError).Error` | manifest entry |
| `(*flowersec.SessionError).RetryDisposition` | manifest entry |
| `(*flowersec.SessionError).Unwrap` | manifest entry |
| `(*flowersec.TunnelRuntime).Close` | manifest entry |
| `(*flowersec.TunnelRuntime).ServePair` | manifest entry |
| `(*flowersec.TunnelRuntime).ServeRoute` | manifest entry |
| `(*flowersec.TunnelRuntime).WaitCleanup` | manifest entry |
| `(*flowersec.TypedMessageStream).CopyApplicationMetadata` | manifest entry |
| `(*flowersec.TypedMessageStream).Definition` | manifest entry |
| `(*flowersec.UnreliableMessageError).Code` | manifest entry |
| `(*flowersec.UnreliableMessageError).Error` | manifest entry |
| `(*flowersec.WebTransportServer).InstallAcceptedRoute` | manifest entry |
| `(*flowersec.WebTransportServer).InterruptConnections` | manifest entry |
| `(*flowersec.WebTransportServer).PrepareTunnel` | manifest entry |
| `flowersec.AcceptorOptions` | manifest entry |
| `flowersec.AdmissionFacts` | manifest entry |
| `flowersec.AdmissionFields` | manifest entry |
| `flowersec.ApplicationExecutorPreset` | manifest entry |
| `flowersec.ApplicationExecutorSnapshot` | manifest entry |
| `flowersec.ApplicationMessageCodec` | manifest entry |
| `flowersec.ApplicationMessageCodecOptions` | manifest entry |
| `flowersec.ApplicationProfileClient` | manifest entry |
| `flowersec.ApplicationProfileConstrained` | manifest entry |
| `flowersec.ApplicationProfileCustom` | manifest entry |
| `flowersec.ApplicationProfileServer` | manifest entry |
| `flowersec.ApplicationResourceProfile` | manifest entry |
| `flowersec.BytesMessageCodec` | manifest entry |
| `flowersec.ConnectArtifactInvalid` | manifest entry |
| `flowersec.ConnectConnectionFailed` | manifest entry |
| `flowersec.ConnectExpired` | manifest entry |
| `flowersec.ConnectTransportSecurityFailed` | manifest entry |
| `flowersec.ConnectTransportSecurityUnsupported` | manifest entry |
| `flowersec.ConnectionControllerOptions` | manifest entry |
| `flowersec.ConnectorOptions` | manifest entry |
| `flowersec.ContractBoolean` | manifest entry |
| `flowersec.ContractByteString` | manifest entry |
| `flowersec.ContractEncodedArray` | manifest entry |
| `flowersec.ContractEncodedMap` | manifest entry |
| `flowersec.ContractTextString` | manifest entry |
| `flowersec.ContractUnsigned` | manifest entry |
| `flowersec.ControlledHTTPService` | manifest entry |
| `flowersec.ControlledHTTPUpgradeConfig` | manifest entry |
| `flowersec.ControllerNotificationEvent` | manifest entry |
| `flowersec.ControllerNotificationGap` | manifest entry |
| `flowersec.ControllerNotificationObserver` | manifest entry |
| `flowersec.ControllerNotificationOptions` | manifest entry |
| `flowersec.CredentialBackingBytes` | manifest entry |
| `flowersec.CurrentWebSocketDirectPath` | manifest entry |
| `flowersec.CurrentWebSocketTunnelPath` | manifest entry |
| `flowersec.DelegatedHTTPService` | manifest entry |
| `flowersec.DelegatedStreamOptions` | type |
| `flowersec.DelegatedStreamServe` | type |
| `flowersec.DelegatedStreamService` | type |
| `flowersec.DuplexAborted` | manifest entry |
| `flowersec.DuplexBridge` | manifest entry |
| `flowersec.DuplexBridgeOptions` | manifest entry |
| `flowersec.DuplexDirectionProgress` | manifest entry |
| `flowersec.DuplexDirectionResult` | manifest entry |
| `flowersec.DuplexFailed` | manifest entry |
| `flowersec.DuplexNormal` | manifest entry |
| `flowersec.DuplexObservation` | manifest entry |
| `flowersec.DuplexOutcome` | manifest entry |
| `flowersec.DuplexProgress` | manifest entry |
| `flowersec.DuplexResult` | manifest entry |
| `flowersec.DuplexSendResult` | manifest entry |
| `flowersec.EmptyStreamMetadata` | manifest entry |
| `flowersec.EncodeServiceContract` | manifest entry |
| `flowersec.EncodedMessageReceiveResult` | manifest entry |
| `flowersec.Environment` | manifest entry |
| `flowersec.EnvironmentOptions` | manifest entry |
| `flowersec.ErrConnectionFailed` | manifest entry |
| `flowersec.ErrDuplexAborted` | manifest entry |
| `flowersec.ErrDuplexCleanupIncomplete` | manifest entry |
| `flowersec.ErrInvalidConnectorOptions` | manifest entry |
| `flowersec.ErrInvalidMetadata` | manifest entry |
| `flowersec.ErrInvalidProxyServer` | manifest entry |
| `flowersec.ErrMessageDecodeFailed` | manifest entry |
| `flowersec.ErrMessageEncodeFailed` | manifest entry |
| `flowersec.ErrMessageInputDelivered` | manifest entry |
| `flowersec.ErrMessageWouldBlock` | manifest entry |
| `flowersec.ExecutorOperationsSnapshot` | manifest entry |
| `flowersec.FeatureEnvelopePolicy` | manifest entry |
| `flowersec.HTTPStream` | manifest entry |
| `flowersec.HTTPStreamCharge` | manifest entry |
| `flowersec.HTTPStreamUpgrader` | manifest entry |
| `flowersec.HTTPUpgradePeer` | manifest entry |
| `flowersec.MessageCodec` | manifest entry |
| `flowersec.MessageCodecExecution` | manifest entry |
| `flowersec.MessageCodecIdentity` | manifest entry |
| `flowersec.MessageCodecIndependent` | manifest entry |
| `flowersec.MessageCodecSynchronous` | manifest entry |
| `flowersec.MessageDefinitionCodec` | manifest entry |
| `flowersec.MessageDefinitionCodecCharge` | manifest entry |
| `flowersec.MessageDirectionDefinition` | manifest entry |
| `flowersec.MessageReceiveError` | manifest entry |
| `flowersec.MessageReceiveResult` | manifest entry |
| `flowersec.MessageResultModeConflict` | manifest entry |
| `flowersec.MessageStreamDefinition.Digest` | manifest entry |
| `flowersec.MessageStreamDefinition.Directions` | manifest entry |
| `flowersec.MessageStreamDefinition.Kind` | manifest entry |
| `flowersec.MessageStreamDefinition.Revision` | manifest entry |
| `flowersec.MessageStreamDirection` | manifest entry |
| `flowersec.MessageStreamOptions` | manifest entry |
| `flowersec.MessageWireDefinition` | manifest entry |
| `flowersec.NamespaceRefresh` | manifest entry |
| `flowersec.NamespaceRefreshCharge` | manifest entry |
| `flowersec.NamespaceRefreshConfig` | manifest entry |
| `flowersec.NamespaceRefreshLimits` | manifest entry |
| `flowersec.NamespaceRefreshProvider` | manifest entry |
| `flowersec.NamespaceRefreshRequest` | manifest entry |
| `flowersec.NativeTCP` | manifest entry |
| `flowersec.NativeTCPCharge` | manifest entry |
| `flowersec.NativeTCPDial` | manifest entry |
| `flowersec.NativeTCPDialCharge` | manifest entry |
| `flowersec.NativeTCPDialOptions` | manifest entry |
| `flowersec.NativeTCPOptions` | manifest entry |
| `flowersec.NewDuplexBridge` | manifest entry |
| `flowersec.NewMessageDefinitionCodec` | manifest entry |
| `flowersec.NewMessageStreamDefinition` | manifest entry |
| `flowersec.NewNamespaceRefresh` | manifest entry |
| `flowersec.NewNativeDuplexBridge` | manifest entry |
| `flowersec.NewProtocolDecoder` | manifest entry |
| `flowersec.NewProxyServer` | manifest entry |
| `flowersec.NewServiceContractCodec` | manifest entry |
| `flowersec.NewSignedMapCodec` | manifest entry |
| `flowersec.NewStreamMetadata` | manifest entry |
| `flowersec.NewTunnelHop` | manifest entry |
| `flowersec.NewTunnelPair` | manifest entry |
| `flowersec.NewTunnelRoute` | manifest entry |
| `flowersec.NewTunnelRuntime` | manifest entry |
| `flowersec.NewWebSocketIngress` | manifest entry |
| `flowersec.NotificationCurrentOnly` | manifest entry |
| `flowersec.NotificationDrainAware` | manifest entry |
| `flowersec.NotificationDropNewest` | manifest entry |
| `flowersec.NotificationGapCapacity` | manifest entry |
| `flowersec.NotificationGapCoalesced` | manifest entry |
| `flowersec.NotificationGapContract` | manifest entry |
| `flowersec.NotificationGapExpired` | manifest entry |
| `flowersec.NotificationGapHandler` | manifest entry |
| `flowersec.NotificationGapHandoff` | manifest entry |
| `flowersec.NotificationGapInvalidPayload` | manifest entry |
| `flowersec.NotificationGapLateAttachment` | manifest entry |
| `flowersec.NotificationGapReasons` | manifest entry |
| `flowersec.NotificationGapSourceClosed` | manifest entry |
| `flowersec.NotificationLatestPending` | manifest entry |
| `flowersec.NotificationMethod` | manifest entry |
| `flowersec.NotificationObservationPolicy` | manifest entry |
| `flowersec.NotificationObservationStatus` | manifest entry |
| `flowersec.NotificationObserver` | manifest entry |
| `flowersec.NotificationPendingPolicy` | manifest entry |
| `flowersec.NotificationStatus` | manifest entry |
| `flowersec.PoolSpendFields` | manifest entry |
| `flowersec.ProtocolDecoder` | manifest entry |
| `flowersec.ProtocolDecoderBackingBytes` | manifest entry |
| `flowersec.ProtocolDocument` | manifest entry |
| `flowersec.ProtocolValue` | manifest entry |
| `flowersec.ProxyServer` | manifest entry |
| `flowersec.ProxyServerOptions` | manifest entry |
| `flowersec.QueryTargetAccess` | manifest entry |
| `flowersec.QueryTargetAllowed` | manifest entry |
| `flowersec.QueryTargetDenied` | manifest entry |
| `flowersec.QueryTargetUnavailable` | manifest entry |
| `flowersec.ReadTerminalEof` | manifest entry |
| `flowersec.RegisterMessageStream` | manifest entry |
| `flowersec.ResourceBackingBytes` | manifest entry |
| `flowersec.RetryDisposition` | manifest entry |
| `flowersec.RetryDispositionKind` | manifest entry |
| `flowersec.RetryDispositionRetryAfter` | manifest entry |
| `flowersec.RetryDispositionRetryable` | manifest entry |
| `flowersec.RetryDispositionTerminal` | manifest entry |
| `flowersec.ServeHTTPStream` | manifest entry |
| `flowersec.ServiceContract` | manifest entry |
| `flowersec.ServiceContractBackingBytes` | manifest entry |
| `flowersec.ServiceContractCodec` | manifest entry |
| `flowersec.ServiceContractField` | manifest entry |
| `flowersec.ServiceContractFieldKind` | manifest entry |
| `flowersec.SessionCanceled` | manifest entry |
| `flowersec.SessionClosed` | manifest entry |
| `flowersec.SessionContract` | manifest entry |
| `flowersec.SessionCoreReferenceSlots` | manifest entry |
| `flowersec.SessionCoreRequirements` | manifest entry |
| `flowersec.SessionError` | manifest entry |
| `flowersec.SessionErrorCode` | manifest entry |
| `flowersec.SessionGoingAway` | manifest entry |
| `flowersec.SessionLivenessFailed` | manifest entry |
| `flowersec.SessionOperationFailed` | manifest entry |
| `flowersec.SessionParameters` | manifest entry |
| `flowersec.SessionRekeyFailed` | manifest entry |
| `flowersec.SessionResourceExhausted` | manifest entry |
| `flowersec.SessionStreamRejected` | manifest entry |
| `flowersec.SessionStreamReset` | manifest entry |
| `flowersec.SessionTimeout` | manifest entry |
| `flowersec.SignedMapBackingBytes` | manifest entry |
| `flowersec.StartAcceptedHTTPStream` | manifest entry |
| `flowersec.StartHTTPStream` | manifest entry |
| `flowersec.StartNativeTCPDial` | manifest entry |
| `flowersec.StreamConn` | manifest entry |
| `flowersec.StreamConnCharge` | manifest entry |
| `flowersec.StreamConnOptions` | manifest entry |
| `flowersec.StreamMetadata` | manifest entry |
| `flowersec.StreamMetadata.Values` | manifest entry |
| `flowersec.TunnelCarrierPreparation` | manifest entry |
| `flowersec.TunnelHop` | manifest entry |
| `flowersec.TunnelHopConfig` | manifest entry |
| `flowersec.TunnelHopReservations` | manifest entry |
| `flowersec.TunnelPair` | manifest entry |
| `flowersec.TunnelPairCharge` | manifest entry |
| `flowersec.TunnelPairConfig` | manifest entry |
| `flowersec.TunnelRoute` | manifest entry |
| `flowersec.TunnelRouteCharge` | manifest entry |
| `flowersec.TunnelRouteConfig` | manifest entry |
| `flowersec.TunnelRouteRun` | manifest entry |
| `flowersec.TunnelRuntime` | manifest entry |
| `flowersec.TunnelRuntimeCharge` | manifest entry |
| `flowersec.TunnelRuntimeOptions` | manifest entry |
| `flowersec.UTF8MessageCodec` | manifest entry |
| `flowersec.UnreliableAccepted` | manifest entry |
| `flowersec.UnreliableDroppedBudget` | manifest entry |
| `flowersec.UnreliableDroppedCarrier` | manifest entry |
| `flowersec.UnreliableDroppedExpired` | manifest entry |
| `flowersec.UnreliableMessageCanceled` | manifest entry |
| `flowersec.UnreliableMessageChannel` | manifest entry |
| `flowersec.UnreliableMessageChannel.MaxMessageBytes` | manifest entry |
| `flowersec.UnreliableMessageChannel.Receive` | manifest entry |
| `flowersec.UnreliableMessageChannel.Send` | manifest entry |
| `flowersec.UnreliableMessageClosed` | manifest entry |
| `flowersec.UnreliableMessageError` | manifest entry |
| `flowersec.UnreliableMessageErrorCode` | manifest entry |
| `flowersec.UnreliableMessageErrorCode.String` | manifest entry |
| `flowersec.UnreliableMessageInvalid` | manifest entry |
| `flowersec.UnreliableMessageOperationFailed` | manifest entry |
| `flowersec.UnreliableMessageTooLarge` | manifest entry |
| `flowersec.UnreliableMessageUnavailable` | manifest entry |
| `flowersec.UnreliableSendOptions` | manifest entry |
| `flowersec.UnreliableSendStatus` | manifest entry |
| `flowersec.WebSocketIngress` | manifest entry |
| `flowersec.WebSocketIngressCharge` | manifest entry |
| `flowersec.WebSocketIngressConfig` | manifest entry |
| `controlplane.ArtifactIssueAuthenticationKind` | manifest entry |
| `controlplane.ArtifactIssueHost` | manifest entry |
| `controlplane.ArtifactIssueHostCharge` | manifest entry |
| `controlplane.ArtifactIssueHostConfig` | manifest entry |
| `controlplane.ArtifactIssueLocalCredential` | manifest entry |
| `controlplane.ArtifactIssueMutualTLS` | manifest entry |
| `controlplane.ArtifactIssueShareConfig` | manifest entry |
| `controlplane.ArtifactIssueStateShareBytes` | manifest entry |
| `controlplane.NewArtifactIssueHost` | manifest entry |
| `controlplane.NewPoolHTTPSService` | manifest entry |
| `controlplane.NewPoolOwnerProofIssuer` | manifest entry |
| `controlplane.NewPoolSourceAuthority` | manifest entry |
| `controlplane.NewPoolTunnelAuthority` | manifest entry |
| `controlplane.NewPoolTunnelDeployment` | manifest entry |
| `controlplane.NewPoolTunnelDeploymentFromPolicy` | manifest entry |
| `controlplane.PoolBatchVerificationConfig` | manifest entry |
| `controlplane.PoolHTTPSService` | manifest entry |
| `controlplane.PoolHTTPSServiceCharge` | manifest entry |
| `controlplane.PoolHTTPSServiceConfig` | manifest entry |
| `controlplane.PoolOwnerProofIssuer` | manifest entry |
| `controlplane.PoolOwnerProofIssuerCharge` | manifest entry |
| `controlplane.PoolOwnerProofIssuerConfig` | manifest entry |
| `controlplane.PoolSourceAuthority` | manifest entry |
| `controlplane.PoolSourceAuthorityCharge` | manifest entry |
| `controlplane.PoolSourceAuthorityConfig` | manifest entry |
| `controlplane.PoolSourceIssuanceLimits` | manifest entry |
| `controlplane.PoolTunnelAuthority` | manifest entry |
| `controlplane.PoolTunnelAuthorityCharge` | manifest entry |
| `controlplane.PoolTunnelAuthorityConfig` | manifest entry |
| `controlplane.PoolTunnelDeployment` | manifest entry |
| `controlplane.PoolTunnelDeploymentCharge` | manifest entry |
| `controlplane.PoolTunnelDeploymentConfig` | manifest entry |
| `controlplane.PoolTunnelDeploymentPolicyCharge` | manifest entry |
| `controlplane.PoolTunnelDeploymentPolicyConfig` | manifest entry |
| `controlplane.PoolTunnelSigningRoute` | manifest entry |
