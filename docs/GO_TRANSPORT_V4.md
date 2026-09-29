# Go transport v4 assembly

The public `github.com/floegence/flowersec/flowersec-go/v6` package exposes the
original bounded transport v4 implementation through `TransportEnvironment`,
`V4Session`, immutable connection materials and explicit control-plane adapters.
All examples below use `fs` as the package import alias. The schema and provider
qualification gates in [TRANSPORT_V4_BINDING.md](TRANSPORT_V4_BINDING.md) remain
separate from API availability.

## Shared host components

Construct one `V4ResourceRoot` for every group that claims a shared budget.
`V4ResourceConfig` fixes the profile revision, finite dimension limits and
account, reservation and reference slot counts. Create accounts with explicit
`V4ResourceAccountKey` values; peer names never create an account. Every owning
constructor requires its corresponding `...Charge` reservation before it can
allocate or run. References move through their original `Take`/`Borrow` rules;
copying a handle does not reserve new quota.

Create a `V4Clock` from a qualified monotonic source and a `V4ClockProfile`.
`V4ClockRate` expresses an error ratio, so its numerator must be smaller than its
denominator. The source reports an incarnation and must report loss of its
continuity guarantee. Install trusted time intervals only from an independently
authenticated host or control authority. A wall-clock timestamp alone does not
qualify time. `NewV4Deadline` and `NewV4Age` retain unsigned millisecond caps.
The local adapter must be bounded and safe for concurrent calls. Clock, deadline,
window, delay and idle owners invoke it outside their own state locks. Concurrent
read completion preserves the newest published mark in the same continuous era;
a read below the frontier captured before that call proves rollback. A result
from a retired era cannot install a time anchor or restore an old deadline.
Adapter panic or abnormal task exit invalidates the original era. Contradictory
trusted envelopes invalidate previously captured wall samples without changing
the separate monotonic-only window policy. The original network refresh position
remains occupied through sampling, cancellation and actual completion.

Create one `V4VerificationNamespaces` for the physical Environment budget,
selecting `V4OnlineBootstrap` or `V4DurableRestore` before construction. Register
independent `V4NamespaceTrustStore` anchors and complete their corresponding
bootstrap or restore operation. An online nonce cannot establish absence of
rollback in a restored durable store. Refresh, retained history and credential
subscriptions remain owned by their original namespace.

Endpoint, preparation and retained-result authorization sample each distinct
clock outside their ownership gates. They then recheck the original owner,
current namespace and independent trust before any transfer. Concrete trust
reads, namespace publication and notification delivery use that same sample;
forked deadlines retain the parent's original cap and earliest projection.
Closing fences new transfers immediately and retains subscriptions through
actual in-flight sampling. A preparation or delivery creator that has already
transferred ownership cannot close its successor through a late read or abnormal
exit. Custom namespace trust adapters must still provide bounded local reads.

Online bootstrap owns its cancellation context and uses its admitted watchdog
to observe the caller and Environment. Caller context methods and clock reads
run outside the bootstrap gate. Close can fence setup before a blocked read
returns; retirement waits for actual setup, provider and watchdog exit. The
delivered namespace belongs to the Environment and does not inherit the
bootstrap caller's cancellation.

The live namespace also owns its local cancellation chain. It captures the
Environment cancellation signal outside State workspace locks and observes it
with the original watchdog. Provider contexts retain the Environment's values
and deadline. Context setup failure returns unpublished State and namespace
owners; a blocked context read retains the actual sampling and watchdog tails
through Close. Parent cancellation fences authorization even before the
watchdog runs. Abnormal namespace and refresh watchdog exits cancel their
original work and keep provider backing until the provider actually returns.

The root-shared `V4ApplicationExecutor` requires explicit ordinary, resident and
protected Completion capacities. Its `V4ApplicationExecutorCharge` includes the
qualified runtime allowance; no callback may create another free worker pool.
The Environment borrows shared dependencies without closing them.

```go
env, err := fs.NewTransportEnvironment(fs.TransportEnvironmentOptions{
    Config: fs.V4EnvironmentConfig{
        Positions: 8, Materials: 16, MaterialPools: 1,
        MaterialCreateMS: 10_000, RuntimeBytes: qualifiedEnvironmentBytes,
        Clock: clock, Verification: verification,
    },
    Reservation: environmentReservation,
    Dependencies: sharedDependencies,
})
```

Reserve `environmentReservation` with `V4EnvironmentCharge` for this exact
configuration. Runtime sizes, account limits and provider charges come from the
deployment's qualified profile rather than values copied from the example.
Services additionally configure finite result/query capacity and the shared
logical service registry.

Each admitted RPC Session protects one future short-result position in the
original Environment result table as well as the root result quota and
Completion service. Ordinary results cannot consume that position. Session
admission obtains it before spending; source, pool and static-material Connect
reserve it with their original Session graph before acquiring or attaching
material and transfer the same position into admission. Controller candidates
use this same preparation.
Closing a Session releases idle protection while completed, undelivered results
retain their independent result positions and backing through actual cleanup.

The short floor supplies a minimum opportunity. Concurrent short calls and
legal per-call envelopes larger than the floor may use fully charged general
capacity. They retain their trusted short classification, exact response limit
and complete payload; they do not duplicate the floor or borrow another future
Completion position without admission.

## Session plans and connection inputs

`V4SessionPlanFactory.Create` atomically reserves metadata, an original ordinary
task and future protected Completion responsibility. It captures the immutable
`V4SessionPlanConfig` without invoking application code. The authorization
callback later receives `V4AuthenticatedRequestContext` under the original
permit; it reserves and returns the same invocation's `V4ApplicationLease` with
its cleanup callback. Handler declarations are fixed before READY. Build a new
handler plan and application plan for each Session.

`V4ConnectOptions.Preparation` supplies the local carrier factory, exact
application profile and K, required guarantees, original deadline, bounded
Hello/establishment geometry, preauth backing, root, owner, tenant/session scope
and original application plan. Workspace reference fields are empty at this
entry point: the public assembly obtains the six source or four static/pool
workspace charges in one root batch. A `V4PoolSessionInput` or
`V4LiveSessionInput` supplies the separately admitted original durable spend
authority or authenticated control provider and workspaces. Exactly one is
required.

Every Connect path admits the same future Session resource graph before source
acquisition. It owns actual receive, execution, result, Completion and declared
dependency positions; final admission consumes those original positions. A
failed local admission releases its partial reservations without contacting
the source or durable spend provider. Closing an accepted attempt retains its
resources until the original source and candidate workers actually leave.

The same preparation captures actual subscriber positions in each known
revocation namespace. Static and pool material use their original verified
credential graph; the built-in direct HTTPS source uses its independently
installed Artifact and identity trust owners. Repeated dependencies share one
position in the same namespace. The caller's subscription reservation remains
untouched on local refusal and transfers only after Connect accepts ownership.
The final credential closure attaches to this same subscription object and
notification channel. Pool acquisition checks the actual selected material's
namespace owners before durable take; a changed, unreserved namespace does not
consume the pool item. Public live source wrappers and `ConnectSource` require
the provider's fixed namespace snapshot, so a complete subscriber graph is
reserved before `Acquire`. A provider-admission token may carry that same
snapshot when it owns the original source position; the token and its
namespace owners are then transferred together through cleanup. Providers
without this preflight remain usable only through component material APIs and
are rejected by the public live source boundary.

A complete source namespace snapshot also reserves the short result's and each
declared unary/streaming workload's independent delivery subscription slots
before acquisition. Verification binds the same source's credential closure
into those original floors without allocating another namespace reference.
Closing the Session leaves an attached result's original floor alive through
its actual independent cleanup.

Candidate metadata uses one protected reservation per configured parallel
position. Numeric retries reuse that position only after the previous carrier
has physically retired. They do not reserve another metadata owner or borrow
another Environment alias. Component callers reserve the first position using
`V4SourceCarrierCharge`; the shared preparation admits the additional position
before acquisition when parallel preparation is enabled. The built-in native
factories also admit their actual method positions, immutable policy references,
Environment aliases and separate TLS/socket/transport backing at this point.
One fixed endpoint uses one preparation position per Connect. Each position
reuses its original backing only after physical retirement, without acquiring
another root reservation or Environment alias between attempts. A stale
preparation cannot claim a later generation of the same factory position.

The candidate race keeps one original 30-second preparation window across
numeric attempts and winner replacement. Selecting a winner cancels other
methods and starts their fixed five-second cleanup windows. The source joins
those original methods before spending the selected lease. A cleanup timeout
returns `cleanup_incomplete`; unfinished provider tails remain charged and keep
their original Environment position until they actually exit. A new winner
cannot restart another candidate's cleanup allowance.

The signed session parameters come from the acquired material. Do not copy
parameters, feature grants or identity fields from an earlier connection.
`V4RPCServicesConfig` supplies immutable method registrations and exact canonical
contracts; its Session and crypto profile are filled from the actual material
inside the same aggregate admission.

`NewV4WebSocketCarrierFactory` supplies a native direct WSS implementation of
`V4ConsumerCarrierFactory`. Register one exact canonical public Route, its fixed
numeric endpoint, independent CA roots (CA mode) or signed leaf-DER pins (pin
mode), original clock and qualified provider options. Reserve
`V4WebSocketCarrierFactoryCharge` before construction. Connect reserves each
prospective connection's protected `websocket.Charge` under the preparation's
original tenant/Session accounts before acquisition, then transfers that backing
into native TLS/upgrade work. Direct component preparation obtains the same
provider charge before dialing. Use `AddressAttempts: 1` for this
fixed-endpoint profile; it performs no implicit DNS or retry.

The factory compares the complete registered Route with the original selected
candidate and digest, verifies TLS 1.3 over the trusted time interval, and
rechecks the actual verified peer window before activation. HTTP upgrade carries
no Flowersec credential. CA mode verifies the logical hostname/IP SAN; pin mode
uses the originally active, signed leaf-DER set without adding a CA fallback.
Origin, when configured, must belong to the signed policy. The application need
not implement a provider lifecycle adapter. `Close` fences future preparation;
returned carriers remain owned by their original Sessions and keep factory
policy backing until physical cleanup and retirement. `WaitCleanup` observes
those original tails. This factory does not supply local-loopback or tunnel
admission, listener setup, native QUIC, or WebTransport.

For multiple fixed WSS candidates, use `NewV4WebSocketCarrierSet` with up to 16
distinct `V4WebSocketEndpoint` entries. Its metadata reservation uses
`V4WebSocketCarrierSetCharge`; construction additionally reserves all child
factories atomically under the supplied original accounts. Set
`Preparation.Carrier` to the returned set. Each call dispatches only the exact
signed Route selected by the existing Connect owner; finite candidate racing,
winner selection and the single durable claim retain their original ownership.
Before acquisition, one source captures an actual free position and policy
reference in every registered route factory. Its one or two parallel candidate
positions reserve native backing once each and reuse it across alternative
routes; unused routes reserve no additional native connection. After final
winner selection and loser cleanup, idle positions are released before spend.
The selected provider keeps its original position, backing and Environment alias
until physical retirement. A set preparation uses one position per route, so
`ConnectionsPerRoute` also bounds simultaneously retained source preparations.
Closing the set fences new preparation, and its cleanup waits for the original
child providers to retire.

`NewV4QUICCarrierFactory` provides the direct native QUIC alternative through
the same `Preparation.Carrier` field. `V4QUICFactoryConfig` fixes one canonical
signed Route, numeric `RemoteAddress`, independently installed CA roots or signed
leaf-DER pins, original clock and finite `V4QUICProviderOptions`. Reserve
`V4QUICCarrierFactoryCharge` before construction. `DefaultV4QUICLimits` supplies
the protocol geometry; deployments still provide qualified runtime, provider
byte/task limits and native stream/connection positions. Use one address attempt.

The factory binds `flowersec-direct/4` to the exact signed direct leg. Raw QUIC
routes encode empty `path` and `subprotocol` strings and omit `origin_policy`.
Preparation verifies TLS 1.3 over the original trusted interval and opens the
maintenance stream without sending Flowersec credentials. It performs no DNS,
implicit retry, TLS resumption or 0-RTT. The Environment then follows the same
pool or live durable activation, Noise and dual READY owners. Native application
streams remain attached to the original charged QUIC connection. Reported
Session guarantees come from the actual admitted graph and current registry;
the existence of a factory does not establish deployment qualification.

`NewV4WebTransportCarrierFactory` uses the same native Session graph over a
dedicated HTTP/3 connection. Its signed Route fixes `h3`,
`/flowersec/webtransport/v4/direct`, an empty subprotocol and explicit Origin
policy. `V4WebTransportFactoryConfig` binds one numeric endpoint, the logical
signed host, TLS roots or DER pins, the original clock and finite provider
options. Reserve `V4WebTransportCarrierFactoryCharge` before construction.
Preparation permits only TLS, HTTP/3 CONNECT/SETTINGS and native association
bytes; Flowersec credentials remain behind the existing durable activation.
There is one WebTransport Session per native connection and no connection reuse,
address retry, TLS resumption, 0-RTT or capsule fallback.

Native WSS, raw QUIC and WebTransport factories and accepted entrances support
`direct_exporter` as an explicit fixed mode. Select `Hello.Policy.BindingMode = 0`
and `Hello.BindingModes = 1`, leaving `Hello.Policy.Exporter` empty. The SDK derives
the 32-byte value from the actual owned TLS 1.3 connection with label
`EXPORTER-flowersec-v4` and the original Artifact digest as context. WebTransport
uses the fixed `EXPORTER-WebTransport` wrapper, incorporating the actual CONNECT
stream ID. Caller-supplied exporter values are refused. Capability failure is
checked before irreversible spend, and the accepted peer independently derives
its own value. There is no fallback to `authenticated_context` or alternate
exporter mapping. Explicit authenticated-context selection remains available.

Use one of these explicit inputs:

| Entry point | Original input |
| --- | --- |
| `env.ConnectSource(ctx, provider, options)` | A fixed `V4ApplicationIdentity` and `V4MaterialLeaseProvider`; acquisition returns a verified lease. |
| `env.ConnectMaterial(ctx, material, options)` | One immutable material hosted through `env.CreateMaterial`; identity/provider/acquisition fields are absent. |
| `env.ConnectPool(ctx, source, options)` | An installed item from this Environment's preauthorized source; generation, identity/provider and material-allocation fields are absent. |

Create material with `NewConnectionMaterial` from an original verified lease,
matching immutable identity, material generation and `V4ConnectionMaterialCharge`
reservation. It never wraps an existing Session. The Environment claims a finite
material position before entering the `CreateMaterial` callback. Local refusal
preserves caller inputs. Once original preparation is admitted, the Environment
keeps its workspaces and application plan through real cleanup, even when the
Connect wait returns canceled without a Session. A canceled wait does not prove
that spend, provider work or material retirement has completed.

For an independent live control authority, set `V4LiveSessionInput.Control` to
`V4LiveControlConfig` and reserve `V4LiveControlCharge` in its `Buffers` field.
The SQLite store, authority, issuance, policy, guard and invocation fields are
absent in this variant, as is `Preparation.LiveIssuance`. The original prepared
winner and complete Session admission precede the control request. The trusted
`V4LiveAuthorizationProvider` receives only fixed public request fields and one
bounded proof output buffer; its backing is retained through actual return.
This explicit L1 path uses one physical attempt, with no hidden retry or fallback.
The adapter supplies authenticated control transport and authority-side logical
deduplication. `NewV4LiveHTTPSTransport` supplies the bounded consumer HTTPS
transport, using independently installed server trust, an explicit client TLS
identity and a fixed numeric endpoint. Reserve its transport charge and the
separate `V4HTTPSBootstrapCharge` before construction. Its one physical request
posts the `live-authorization-1` envelope to `<BaseURL>/live/authorize`; success
requires HTTP/1.1 200, `application/cbor`, a positive bounded Content-Length,
and complete original proof bytes. The server must authenticate and authorize
the client certificate. Redirects, compression and chunked responses are refused.
`controlplane.NewV4LiveAuthorizationCodec` provides the bounded server request
decoder; parsing never grants an issuance or activation capability.
Returned proof bytes pass the same signature, namespace, exact winner and
original Activate gate as the in-process authority. A late valid proof cannot
revive a canceled Connect. Both variants then use the original FSB/FSA, Noise
and dual READY path.

The reference live request is a canonical CBOR array in this exact order:
`["live-authorization-1", tenant, audience, crypto_profile, issuer_id,
lease_id, attempt_id, artifact_digest, client_identity_digest,
server_identity_digest, [candidate_index, candidate_id, route_digest],
activation_not_after_ms, physical_attempt_number]`. It is at most 1024 bytes.
The physical attempt number is exactly 1 in this conservative transport profile;
it is not a new spend key. The server resolves the original Artifact and frozen
authority projection independently. It must not authorize from the request's
identity or digest fields alone.

`controlplane.NewV4LiveAuthorizationHTTPSService` supplies the matching reference
server at `POST /live/authorize`. Its independently configured host binds the
verified TLS certificate to the tenant, client identity and audience, then
returns the retained original Artifact, activation plan, trust and deadline.
The service checks the complete request against that material and current full
State. It first reads the original durable proof: only an authenticated
`not_observed` result may proceed to new TxA. Spending, unknown and denied rows
never redispatch policy. TxA, the one policy invocation, TxB and original response
publication retain the same guard; restart can read exact committed proof bytes
without reviving the old execution right.

Reserve all five vectors returned by
`V4LiveAuthorizationHTTPSServiceCharges` before construction, plus the separately
owned native listener/header/connection budgets. The service supports direct
and tunnel plans, with one physical request position, a fixed aggregate rate
share and no queue. Tunnel plans retain both original leg Grants and publish
the server allow through their independently authenticated adapter before
returning initial client material. Close seals new requests and interrupts
body/publication I/O while actual host, policy, writer and store work retain
their original charges.

## Native WSS serving

Create `V4Environment.Serve` with a separately reserved `V4ServeCharge` and a
finite `V4ServeConfig`. The returned `ServeHandle` owns the ingress aggregate
and its Sessions. Each original ingress receives a random invocation/carrier
identity from this aggregate; applications cannot supply a detached admission
owner to `AcceptWebSocket`.

`NewV4WebSocketServer` owns one native TCP listener, static certificate chain,
canonical direct WSS Route and exact Origin policy. Its `V4WebSocketServerCharge`
reserves finite connection positions, bounded HTTP headers/timeouts and native
provider allowances before serving. It enforces TLS 1.3, HTTP/1.1, no TLS
resumption, exact Host/port/path and the actual local socket address. Pin-mode
configuration checks its actual leaf DER against the signed policy; CA-mode
configuration supplies independent roots. Certificate validity uses the shared
trusted clock. The server accepts only native `*net.TCPListener` ownership.

In that server's handler, call `serve.AcceptWebSocket(ctx, writer, request,
options)`, setting `options.Server` to the original server and leaving
`options.Upgrade` empty. Supply a fresh application plan, trusted bounded
`V4AcceptedMaterialSource`, original deadline, resource accounts, establishment
limits and SQLite AdmissionLedger authority. Its input workspace and admission
owner fields remain empty: the public boundary reserves the complete intake
batch and installs the original ingress identity itself. Material lookup sees
bounded unauthenticated Hello bytes; only the subsequent verified credentials
and application authorization can admit the Session.

The same call performs upgrade, signed route checking, durable admission,
FSB/FSA, Noise and both READY flights. The returned `hijacked` flag records the
actual native HTTP ownership transfer even on failure. Write an HTTP error only
when it is false. Cancellation may end Session admission early, but this call
still joins the original request/writer borrow before returning. After upgrade,
the provider retains policy backing through physical cleanup and retirement.

The native server, ServeHandle and shared Environment have distinct lifetimes.
ServeHandle Drain fences ingress and drains its original Sessions. Close the
native server to stop listener/HTTP admission and close its owned sockets;
`WaitCleanup` also waits for original handlers and retained policy borrowers.
Close and wait for the ServeHandle and Environment to retire their own children.
A Session ending never closes a shared listener, clock, key or durable authority.

## Native QUIC serving

`NewV4QUICServer` opens a finite native UDP listener for one fixed signed direct
Route and static certificate. Reserve `V4QUICServerCharge` with the exact
preauth accounts. Construction additionally reserves the listener's provider
allowance, and each connection is reserved before its native TLS work. The
server rejects dynamic certificate callbacks, resumption and wrong ALPN. Its
fixed local certificate must satisfy the signed CA or pin policy and shared
trusted clock. `Address` returns the actual bound numeric endpoint.

Call `server.Accept(ctx, entrance)` with the original deadline and initial frame
policy to obtain an opaque `V4QUICIngress`. This result is an accepted TLS owner,
not an authenticated Session. Pass it to `serve.AcceptQUIC(ctx, ingress, options)`
using the same entrance, root, Environment and exact account generations. Supply
a fresh application plan, bounded `V4AcceptedMaterialSource`, establishment
limits and SQLite AdmissionLedger authority. Leave the input's owner, entrance,
establishment, subscriptions and admission workspace fields empty. The boundary
reserves six admission owners together and obtains the ingress identity from
the existing Serve aggregate.

Before durable admission, the accepted provider compares the signed candidate
with its actual local/remote addresses, SNI, TLS version, negotiated ALPN and
fixed listener policy. The same original path receives HELLO and FSB, verifies
material, commits accepted admission, performs Noise and both READY flights,
then returns a public `V4Session`. Public `OpenStream` uses its authenticated
native stream dispatcher in either signed role; raw QUIC connection handles
are not exposed. Pool and live source profiles share this assembly.

An ingress is claimable once. Close and wait for an ingress that will not be
submitted. Once claimed, `AcceptQUIC` consumes it even on failure and retains its
actual native cleanup under the original admission owner. Server closure fences
new admission and joins pending accepts; established Sessions keep their own
provider retirement. Close Sessions and observe `WaitCleanup`, then close and
wait for the server/factory, Serve handle and Environment. The shared root,
executor, namespace, keys and durable store remain caller-owned.

## Artifact issuance and HTTPS publication

`controlplane.NewV4DirectIssuer` fixes verified client/server certificates,
direct or private-local candidates, profile, Session contract and revocation
policy. Its signing authority is separate from ordinary connection consumers.
Every issue generates independent nonzero lease, Session nonce and PSK values,
reserves the full durable issuance obligation before signing, and commits the
actual signed Artifact digest before publication.

`NewV4SQLiteDirectIssueAuthority` provides that durable gate in the original
SQLite transaction domain. Its immutable namespace/issuer/policy share comes
from current independently verified TrustConfig and complete State. The
configured rate, outstanding count and reserved State-byte limits are persisted
and shared by adapters using that store. Reopen, cancellation, failed signing
and uncertain commit do not restore issuance capacity. The host's access hook
authenticates the original request and authorizes both verifiers' complete
namespace read permissions; authenticated transport alone does not supply those
application rights.

`controlplane.NewV4ArtifactIssuer` also supports a fixed mixture of direct and
tunnel candidates. Each tunnel leg has its own independently installed Grant
issuer/policy and verified relay identity. Construction checks every candidate's
exact namespace closure, including the endpoint and relay role masks, against
the actual local namespace owners. The parent policy and validity envelope must
cover all required Grant and relay dependencies.
`V4ArtifactIssuer.NamespaceClosure` supplies the complete dependency set for
the durable authority's `V4DirectIssuePolicyConfig.Namespaces`. The authority
checks this complete set for every issuance, and its persisted immutable
configuration binds the set so reopening cannot omit or change dependencies.
The same SQLite authority implements `V4ArtifactIssueAuthority`; its durable
parent obligation is distinct from endpoint Grant issuance during live TxB.

`V4SQLiteDirectIssueAuthority.RetireMature` retires an original request only after
current authenticated full State and its Head establish a connection floor
strictly above its cohort, and trusted lower time passes the namespace's maximum
complete impact. It rechecks the exact evidence around the durable compare and
swap. Retirement releases the active outstanding/State reservations but preserves
the original issuance facts, digest and retirement proof in a replay tombstone;
the tombstone still counts against physical `MaxRecords`.
`ReadNextObligation` copies one bounded original row into caller-owned storage,
including retired rows. Enumeration is a publication input, not a coherent
complete-State snapshot or a signed State/Head publisher.

`NewV4DirectIssueHTTPSService` mounts one such issuer for one registered client
certificate at `POST /issue/direct`. The request body is the canonical CBOR
array `[request_id: bytes32]`, exactly 35 bytes. Its body cannot select an
identity, route or signer. Mount it on a separately reserved native TLS 1.3
listener with mandatory client verification, session tickets disabled, bounded
headers and finite connection/task capacity. The handler pins the verified
client certificate, checks trusted-time validity, admits one request position
without a queue, and applies its aggregate request rate before body work.
`V4AuthenticatedDirectIssueClient(ctx)` exposes the original mTLS fingerprint
to the authority's host hook, which compares it with the authentication envelope.

`NewV4ArtifactIssueHTTPSService` fixes the general issuer at
`POST /issue/artifact` with the same request, mTLS registration and bounded
publication contract. The constructor selects the endpoint; neither service
accepts a peer-selected issuer or falls back to the other endpoint.

The handler returns the complete signed Artifact with `application/cbor`, an
explicit Content-Length and `Cache-Control: no-store`. Refusals have empty
bodies. Close fences new work and interrupts actual body/response I/O; the
service retains its buffers and borrowed issuer until authority, signing,
publication and cancellation callbacks exit. It borrows the issuer and does
not close that shared authority. A request ID whose durable reservation was
accepted cannot be reused to manufacture another issuance after a lost reply.

`NewV4DirectIssueSource` is the matching consumer `V4MaterialLeaseProvider` for
ordinary `ConnectSource`. Configure the immutable client/server certificates,
their independent namespace trust, activation delegation name and exact
application profile/K before construction. Connect captures the source's actual
single acquisition position and reserves its separate lease output under the
original root/account generations before Acquire. The output's dependency and
first-material aliases are also admitted at this point. The opaque preparation
binds the source, generation and complete original request; another caller
cannot use its position or substitute an identity/requirement set. The source
verifies both identities before issuer I/O, sends one fresh random request ID,
then verifies the complete Artifact and activation-source
mapping against current trust. The returned lease owns its copied credentials
and survives source closure. The source owns no signing key or SQLite authority;
its caller separately selects the live authorization provider for Connect.
The original source position returns when acquisition physically exits; a
successful lease takes its output reservation and already admitted aliases.
Closing an idle preparation releases those inputs immediately, while closing a
running preparation cancels that original call and retains them through return.
Standalone component calls to `AcquireLease` reserve their output before issuer
I/O and cannot take a position already reserved by Connect.

Source, HTTPS provider and each returned lease have separate admitted charges.
Close interrupts the original physical request and keeps its buffers until
actual network/callback exit. Failed or uncertain responses do not trigger a
new request, a second issuer or automatic reacquisition.

`NewV4ArtifactIssueSource` uses `/issue/artifact`. Its immutable tunnel entries
name the original candidate index, endpoint role, Grant validation and relay
certificate/trust. They must cover every returned tunnel candidate for the
local endpoint. The source verifies the returned parent and derives each
pending Grant's issue/session bounds from that parent's original bounds. The
lease retains those exact expectations through source cleanup, preparation and
the actual TxB Grant check. `PreparationNamespaceSet` reports all actual local
namespace owners before issuer I/O; it does not sample time or acquire a new
credential permission.

## Retained original live Artifact material

`controlplane.NewV4LiveArtifactHost` connects general issuance with the native
live authorization service. Pass the same host as
`V4ArtifactIssuerConfig.Retention` and `V4LiveAuthorizationHTTPSConfig.Host`.
Its configuration fixes the authenticated client TLS certificate digest,
endpoint certificates and independent trust, activation delegation and signer,
per-candidate Grant signers/limits, relay identities, and application policy.
The durable issuance authority and SQLite live spend store remain independent
requirements. The host never substitutes its resident material index for either
durable ledger.

`V4LiveArtifactHostCharges` returns the material host charge and the charge for
one protected plan position. Reserve the host and `MaxArtifacts` separate plan
positions under the same Environment before construction. The host reserves an
original material position before durable issuance begins. Only after the
original issuance permit commits does it retain the full verified Artifact.
It checks the exact signed parent, endpoint identities, deadlines, policy and
union of all signed candidate namespace masks against the original issuance
facts before the issuer returns any client bytes. Secret material has no public
lookup or diagnostic export.

The first authenticated live request fixes the exact attempt, winner and
activation cutoff in that original position. The plan derives both Grant
scopes using the same parent issue/session bounds used by
`V4ArtifactIssueSource`. Its independent application policy runs once, only
through the original SQLite TxA dispatch. Further requests borrow the same
plan for the existing read-only material path; they cannot replace its winner,
regenerate Grant projections, or rerun the policy after an uncertain outcome.

For a tunnel, `V4LiveArtifactServerResolver` receives the fixed public plan
fields and a read-only `V4LiveArtifactServerMaterial` borrow before TxA. The
secret Artifact is for the independently authenticated server endpoint only.
The resolver joins authenticated material delivery and admission of the
server's original registration, then returns its exact incarnation and
publication configuration. The server may prepare its physical leg when the
first valid allow arrives. The server installs its own independent validation
for the supplied public Grant scope. This callback returns no permission to
activate: durable TxB, optional relay registration and the original server allow
publication still precede the client's first activation material response.
Duplicate material reads do not invoke the resolver or send another allow.

`CollectExpired` releases only idle local material at its original initiation
deadline. It is also attempted before reserving another issuance position.
Close fences all new work; active issuer, access, signer and server cleanup
tails retain their original positions through actual return. `WaitCleanup`
observes that completion. Local collection changes no durable issuance,
revocation or spend history. This host deliberately retains material only in
memory: process loss makes its old material unavailable and never reconstructs
the original authority's signing or allow dispatch from storage.

## Deferred server allow preparation

`NewV4TunnelServerAllowRegistration` admits one original material, candidate
and attempt before exposing its fresh recipient incarnation. Reserve all four
vectors from `V4TunnelServerAllowRegistrationCharges`: registration, recipient,
credential subscriptions and carrier. The configured admitting carrier factory
reserves its preparation position without carrier I/O. The server Runtime is
independent of the incoming physical HTTP request.

Pass the registration as the `V4TunnelServerAllowEndpoint` of the authenticated
allow service. The first valid original instruction atomically starts its only
Prepare dispatch; a later physical send may be that first arrival. It verifies
the exact request and Grant before preparing the public route and checks the
actual returned carrier identity before binding the allow. One duplicate may
join the existing execution; a failure or cancellation cannot start another
Prepare. The original bounded work window and deadline apply throughout.

`TakePrepared` has one passive observer position and transfers the original
recipient and deadline exactly once. Canceling that wait releases only the
observer. The returned recipient owns its preparation context until physical
adoption or cleanup, including backing needed from the original registration.
Close seals admission and cancels untaken work; `WaitCleanup` drives actual
physical retirement and retains charges while work or observers remain active.
Terminal disposition stays in the registration until Close. A new registration
always has a new incarnation and cannot accept the previous one's allow.

## Preauthorized pool and explicit TopUp

A pool has one `V4SQLiteTopUpJournal`, complete material decoder, original-key
identity restorer and `V4MaterialPool`. Create or open the journal explicitly
with its independent `V4SQLiteContinuity` and `V4SQLiteTopUpAuthority`.
`CreateV4SQLiteTopUpJournal` is only for an authorized new namespace;
`OpenV4SQLiteTopUpJournal` never initializes missing history. Persistent backing
survives closure, and `V4StorageFormatError.Projection` exposes only finite
refusal facts.

Use `env.NewMaterialPool` to register the original pool tails under the
Environment's configured `MaterialPools` and `Materials` limits. A
`V4PoolMaterialDecoder` verifies the reference `pool-material-1` bundle against
independent issuer and activation trust. `V4PoolIdentityRestorer` recovers the
persisted certificate and opaque provider locator; it must not substitute the
provider's current identity.

The issuer side can use `NewV4PoolBatchSigningIssuer`. It reserves one bounded
batch worker and a separate activation-plan position for every requested item.
Each item is issued through the original Artifact authority, then the issuer
verifies the complete preauthorized candidate set and fixed attempt budget,
constructs one immutable activation projection, and signs the proof plus both
tunnel Grants together. Direct candidates carry no relay pair. Tunnel entries
must carry both roles and the same parent, route, identities, pairing and
deadline; the complete bundle is size-checked before any bytes enter the TopUp
response. A failed or canceled item clears its private bytes and cannot be
re-signed by that plan.

Configure `NewV4PoolRelayFactory` with independent parent/Grant/relay trust and
the destination `SQLiteRelayAuthorityTable`. It verifies every returned pool
bundle against the original Artifact, proof, candidate set, activation
delegation, current revocation state and both role-local Grants. Only after the
complete paired projections are admitted does it construct the original relay
publication owner. It never signs, chooses a replacement candidate, sends a
server allow, or restores a lost publication owner. Closing an unfinished
publication removes only its exact unused reserved rows; committed public rows
and consumption history remain.

`NewV4PreauthorizedPoolSource` fixes source permission, immutable identity
snapshot provider, authenticated owner-proof provider, control transport, fence
key, clock, finite windows and observer cap. The source owns one control worker
and one unresolved durable intent. The reference `V4PoolHTTPSTransport` provides
independent cold-start control I/O using explicit TLS trust and a fixed numeric
endpoint. Its `V4PoolResultDecoder` validates the complete authenticated response
envelope. Reserve the transport, HTTPS provider and decoder charges separately.
Their dependencies retain all TLS/key/trust backing through actual method exit.

```go
result := source.TopUp(ctx, fs.V4TopUpOptions{
    DesiredCount: 4,
    MaxItemBytes: 65536,
})
if result.Handle != nil {
    observation := source.TopUpStatus(ctx, result.Handle)
    _ = observation // Inspect State, TerminalError and CallError separately.
}

recovered := source.RecoverPendingTopUps(ctx, tenant, sourceIncarnation)
for i := uint8(0); i < recovered.Count; i++ {
    original := recovered.Operations[i]
    _ = original
}

session, err := env.ConnectPool(ctx, source, options)
```

`TopUp` first durably records the exact intent and original identity, then sends
that intent. Concurrent calls join it. `installed` means the complete batch and
Applied frontier are committed; `acked` is a separate confirmed history
retirement result. `RecoverPendingTopUps` reads and reconstructs existing intent
facts; it does not invent a new append. `TopUpStatus` performs no control I/O.
Permission denial takes precedence over source availability and known history.

An expired or canceled wait preserves the original intent and operation handle.
Only explicit source `Close` cancels the worker. Neither pool acquisition nor
`ConnectPool` triggers replenishment or fallback. `ConnectPool` reserves the
Session position before acquiring/removing an installed material, then uses the
same carrier preparation, spend, Noise and READY owners as the other inputs.
After process recovery, `V4MaterialPool.RestoreInstalled` restores complete
untaken items with their original certificate/key reference.

## Live spend facts and original material

`controlplane.NewSpendReceiptService` borrows the original SQLite store, trusted
clock and independently reserved service/read capacity. The host derives
`V4LiveSpendReadAccess` from authenticated tenant, identity and audience context.
The request's lease identifier alone cannot authorize a lookup. One actual read
and response position shares a finite rate/burst limit and at most two seconds
of work. The response writer and row remain charged until their actual exit.

Standalone `V4SQLiteLiveSpendReadCharge` and `NewV4SQLiteLiveSpendRead` also
require the qualified `runtimeBytes` allowance. The read captures the parent's
deadline and cancellation signal during admitted construction. Its own reserved
observer and timer enforce the original read window while store or response
work runs; cleanup joins that observer before returning capacity. Cancellation
and ownership checks do not invoke parent context methods under a read lock.

`QuerySpendReceipt` reports only the lease/attempt, state, authorization outcome,
update time and query delay. `QuerySpendReceiptBytes` encodes that same shared
canonical CBOR map into caller-reserved output. Neither method constructs a
signed control response; the authenticated application or HTTPS response owner
still binds the original request and supplies its required signature.

`V4SQLiteLiveSpendRead.RecoverExpired` can end an expired spending intent as
`consumed/unknown`. `ReconcileAuthorization` can monotonically record a trusted
external `denied` or `authorized` fact for the exact original target. It cannot
generate material, dispatch policy or server allow, or infer `not_started`.
That last outcome requires the still-retained original authority invocation to
close its unused dispatch guard before an exact terminal CAS. Cancellation
after dispatch remains uncertain; a failed terminal write grants no new action.

Original commit owners retain a bounded cancellation observer through their
actual lifetime. Clock sampling runs outside the transaction gate, and each
publication rechecks the original deadline and time era at that gate. A separate
finite position handles independently delivered original receipts; the original
store task retains its completed result while those receipts race. Cleanup
keeps the original reservation until store, dispatch, sampling and observer
tails have all exited. Adapter panic or task exit cannot reopen a write or
dispatch guard. The invocation charge includes these overlapping tasks and the
observer and confirmation-backoff timers.

SQLite maintenance claims its batch position before reading caller context or
clock adapters. Its batch observer joins before returning that position, and
Close can cancel a batch while a clock or store adapter is still running.
Maintenance context, observer, worker and timer costs are included in its
construction charge. Every batch keeps the same two-second work window through
its scan and final recovery or retirement checks.

Original client material delivery is private to the authenticated control call.
It verifies the complete stored TxB and current access, then returns the exact
original proof bytes before their original hard deadline. It does not sign a
replacement or extend the deadline. The public receipt adapter exposes no
material getter. Maintenance keeps the original intent, definite outcomes and
required retention history independently of Session or Environment closure.

## Native WebTransport serving and datagrams

`NewV4WebTransportServer` owns a finite UDP/H3 listener, fixed signed route,
TLS identity, exact Origin policy and preauthentication account generations.
Reserve `V4WebTransportServerCharge` before construction. `Accept` obtains an
opaque `V4WebTransportIngress`; `serve.AcceptWebTransport` performs original
material verification, durable admission, Noise and both READY obligations.
Unadopted ingress must be closed. Listener, ingress and Session cleanup retain
their respective original native tasks and stream positions through real exit.

With the signed datagram feature selected and `Core.Datagrams` configured,
raw QUIC and WebTransport `V4Session.UnreliableMessages` expose the existing
carrier-neutral `UnreliableMessageChannel`. `MaxMessageBytes` reports only the
current local submission payload cap (949 bytes for the standard 1024-byte
envelope). A smaller observed native MTU is retained; it grants no retry.
The two crypto directions and receive queue have separate admitted backing.
The 64 send positions include pending, encrypting, cancelled-but-running and
provider-retained tails. Expiry is checked before budget and before submission.
An `accepted` result means local provider submission, never remote delivery.
Rekey, cancellation, queue rejection and MTU changes never replay a message.
Receive rechecks the original authorization and epoch at application handoff;
`temporarily_blocked` and `receive_disabled` retain their explicit error codes.

The local Go tests exercise direct native pool/live establishment, both Noise
profiles, CA and DER pin verification, bidirectional public Streams, datagrams
and cleanup. Browser interoperability, provider tail qualification, full
reference-profile load and deployment certification are separate remaining
qualification work; these constructors do not assert those results.

## Service operations and response publication

Bind a service to one `V4Session`, or call `PrepareUnary` with an exact installed
contract digest and trusted local codec/decoder. Prepare fixes input and
deadlines. Start joins the same original operation and returns `NotAdmitted`
separately from an admitted operation that later fails. `Status`, `Progress` and
`WaitStatus` do not infer remote execution from local send acceptance.

Method-bound preparation chooses `V4OperationOptions.ResponseLimitBytes` when
nonzero or when `ExplicitResponseLimit` is true, then the method's
`DefaultResponseLimitBytes`, and finally the exact contract maximum. Set
`ExplicitDefaultResponseLimit` to configure a zero local default. Both explicit
zero and an omitted value retain their distinct meaning. Fixed/bounded limits
are validated before encoding, with `ErrResponseLimitUnsupported` for an invalid
selection. Bind and Prepare reject an invalid local default even when a call
supplies an otherwise valid override; they never clamp or replace that default.
Direct internal route preparation already receives a fully selected limit.

The request and result-receive deadline projections are captured during Prepare.
Start inherits both original projections, including the separately configured
receive grace, so a narrower clock anchor cannot renew either local deadline.
The preparation lifetime also survives local Start admission until the first
request header is actually accepted. Execution method preparation captures one
installed exact Offer; supplied bounds must match that real snapshot. It does
not merge windows, query for a replacement, or renew an older operation.

`V4ServiceClient` borrows one fixed Session or one Controller and owns a finite
mixed unary, streaming and notify method table in the Environment's 64-entry
service index. `BindMethods`
accepts a trusted namespace and method definition; `BindUnaryService` restricts
that same owner to unary descriptors. Selectors carry the namespace and nonzero
type ID. `InitialMethods` omitted installs every method. A nonempty subset
reserves all descriptors and their exact static route references, but installs
only the selected snapshots. Empty, duplicate, unknown, and foreign-namespace
selectors fail before work. An uninstalled method returns `not_ready` before
encoding. `MaxBoundMethods` defaults to 256 per Environment; constrained
composition selects 16. Aggregate counts retain closed bindings through their
actual cleanup. The original single-method convenience entry uses this same
owner and implementation.

Handler registrations can borrow exact subsets through `Dependencies`.
`NewV4ServiceDependency` takes a local alias, an existing `V4ServiceClient`, and
namespace-qualified `V4ServiceDependencyMethod` selectors. Each method defaults
to `V4RequiredForDispatch`; `V4OnUse` allows the application to enter without
that dependency being ready. Declarations are limited to 64 aliases and 256
method references per registration, with copied selectors and real references
charged to that registration. They reuse the client's original method slots,
source identity, contracts and renewal owner. Unknown modes, duplicate aliases
or methods, foreign namespaces and impossible simultaneous stream demand fail
registration. Optional uninstalled descriptors do not create extra bindings.
Registration construction reserves its original position and backing before
borrowing clients outside host authority gates. Close can seal that position;
the final registration gate rejects late construction without publishing it.
Selecting a view retains its actual application origin and the registration's
borrowed clients until that call returns. Registration Close seals new selection
but cannot clear a selected call's clients early. An initializer whose origin
and registration share the same primary uses one alias for that responsibility.
Ordinary registrations preadmit view reference slots for each borrowed client's
generic call table and distinct declared workloads. Repeated aliases of the
same client/method share that promise. Selecting a view reuses those original
slots for the actual application origin and registration; it cannot acquire an
extra root reference when the slab is full. Shared aggregate metadata stays
charged as a whole through every component's actual lifetime. Initializers
retain their separate pre-Acquire Controller reference allowance.

`V4InvocationServiceFromContext(ctx, alias)` returns the restricted invocation
view. Its unary, streaming and notification preparation and convenience methods
use only the declared selectors. It provides no Bind, Refresh, UpdateContract,
Close or Controller controls. Use the original callback context or a child
context; an escaped view cannot create work after the callback exits. Closing
the declaration seals new work without closing the borrowed service. Explicitly
transferred operations retain their own original ownership and publication gates.

Service call admission retains its actual generic or workload position before
deriving the caller context outside the binding lock. Close fences that pending
setup, and abnormal context methods return the same original position. A late
setup cannot begin encoding after the binding has closed.
Each position also includes an explicit cancellation context and observer task
in its original charge. The observer reads the caller's cancellation error and
cause outside SDK gates and preserves its original deadline, values and cause
for descendants. A caller without a cancellation signal starts no observer.
SDK child registration and Close touch only local state; they do not register
an opaque-parent cancellation relay. A blocked or abnormal parent read retains
its original position through actual observer exit, even after the caller has
returned. Controller workload reselection transfers this same cancellation
owner into the already admitted replacement position.

Before ordinary task admission, unary and streaming dispatch reject missing
required dependencies locally. Notification observation waits in its existing
bounded input queue without occupying ordinary ready/running positions; its
original deadline and overflow policy still apply. Every application entry
rechecks required readiness before the first decoder or handler. On-use misses
do not block these entries. An actual invocation call still requires its precise
contract, applicable Offer and accepted RPC/NOTIFY path or exact empty streaming
pool entry before encoding. It uses try-now admission, performs no implicit
query, OPEN, acquisition, retry or pool replenishment, and tolerates a legal
rekey ticket freeze without treating the existing path as structurally absent.

The streaming pool shares eight positions per Session and two per
service across methods and digests. Pending and closing entries keep their
positions until real cleanup. Each accepted empty entry has one 30-second
monotonic idle window; checkout cannot renew it or the original operation
deadline. Required declarations across registrations and service clients share
one bounded capacity check in their source Environment; repeated exact targets
share demand. Explicit pending, accepted and closing pool entries participate
in that same capacity calculation. Only an unclaimed exact live entry satisfies
a required target; closing or checked-out entries keep their physical cost while
a replacement needs its own position. Explicit preaccept, dependency registration,
contract installation and current publication share the capacity gate.
The Environment coordinator installs required static descriptors
through their original binding update and prepares missing RPC/NOTIFY channels
or an exact empty streaming pool entry. Accepted pool checkout creates future
replenishment demand only while a required declaration remains live. Pending
preparation shares the original channel/pool owner, never an application permit.
An unavailable path retains one fixed preparation deadline; polling does not
extend it. Missing required remote snapshots on an existing current or fixed
Session use the same original query protocol and method update flights, in
batches of at most eight. The currently declared initial set shares one deadline
across its batches. Partial denial preserves independent successful methods;
closing the declaration revokes late installation and retains actual query
cleanup. Optional descriptors create none of this work. Replacement candidates
use the original Controller attempt to query and stage their own authenticated
exact snapshots and Offers before publication.

`V4ConnectionController.BindMethods` and `BindUnaryMethods` use the Controller's
existing accepting current. They capture the authenticated logical endpoints
and trusted application mapping and preserve full canonical snapshots in
charged binding backing. New work selects only that Controller's current and
requires its own exact registration, Offer and resource admission. Missing
current fails locally before encoding; another logical target seals the binding.
The binding does not retain a retired Session's registry or Session accounts.
Closing the binding closes its convenience scopes without closing the borrowed
Controller or explicitly transferred operations. Queued unary uses the original
bounded pre-header reselection; prepared streaming and notification operations
retain their selected Session. No binding entry acquires connection material.

`Contract` reports the installed digest, generation, pending target, and actual
Offer readiness. By default, `Refresh` uses the admitted static registry and
returns independent method outcomes. `UpdateContract` approves
one future exact digest and preserves every existing prepared operation. The
same target joins one update; a different target fails with
`ErrContractUpdateInProgress`. Joining observers can cancel only their own
waits. The original context, authorization, registration, Prepare capture and
Close fence installation. Static reads share the Environment's finite contract
work bound with remote acquisitions and never acquire a connection.

For Controller bindings, static reads use the selected current's registry and
installation is fenced against current replacement. Updating across registries
compares the original method/schema identity and, for bounded policy, every
unapproved canonical field. Failure preserves the existing snapshot and local
response default. Snapshot availability and actual current dispatch readiness
are separate facts.

`V4ServiceBindOptions.ContractSource = V4ServiceContractsRemote` obtains the
selected methods through the existing authenticated ordinary query channel.
The entire definition and maximum snapshot backing are reserved first, including
unselected descriptors. Initial acquisition returns the client only when every
selected method passes the final common authorization, registration, Offer and
deadline gate. Explicit `Refresh` batches at most eight methods, preserves
partial outcomes, and `UpdateContract` queries the explicitly approved digest.
All batches fork the same original trusted deadline. A complete installed
canonical body supplies conditional queries; both successful response variants
copy into the original method snapshot. Unknown local variants cannot install
methods or handlers. Per-target refusals distinguish `ErrV4ContractDenied` from
`ErrV4ContractUnavailable`. Current method/schema identity, bounded acceptance and
response defaults remain mandatory. Offer installation retains distinct old
windows, accepts a valid future window as time-pending, and captures the selected
window in each new prepared operation. Environment acquisition positions are
claimed before candidate work and transferred to their query workers. Same-target
joins do not publish another query, and cancellation or Close retains the method
and service through actual query cleanup. Exact transient and observation
Refresh returns the installed local snapshot without sending a query.

Each binding preadmits four explicit refresh positions, including their
cancellation contexts, observer tasks, and timer channels. Each observer uses
the original trusted deadline for every wake and does not register with an
opaque caller context. Close cancels only SDK state; a blocked caller or clock
read retains its actual position until it exits. Static installation captures
its caller signal and SDK invocation identity outside owner locks and creates
no cancellation task. Contract reads, joined observers, and batch installation
return their original visits on panic or abnormal task exit. An abandoned batch
settles only its own original method updates and retains any real query tail.

Remote bindings can set `OfferRefresh: V4ServiceOfferRefreshManaged` with an
explicit `V4ContractRenewalPolicy`. The policy supplies qualified complete-batch,
join, whole-round suspension and trusted-time error bounds, plus the source's
guaranteed minimum remaining Offer window. These are trusted deployment inputs;
peer timestamps and measured query latency cannot establish them. Initial Bind
and each later execution installation qualify the complete Environment set
before publishing the new responsibility. Short Offers remain legal through
the static and explicit paths. Transient-only managed bindings reserve no
renewal opportunity, and uninstalled descriptors do not trigger background
queries.

The original Environment coordinator selects exact installed execution targets
by expiry, with persistent rotation for ties and batches of at most eight. All
bindings share one of the original Environment acquisition positions and one
complete protected output; each participating Session protects one original
Q2 vector and fixed worker index. Shared output bytes are charged once at the
root and fully against each actual Session scope. No method adds a goroutine,
timer, query engine or connection. A round retains one absolute deadline across
batches and bounded backoff. Exhausting that deadline leaves a local blocked
renewal result; an explicit successful Refresh can restore the responsibility.
`Contract.ManagedRenewal` and `Contract.RenewalError` distinguish renewal state
from current Offer usability. Controller replacement acquires its candidate's
real renewal vectors before current publication. Old active queries and outputs
retain their source scopes until physical exit. Closing the last execution
binding withdraws unused future protection without refunding live tails.

Methods may require execution or durable execution through immutable
`RequireExecution` and `RequireDurable` configuration. Bind validates every
descriptor, including unselected initial methods. Direct preparation rejects
an incompatible variant before application encoding; a per-call option cannot
weaken the method's configured guarantee.

`V4RPCServicesConfig.Workloads` accepts `V4SessionMethodWorkload` targets for
complete Session assembly. Each fixes the trusted namespace, method descriptor
and `V4ServiceMethodWorkload` before material acquisition. The existing
`V4RPCServicesRequirements` includes these operation/result/Completion vectors;
complete Session admission additionally includes their actual streaming
transport, receive and native ownership. These targets share the Session's
existing tables and baseline services. They do not create remote reservations
or occupy running application workers while idle.

Pass matching `V4ServiceBindOptions.Workloads` when binding the service. Bind
takes the Session's already admitted matching target when available; otherwise
it must acquire the complete additional vector before publishing the binding.
The method type must belong to that definition, targets must be unique, and an
explicit empty recipe list is invalid. A missing list adds no workload target.

```go
method := definition.Methods[0]
recipe := fs.V4ServiceMethodWorkload{
    Type: method.Type, Calls: 4, RequestBytes: 1024,
}
rpcConfig.Workloads = []fs.V4SessionMethodWorkload{{
    Namespace: definition.Namespace, Method: method, Workload: recipe,
}}
// Use rpcConfig in the original Session assembly, then bind that Session.
client, err := session.BindMethods(ctx, definition, fs.V4ServiceBindOptions{
    Workloads: []fs.V4ServiceMethodWorkload{recipe},
})
```

`Calls` counts positions still held by prepared, accepted, decoding or
undelivered work, including real cleanup tails. `RequestBytes` bounds this
recipe's input envelope. Codec output and scratch use the descriptor's separate
maximums. Unary response and streaming item limits use normal method/contract
selection; set `ExplicitResponseLimit` to distinguish an explicit zero limit.
Notify recipes reject either response-limit field. Legal calls outside the
declared envelope may use actual ordinary capacity; the recipe neither truncates
them nor changes their contract. Streaming targets retain their exact kind and
metadata and remain subject to the original per-service and Session pool limits.
Each workload call also reserves actual parent-reference positions in the root
slab before acquisition or successful Bind. Preparation, Start, independent
results and their bounded consumers attach those positions to their actual
application ancestors at runtime, up to the existing eight-ancestor limit.
Unary calls cover preparation, Start, the result and four result observers;
streaming covers preparation, the result and its single item reader; notify
covers preparation. A returned position can retain a different actual parent
on its next generation, without searching for a free root reference. Source
authority and account fences still apply. A call position is reusable only
after every previous parent reference returns. Transport Close retains capacity
for independent accepted results until their real result and decoder owners
exit; closing the Environment still fences new use.
Component-only `InstallRPCServices` cannot accept these Session assembly targets.
Automatically qualifying all existing binding recipes before replacement
acquisition and deployment-wide workload profile reports remain incomplete.

`V4Session.QueryServiceContracts` reads one to eight explicit
`V4ServiceContractTarget` values through an existing ordinary RPC channel. The
original fixed query worker, Session query capacity, Environment acquisition
position, deadlines and authenticated publication gate remain responsible for
the entire request and cleanup. Targets may specify one approved digest and a
locally trusted Offer window cap. A `Known` snapshot plus `KnownIndex` supplies
an SDK-validated conditional baseline in the same Environment; arbitrary known
digests do not substitute for complete canonical bytes. `V4ContractQuerySnapshots`
owns the returned batch. Use `Count`, `Item` and `CopyCanonical`, then `Close`.
Both full and unchanged successful responses own independent canonical bodies;
closing a baseline cannot reclaim a query's live borrow. These reads do not
install or approve a service contract, execute business work or renew an operation.

Per-method acceptance defaults to exact. An explicit bounded policy permits up
to four unique closed ranges for history retention, unary execution result
retention, and response minimum/maximum. It checks the complete canonical
variant, forbids absent fields and unsupported ranges, and compares every
unlisted canonical field on updates. Explicit digest approval cannot bypass a
bounded policy. Existing response defaults remain unchanged and must be legal
under every installed candidate; short work must fit the configured response
floor. Candidate routes coexist with current and prepared routes under actual
resource reservations before installation. Explicit remote `Refresh` on an
installed bounded method checks the current advertisement under those same
rules; exact execution bindings query only their approved digest.

`Close` cancels preparation and convenience `Call`, `StreamMethod` and
`NotifyMethod` scopes; explicit handles returned by preparation or a successful
stream start keep independent ownership. Up to 32
concurrent preparation/call positions include original network and decoder
tails. `CleanupStatus` and bounded `WaitCleanup` observe actual exit without
closing the borrowed Session or Environment. Full generated typed capability
views, full deployment qualification of managed
renewal across independently authenticated Sessions, remote variants outside
the finite trusted registry, and full deployment qualification of independently
authenticated Controller replacement remain incomplete.

`PrepareStreaming` and `PrepareStreamingMethod` encode the original request
once and capture the trusted stream kind and metadata without opening a stream.
`StreamMethod` prepares and starts that same operation, then transfers the
handle. Before transfer, a failure closes the private operation and returns
`StreamingStartError`, retaining an already created execution reference and
the current cleanup fact. `ReadNext` and `ReadNextEncoded` share the original
item owner; `Items` closes it when iteration exits. `WaitStatus` observes only
status, and `WaitCleanup` never closes the operation implicitly.

`PrepareNotify` and `PrepareNotifyMethod` have no response decoder. Preparation
finalizes the encoder's original output exactly once; `NotifyMethod` starts it,
waits only for local submission, and closes its hidden handle on every exit.
`NotificationResult` reports that submission and cleanup, plus a query-only
reference for execution notifications. Observation notifications have no valid
execution reference. `Result` also preserves an existing execution reference
and original submission facts on success, cancellation and failure. A result
already handed off by the original result owner survives late cancellation.
Neither result value retains a Session, credentials or a hidden operation.

`NewV4StreamRegistration` adapts a trusted server handler into the original
preinstalled streaming dispatcher. The handler receives authenticated request
context and bounded input; `V4StreamingResponse.SendItemEncoded` applies the
original item limit and backpressure. Returning from the handler lets the
dispatcher publish the terminal output. These dynamic operation handles still
expose reference methods that reject unsupported semantics at runtime; the
generated statically restricted capability surface is not yet complete.

TakeResult and TakeEncodedResult share one result-consumption right. Typed
decoding starts only through the original Completion service, once. Waiting
cancellation leaves the same result owner alive. AbandonResult discards output
interest; RequestCancel uses the existing authenticated business-cancellation
management path. Opaque operation references grant query/cancel location,
without granting a new Start or invocation.

`PrepareUnaryAndSave`, `PrepareStreamingAndSave`, `PrepareNotifyAndSave` and
the corresponding ServiceClient `Prepare*MethodAndSave` entries validate the
exact configured reference domain and same-Environment store backing before
encoding. They require execution semantics, prepare once and invoke the supplied
`OperationReferenceStore` once on the original application executor. Only
confirmed durable persistence followed by a current authorization/lifetime
handoff returns the original unstarted handle. `OperationReferenceSaveResult`
separates the query locator, whether the store was entered, and its confirmation
fact. Cancellation, provider error, panic and late confirmation never recreate
Start. An uncooperative store retains the original operation and binding charges
through its actual exit.

`OperationReferenceCodec` imports and exports canonical query-only locators for
one explicitly expected local domain. Reserve its exact charge before creation.
`CreateV4SQLiteReferences` and `OpenV4SQLiteReferences` provide bounded durable
reference storage with independent continuity validation. Configure finite
record count, encoded bytes and retention; duplicate exact saves do not renew
retention, and a conflicting value under the same identity is rejected.
`Collect` explicitly removes expired records. `List` copies at most 16 entries
into caller-owned output without an unbounded enumeration queue. Close fences
new work; `WaitCleanup` and `Retire` preserve the provider's actual exit.
`NewV4SQLiteReferenceStore` supplies the matching application-store binding.
This persistence path stores query locators, not payloads or a replay outbox.

`PrepareResume` captures one already accepted, unused target `Stream` in the
same Session using a trusted `V4ResumeMethod`. Its exact registered contract must
be durable unary execution; the application-resume feature and signed policy
must be enabled. The method ordinal and transport context/stream ID are derived
internally. Preparation borrows that target's message qualification before
fixing the new operation ID, request digest, original Offer and deadlines.
`Resume` calls that same preparation and Start path. Both return the existing
`OperationHandle`; typed Take returns `V4ResumeResult` in `Result.Value`, and
encoded Take consumes the same single result. The accepted/rejected/unknown
recovery decision is separate from local operation completion and submission.

`V4ResumeCodec` imports canonical signed/MAC token syntax and decodes result
values using an explicitly reserved workspace. Import does not authenticate a
token. The receiving application service independently verifies the recovery
key, caller permission, original history and atomic token/generation change.
`PrepareResumeAndSave` uses the same persistence gate and additionally rechecks
the original target before handle delivery. A persisted reference cannot bind
another target or restore Start authority.

Server recovery assembly uses `CreateV4SQLiteExecutions` or
`OpenV4SQLiteExecutions` with explicit continuity, limits and original backing,
then `NewV4DurableExecutions` for the shared execution history.
`V4DurableServiceBinding` connects that history and an independently provisioned
`V4RecoveryVerifier` to the existing service registry. The verifier freezes at
most sixteen recovery keys; `ImportV4RecoveryMACKey` creates a charged opaque key
owner, while signature keys retain their explicit signer backing. Session keys
cannot substitute for recovery authority. `NewV4ResumeRegistration` selects the
original SDK recovery handler; its configured `V4ResumeStreamBinding` fixes the
accepted stream entrance. `V4ResumeCodec.CaptureCheckpoint` copies an application
checkpoint into bounded canonical backing, and `V4UnaryResponse.IssueCheckpoint`
uses the same durable history and generation transaction. These assembly APIs
do not independently authorize token consumption or expose an arbitrary target
constructor.

An application first retains the actual business checkpoint, then issues its
token through a separate authorized durable unary operation. `IssueCheckpoint`
commits that invocation's result; return from the handler without writing a
second response. The caller receives the canonical token through ordinary
result consumption. Later `ReadOperationResult` calls read those same stored
bytes and do not issue another token or renew its expiry. Pass that token to
`PrepareResume` on the accepted target, then inspect the explicit recovery result
before using the Stream for application traffic.

Build the application plan with its raw Stream handlers before the Session core
claims that handler plan. Register the recovery method and its exact kind,
contract, durable history and verifier before READY. Restore admission offers
from the store's original registration; creating a fresh offer window in only
the network route does not extend the store's admission window. The raw handler
runs after a confirmed accepted recovery and reads the committed checkpoint and
generation through `StreamOwnership.RecoveryProgress()`. Its Stream can then
carry ordinary application bytes. Execution and result joins retain any earlier
Stream or Session deadline without rewriting the operation's wire deadline.

The original recovery worker sends once and reads exactly one response boundary.
It validates the response before making it consumable, then returns the borrowed
message qualification to the same Stream. Complete results retain their existing
charge and authorization after transport detachment. Take cancellation ends
only that wait; submitted Close/Abandon retain the original bounded late response
and cleanup responsibility. Closing a completed handle leaves the caller's
target Stream usable. Submission reports actual queue acceptance and does not
infer provider flush or remote token consumption.

For `restart_flush`, reserve `V4MaintenanceOwnerCharge(maxObservations,
runtimeBytes)` in the original Environment, create `NewV4MaintenanceOwner`, and
inject that same owner into `V4SessionPlanConfig.MaintenanceOwner`. It belongs to
the application's existing Runtime lifecycle and can serve plans in either
connection role. The observation capacity is finite (1–64); registration rejects
a missing, closed, or foreign owner before publishing a restart method.

A unary request exposes one stable `ResponsePublication` before the handler
runs. `MaintenanceOwner()` borrows the injected capability; `TransferTo` accepts
only that owner, once, before the handler returns. Each pending observation
reserves a slot before application entry. Transferred compact observations keep
their slot until the maintenance owner closes.

`flushed` means the original response's exact final bytes reached the local
carrier/provider handoff. The observation is settled from the original record
writer, before physical cleanup; a subsequent publisher failure cannot reverse
it. Reply-slot release and queue admission alone do not prove publication.
Timeout, STOP_OUTPUT, replacement SDK responses, and pre-handoff publisher
failure leave the original response unknown. `Wait` cancellation ends only that
wait. Maintenance `Close` ends observation rights without changing the original
publication outcome; `WaitCleanup` joins the actual remaining response and
observer responsibilities. Neither transfer nor a flushed result restarts the
application or proves peer receipt.

## Namespace State and Head publication

The server-only `controlplane` package provides one durable publication owner
per complete namespace. Create a `V4SQLitePublicationStore` only for an
authorized new namespace; reopen an existing one with
`OpenV4SQLitePublicationStore`. Reserve `V4SQLitePublicationStoreCharges` in the
same Environment before either operation. The configuration fixes the namespace
scope, trusted clock and TrustConfig, independent mutation/read authorization,
bounded authentication input, and complete State/Head history capacity. The
host's SQLite continuity authority remains responsible for rollback detection.

`ReplaceState(ctx, expectedVersion, wire)` compares and replaces the complete
canonical RevocationState in one transaction. Mutation authorization does not
grant namespace visibility. `ReadPublished` checks complete-namespace read
authorization and returns an immutable published State/Head pair into bounded
caller buffers. Updating the authority State does not expose an unsigned or
partially published snapshot to consumers.

Reserve `V4NamespacePublisherCharges` and construct `NewV4NamespacePublisher`
with the independently authorized Head signer. The trusted host calls `Publish`
on its chosen schedule; consumer refresh requests never trigger signing. Each
job first captures one fixed State and reserves its complete publication/history
position. Ordinary later mutations can proceed without changing that captured
job. Emergency trust changes, signer retirement, deadlines and Close fence the
final durable commit. A fresh Head may reuse unchanged State content. Occupied
unexpired history cannot be evicted to make room for another publication, and
uncertain commits do not return an invented successful publication.

`NewV4NamespaceHTTPSService` exposes `/head`, `/state`, `/trust` and nonce-bound
`/bootstrap` to one explicitly authenticated complete-namespace reader. Its
configuration retains the exact client certificate, an independent bootstrap
root signer, work deadlines and request rate limits. The deployment supplies the
native TLS 1.3 mutual-authentication listener and its bounded connection/header
resources. TLS identity and application namespace visibility are separate checks.
Close admission first, then use each service, publisher and store's
`WaitCleanup` before releasing its dependencies. A running signer, database
operation or response writer retains its original reservation until actual exit.

## Fixed-upstream proxy on v4 Streams

Create `NewProxyServer` with the trusted upstream, address ranges, header policy
and finite limits. `ProxyServer.V4StreamHandlers(authorize)` returns the HTTP and
WebSocket entries to install in a `V4StreamHandlerPlanConfig` before READY. The
required callback authorizes that specific upstream using the original
authenticated application binding and Stream metadata. It must not derive that
permission from a content-supplied hostname. Each handler uses its actual v4
Stream ownership, resident executor work and the ProxyServer's shared concurrency
limit. Original raw receive credit is replenished only within the admitted
window as bytes are consumed.

The proxy application uses version 2 canonical CBOR metadata inside length
prefixes. HTTP body chunks terminate with a mandatory, separately bounded
`ProxyBodyEnd`; EOF alone is not a successful terminal. Native HTTP trailers
remain separate fields, and repeated permitted values preserve their order and
original octets. Header framing is validated before hop-header or application
filtering. Input Content-Length remains an integrity assertion even when removed
by Connection, while the native transport chooses output framing. Responses keep
their content-coding labels and stream their original coded bytes.

Numeric upstreams pin the exact normalized address. DNS upstreams additionally
require `AllowedUpstreamAddresses`; the whole result must match before any
numeric dial. HTTP and WebSocket share that policy and verify the connected peer
before request publication. HTTPS retains the logical hostname for identity
verification. Redirects and ambient proxy settings cannot select another target.
The Go HTTP/1 pool does not replay an uncertain request on a failed connection.

These APIs provide the implemented transport and fixed-upstream application
path. Managed credential associations, Surface Clear/fence/install composition,
and complete Environment/tenant resource accounting have separate owners and
are not provided by a bare ProxyServer registration.

## Connection Controller

`V4Environment.NewConnectionController` creates an optional long-lived connection
owner in the existing Environment. It owns at most one current, one candidate,
and one retiring Session. Configure a trusted `V4ControllerSource`, a nonzero
`SourceIncarnation`, the original `Clock`, finite attempt and drain deadlines,
and qualified runtime bytes in `V4ControllerOptions`. Reserve the three separate
vectors returned by `V4ControllerCharges`: Controller metadata, initializer task,
and initializer Completion. The last two are zero without `InitializeSession`.
Construction starts no material acquisition or carrier connection.

Each `PrepareConnection` invocation supplies a fresh `V4ControllerPreparation`:
the `V4SourceConnectConfig`, exactly one Pool or Live spend input, and optionally
the original installed `V4PreauthorizedPoolSource`. Keep all six connection
workspace references empty; the public adapter allocates them as one same-root,
same-tenant/Session batch. The Controller then reserves the complete candidate
admission vector before material acquisition. A source prepares only local
inputs; it must not acquire a lease, dial, or perform application initialization.
A nonnil preparation transfers cleanup responsibility even when returned with an
error. Pool sources are borrowed; replenishment remains explicit `TopUp` work.

For an existing Controller binding, each declared method workload is projected
into the candidate recipe before acquisition. A compatible unclaimed factory
target supplies its original backing; independent bindings receive distinct
targets. The candidate reserves operation, result, streaming and unary
Controller dispatch positions while the previous Session retains its full
responsibility. Additional source snapshot bytes stay charged until the source
worker actually exits. READY qualification redeems the exact reserved target
and cannot allocate a replacement on a miss. Changes to the captured dependency
revision invalidate the attempt; qualification checks it before acquisition and
again at publication. A change racing acquisition does not undo material or
spend facts. Exact remote qualification of the candidate retains this revision.

`Start` begins the connection intent. `WaitForSession` and `CaptureSession` only
observe an already published current Session; they never acquire or open a
channel. Cancellation of a wait ends that observation. The construction context
controls Controller lifetime; the context supplied to `Start` controls that
connection/retry intent. `RetryNow` can wake an existing backoff but cannot cross
an authoritative not-before deadline, overlap unfinished cleanup, or rerun a
failed initializer. `MaximumAttempts` bounds consecutive acquisition attempts;
zero permits the long-lived intent to continue. A successful current starts a
new attempt cycle.

Before acquisition, the original attempt waits for refreshable verification gaps
in its captured identity or installed pool credentials. It uses the namespace's
existing refresh service and the Controller's coalesced wakeup, retains candidate
headroom, and keeps the earliest original preparation deadline. Known revocation,
independent trust rejection, expired credential/initiation bounds, cancellation,
or namespace closure remain terminal. `Snapshot().WaitingVerification` reports
this state separately from source backoff. Waiting neither grants admission nor
creates another material or refresh owner.

`RequiredContracts` fixes the required unary contract digests. Candidate
publication checks exact registered contracts, usable execution Offers and the
original RPC publisher together with READY and current authorization. A missing
route/Offer waits within the same attempt. The optional `InitializeSession`
callback runs once for that candidate on its configured ordinary executor class;
its result passes through the reserved Completion position. The callback and
`WaitForSession` see the same public `V4Session` object. After callback entry,
failure, cancellation or uncertain completion fences Controller dispatch until
an explicit successful `ReplaceSession`; it never silently repeats the callback.
Waiting for the same Controller from its initializer is rejected as a dependency
cycle.

Active handler declarations contribute only their required method subsets to
candidate qualification. The original bound method slots count these references;
closing one declaration does not remove another handler's requirement. Candidate
checks use the candidate's authenticated identity, exact registered contracts,
Offers and actual shape-specific paths. On-use misses do not delay replacement.
The existing attempt prepares required paths on that candidate with its original
fixed deadline before qualification, without starting another acquisition or
changing the published current. Remote dependencies use ordinary query capacity,
at most eight exact targets per batch, and their original method update flights.
The attempt retains a received response across temporary installation contention;
it does not issue another query to retry that handoff. An explicit method update
revokes that target's candidate installation right and waits for its original
query cleanup, without canceling independent targets in the same batch. Exact immutable canonical
bodies remain on the original binding, while the candidate's authenticated Offer
and source facts occupy bounded method metadata. Only a successful current
publication installs those facts for future calls. Denial, cancellation, closure
or a changed method generation preserves current's original snapshot. Managed
renewal qualifies the projected complete target set and candidate Offers before
the same publication gate.

Required streaming targets are requalified before a contract update that would
split a previously shared pool target. Fixed-Session and Controller bindings
that point to the same physical Session share its two-per-service and eight-total
limits; exact duplicate targets count once. Candidate publication checks this
physical projection as well as the Controller's own logical target union.
Adding a missing required dependency gates the related handler's future dispatch
without revoking the published current. The bounded registration revision also
fences additions and contract installation against candidate publication.
`V4ControllerOptions.InitializeDependencies` supplies the initializer's restricted
views and required checks before its ordinary permit and first application entry.
Each attempt freezes these method generations and projects their exact contracts
onto its fixed candidate, with the original authenticated routing identity.
Initialization views never select the Controller's current Session. Before
acquisition, each distinct declared client/method reserves its complete existing
operation workload, result position, Completion floor and streaming backing in
addition to the old current's actual responsibilities. Without an explicit
method workload, it reserves one call with the contract's maximum
request size and the method's normal response limit. Repeated aliases of the
same client/method share that original target. Result-bearing initialization
requires a complete source namespace snapshot before acquisition.
The attempt also reserves its invocation-view aliases in the original resource
slab. Preparation, Start, results and their bounded consumers use the same
workload reference positions as ordinary calls, without duplicating ancestor
capacity in the initializer. Closing the attempt releases idle view positions;
actual children retain their source scopes until physical release. Exhausting
either declared allowance cannot acquire a replacement alias from general
capacity.

Required candidate channels and streaming paths are prepared before callback
entry. Calls through the initialization views redeem only their reserved
positions; exceeding the target refuses locally without falling back to ordinary
capacity. The original attempt deadline also caps the request, preparation and
Completion deadlines, retaining any earlier caller or contract bound. Callback
entry and current publication recheck the captured method generations under
their original binding gates. Failure seals unused targets; actual operation
and result tails retain their original Session/Environment cleanup owners.

`ReplaceSession` establishes and qualifies the candidate before switching future
dispatch. The default retirement drains the previous Session. Explicit
`V4ControllerRetain` requires a fixed positive `RetainUntilMS` within the previous
Session's original hard cap. `CurrentSwitched`, `PreviousRetained`, and
`RetirementError` report separate facts: an old Session that already drained or
closed cannot be reopened by retain. A previous retained Session or its actual
cleanup tail consumes the single retirement position; another replacement fails
with `ErrV4RetirementCapacity` before acquisition.

`PrepareUnary` captures one current Session and constructs the original immutable
operation. `Dispatch` starts only that handle. The actual first-header gate
orders publication with current switching and initialization fencing; accepted
request tails remain on their original Session. Controller queued ordinary unary
operations may select another already READY/accepting current at most twice
before header acceptance. Selection preserves the original encoded bytes,
contract, operation ID/digest, captured Offer, response limit and original
preparation/request/result deadline projections. It neither acquires a connection
nor reruns the encoder or Start. The authenticated authority, tenant, audience,
caller/peer subjects and any installed execution identity must remain equal;
certificate and key rotation alone do not change that identity. Mapping a
different peer subject to an approved replica is not implemented.

The original publication gate permanently fences each discarded route before
the replacement obtains its complete request/result/Completion vector. Prior
publisher turns must actually leave; retained route/result observers continue to
consume their original resources. Failure to admit the replacement terminates
that Start as not submitted. Explicit Session operations, try-now, notifications,
streaming, result reads and submitted requests do not reselect. The Controller's
existing coordinator holds at most 256 original operations; result observation
continues through their bounded route chain, and Close fences future headers.

This implementation does not yet provide declaration replacement, complete
declared workload and replacement headroom qualification, or Controller
notification subscriptions.
Initializer callback, operation, result, Completion and invocation-view aliases
are reserved before acquisition. Declared method workloads also preadmit their
ordinary Prepare/Start/result ancestor references. General callbacks outside
these recipes, ordinary registration-view reference floors, and complete
factory/replacement recipe qualification remain incomplete.

Only structured original source failures and recognized original transport
failures schedule automatic acquisition retries. The native adapters project
QUIC idle/handshake timeout, stateless reset, connection refusal and unavailable
path, selected socket interruptions, and abnormal WebSocket disconnects. Native
stream half-close, stream reset, peer application close, protocol and TLS policy
failures retain their separate meaning. No arbitrary error chain or error text
can supply transport provenance.

Native WebSocket TLS and HTTP preparation carry a private marker from the actual
socket I/O boundary. Truncated handshake input preserves that interruption
through parsing; certificate callbacks, TLS alerts, malformed HTTP and explicit
HTTP refusal cannot forge it or convert a later cleanup failure into a retry.

Preparation retains earlier policy, resource and binding refusals across the
fixed candidate set. Exhausting a factory's immutable numeric address list keeps
the preceding network outcome without starting another dial. The initial
exchange records actual provider I/O separately from builders and verifiers.
Automatic retry after pre-READY failure waits for original candidate cleanup and
requests fresh material; an already consumed lease is never reused. These retry
facts grant no permission to replay application initialization or business work.
Shared reliable writes, maintenance writes and native connection ingress preserve
the first close cause; individual native data-stream failures keep their stream
scope. Public
Controller failures are fixed redacted values and do not retain arbitrary
source/application exception graphs. `Close` seals the Controller; `WaitCleanup`
and `CleanupStatus` retain actual source, callback and Session cleanup ownership.

The direct issuance, live authorization and pool control clients keep one
original cancellation observer through native I/O, credential verification and
result decoding. The HTTPS provider shares that observer with its enclosing
source or transport. Pool RPC calls retain their own admitted observer and join
the original RPC Completion before returning output. Absolute deadlines cover
the whole call; custom caller contexts do not create implicit forwarding tasks.

Context setup occurs after admission and unconditional cleanup installation.
External context methods run outside owner gates; subsequent cancellation and
publication checks read SDK state and captured signals. TLS, decoder or context
panics discard output and become a fixed control-task failure. Goroutine exit
still runs cleanup. Canceled or failed results release both evidence owners
outside transport locks, retaining the original position through those hooks.

The direct issuance, live authorization and namespace HTTPS services also claim
their original position before clock/context callbacks. Their cancellation
observer owns both native deadline-interruption callbacks and is joined before
the service releases its buffers. Authentication and publication validate
trusted clock samples taken outside the service gate. Late callback success
cannot bypass closure or the original deadline.

Live spend queries retain one original service position through access policy,
SQLite reader construction, receipt encoding and publication. Reader policy and
time checks run outside its mutex while its running position prevents cleanup.
Partial construction, canceled publication and abnormal callback exits retain
and clean the actual reader; a cleanup failure cannot refund a live reader.

Pool services reserve a separate single refusal position for authenticating and
replying to a caller while the main issuance call is occupied. Permission denial
still takes precedence over a capacity reply and performs no history lookup.
When both positions are occupied, the adapter refuses locally without entering
another access or response callback. Both positions, their contexts and their
observers are included in the configured resource charge.

Management requests and the incident worker sample trusted time outside the
service mutex. A bounded incident sweep shares one immutable sample across the
original row deadlines. Native response flushing, cancellation interruption and
deadline reset all finish before the management position is returned. Audit
maintenance reserves three original workers and three cancellation observers;
closing or abnormal task exit never starts a replacement worker, and bindings
remain retained until all original tasks actually exit.

## Shutdown and observable cleanup

Notification Close obtains its bounded local clock sample outside the token
and dispatcher gates, then seals dispatch and fixes the cleanup window at the
winning gate. Concurrent or repeated Close never replaces that window. Actual
sampling tails retain their token and dispatcher backing even after another
Close wins. Abnormal sampling still seals the original owner and settles its
tail. WaitClosed retains its admitted waiter across caller context and clock
reads, uses the original cleanup cap, and does not initiate Close.

Session `Drain` starts one original communication boundary and deadline.
WaitDrain cancellation does not replace them. `Rekey` joins the original manual
cause; `ProbeLiveness` keeps its original publication/response owner. An
authenticated PONG can finish a sample before the local provider returns; its
terminal result remains immutable and its actual publication tail stays charged
until that return. `Complete` records provider completion observed before the
sample ended and is not a prerequisite for a successful PONG result.
Temporary maintenance-writer occupancy wakes that original unpublished sample
through its bounded coalesced signal. It retains the original nonce and time
windows; only the pre-ticket busy gate can wait without consuming the sample.
`WaitTermination` observes communication termination independently of cleanup.

Call Session/Environment/source Close to seal admission, then observe their
original cleanup. `V4Session.CleanupStatus` can report `cleanup_incomplete` while
callbacks or providers still retain real backing. A later observation may prove
completion. `env.WaitCleanup` retires Environment metadata only after those tails
exit. It does not close the caller's root, executor, clock, verification registry,
key providers or durable stores. Close and retire these shared owners only after
all users exit. Durable namespace history destruction also requires the physical
Environment resource authority to be closed; ordinary Session replacement never
destroys it.
