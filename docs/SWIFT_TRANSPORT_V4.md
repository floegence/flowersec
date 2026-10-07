# Swift transport v4

`TransportEnvironment(configuration:)` creates the native Swift transport on macOS and
iOS. Applications establish Sessions through an SDK-owned
`ConnectionMaterialSource` or an original `ConnectionMaterial` captured from
that TransportEnvironment. `ConnectionController` uses those same entrances for retry,
initialization and explicit Session replacement. Native direct and tunnel
WebSocket routes support both X25519/ChaChaPoly and P-256/AES-GCM Noise profiles.

## Independent configuration

Configure the tenant, application identities, namespace roots, trusted time,
numerical endpoints, resource limits and durable backing before accepting any
credential. An unverified Artifact or control response cannot select those
values. The following factory accepts the application's existing trusted
adapters:

```swift
import Flowersec
import Foundation

func makeEnvironment(
  rootKeyID: Data,
  rootPublicKey: Data,
  history: TransportPoolHistory?,
  trustedTime: @escaping @Sendable () throws -> TransportTrustedTime,
  bootstrap: @escaping @Sendable (Data) async throws -> TransportNamespaceSnapshot
) async throws -> TransportEnvironment {
  let namespace = TransportTrustNamespace(
    authority: "deployment-authority",
    rootKeyID: rootKeyID,
    rootPublicKey: rootPublicKey,
    maximumTrustLifetimeMilliseconds: 60_000,
    bootstrap: bootstrap
  )
  let configuration = TransportClientConfiguration(
    tenant: "example-tenant",
    audience: "example-service",
    clientSubject: "example-client",
    serverSubject: "example-server",
    namespaces: [namespace],
    endpoints: [
      TransportEndpoint(
        hostname: "transport.example.com", port: 443,
        numericAddress: "192.0.2.10"
      )
    ],
    history: history,
    trustedTime: trustedTime
  )
  return try await TransportEnvironment(configuration: configuration)
}
```

Replace the deployment identifiers and documentation address with independently
configured values. `trustedTime` supplies an inclusive Unix-millisecond
interval; there is no wall-clock fallback. `TransportTimePolicy` bounds drift,
interval width and anchor age. `refreshTrustedTime()` samples the same configured
source. `invalidateTimeContinuity()` fences work whose original continuous
clock can no longer be established. Refreshing time does not revive a terminal
owner.

Set `TransportClientConfiguration.webSocketOrigin` when a native WebSocket
route requires an Origin header. The value must be canonical and match the
signed route policy before any connection or durable spend. Listener routes
validate the incoming Origin independently; private loopback routes retain
their exact signed local Origin.

The bootstrap adapter receives an SDK-generated nonce and returns the exact
signed `TrustBootstrapResponse` and complete `RevocationState`. It must bound
its response, honor cancellation and authenticate its control transport. The
SDK checks the pinned root, nonce, trust, head and state.
`refreshNamespace(authority:head:state:)` updates only the original configured
namespace and preserves revocation fences.

The current complete Head/State pair remains usable within its original
validity while a newer pair awaits time proof or complete State. Independently
verified, mature Head floors immediately reject the affected credential class;
missing State does not defer those denials or revoke unrelated credentials.
A pending candidate keeps its original deadline. Once it expires, a later
refresh can validate a newer pair, but cannot revive the expired candidate.

`TransportPoolHistory` supplies independent once-spend continuity for pool
connections. Its directory must already exist, belong to the current user,
have no group or other permissions and contain no symlink substitutions. Use
`create: true` only for the original store; reopening requires `create: false`
and the same binding. A copied filename or a no-op continuity callback cannot
prove that historical state has not been rolled back.

## Client Sources and fixed Sessions

Generate an application identity with `generateApplicationIdentity(profile:)`
or import its provisioned Ed25519 signing seed and matching Noise static key
with `importApplicationIdentity(profile:signingSeed:noiseStaticPrivateKey:)`.
`TransportApplicationIdentity` exposes public keys and its selected profile;
private keys remain in its original owner.

The configured Source alternatives have separate authority and lifetime:

| Source factory | Original authority | Acquisition and recovery |
| --- | --- | --- |
| `makePreauthorizedPoolSource(_:identity:role:)` | Complete signed local pool records and one immutable identity generation | A finite pool; Acquire does not issue or replenish credentials. |
| `makeLiveAuthoritySource(_:identity:)` | Independent issuance and activation mTLS endpoints, application certificates and activation signing key ID | One original issuance request per acquisition and one original TxB authorization per connection attempt. |
| `makeManagedPreauthorizedPoolSource(_:identity:)` | Independent SourceAuthority fence, TopUp/Ack endpoint and durable refill journal | Acquire takes only installed local records and immediately reports `source_exhausted` when empty. One bounded background worker verifies and installs complete batches; recovery follows retained original intent. |

`makeConnectionMaterialSource(_:identity:)` accepts the corresponding closed
`TransportMaterialSourceConfiguration` alternative. Selecting an activation
profile installs no fallback to another authority.

A finite source verifies the certificate/key/profile pair before releasing a
record. `replacePoolGeneration(_:identity:)` publishes a complete replacement
snapshot and advances an SDK-owned local generation. A live source uses
`replaceLiveConfiguration(_:identity:)` for the same complete-snapshot behavior.
Previously acquired material keeps its original assembly and cannot be rebound
to a later identity or configuration.

`connect(source:requirements:)` acquires one original material and performs its
native preparation, applicable once-spend/activation, FSB/FSA, Noise and both
READY flights. `connectMaterial(_:requirements:)` consumes an already captured
material once. `ConnectionRequirements` expresses required guarantees and
rejects unsupported routes before consumption. Neither retry nor receipt lookup
can recreate an original material's successful commit capability.

A live tunnel fixes its future Grant scope, relay certificate, exact Grant
limits and candidate index independently of TxB. The original response contains
`live-tunnel-material-1`, the activation proof and signed local Grant. The SDK
checks the parent, route, attempt, identities, legs, session contract and current
namespace against the original preparation. All four HOP_AUTH flights use that
carrier's fresh incarnation/challenge before endpoint Hello and READY. A relay
that physically dials an endpoint sends the first HELLO; the original client
listener can transfer that one bounded buffered flight into its activated
carrier owner without authenticating it during preparation.

`TransportRegisteredLiveAuthoritySourceConfiguration` captures one original
installed tunnel Artifact, both endpoint certificates, the future Grant scope
and exact limits, relay certificate, activation signing key ID, and independent
registered authority and relay mTLS configurations. Create its Source through
`TransportEnvironment.makeRegisteredLiveAuthoritySource(_:identity:)`. Both control
configurations use an empty `basePath`; the SDK fixes the registered authority
path to `/flowersec/control/live` and the relay paths to their original tunnel
control operations. The same endpoint mTLS identity serves both controls;
each configuration retains its independently installed trust roots.

This registered Source performs one Acquire. It verifies the installed parent
and identity pair, captures a fresh SDK attempt and source incarnation, and
prepares the original WSS carrier. The registered authority consumes signed
JSON `live_client_prepared` and `live_authorize` envelopes. The latter includes
the exact canonical original authorization request and its independently signed
random prefix. The SDK checks reply authority and incarnation, verifies the
original activation and local Grant, and hands them to the original external
relay through its CBOR preparation and client activation operations. A completed
relay ACK is required before native HOP and endpoint establishment continue.
A failure, cancellation, or Source close withdraws an acquisition that has not
completed its original relay handoff. Source close also cancels the original
material's preparation. A completed handoff remains terminal when the Source
later closes, and the established Session retains its own lifetime. Source
cleanup waits for original control operations, physical HTTP/TLS handlers and
response owners. An explicit response envelope retains the original charge
through parsing even when Foundation stores a short ACK inline; shared byte
backing retains the same charge through its final release. The registered
configuration selects its original Candidate index within the Artifact and
binds that exact index into preparation and authorization.

Managed refill recovery preserves its original operation, response digest and
acknowledgement obligation through physical cleanup. An installed historical
batch can authorize Ack recovery without making old material consumable again.
An unresolved TopUp result stays on that same operation; it is not permission
to generate another refill identity or reset the journal.

For a preauthorized tunnel client, attach a
`TransportPoolServerAllowConfiguration` to each `TransportPoolCredential` through
its `serverAllow` initializer argument. The configuration captures the independently
issued server-role Grant, the original server registration's recipient and incarnation,
and the independently installed mutual TLS sender. The server Grant stays separate
from the local client Grant. The SDK validates its complete closure and prepares
its bounded HTTPS request before durable pool consumption. Only the original
successful consume publishes one `POST /tunnel/server-allow` request; a refused,
unknown or canceled consume publishes none. The sender waits for the canonical
receipt acknowledgement before HOP, and retains its original driver and response
resources through physical cleanup. Its publication timeout must be at most
2,000 milliseconds and its control base path must be empty.

## Server and continuous relay

The macOS/iOS WebSocket profile exposes server admission and accepted Sessions
through `TransportEnvironment.accept` and `serve`. `ServeOptions.resolveHandlers`
selects a `HandlerPlan` containing `ServiceRegistry` and `StreamHandlers` before
Session establishment. The same registered unary and notification definitions
serve inbound calls on endpoint-client Sessions, including each new Controller
generation. `StreamHandlers.serve(session:)` also dispatches application streams
on an established Session and joins active handlers when it closes.

The executable capability checks are:

| Test ID | Runtime | Covered behavior |
| --- | --- | --- |
| `interop/swift-rust-go/wss/live-tunnel` | macOS | Reciprocal RPC and notifications, encrypted streams, rekey, Drain and cleanup with Swift as endpoint client |
| `controller/swift-client-handlers` | macOS SwiftPM | Native inbound unary RPC and registered notifications on a one-shot client and after Controller replacement; retired notification callback cleanup |
| `controller/swift-client-handlers/ios-simulator` | iOS Simulator | The same three native client-handler and Controller cleanup tests |
| `server/swift-acceptor` | macOS SwiftPM | Original pool/live server preparation, authenticated Allow, native listener Session establishment, durable admission and source/carrier cleanup |
| `server/swift-acceptor/ios-simulator` | iOS Simulator | The same six native server admission and cleanup tests |
| `server/swift-session-handlers` | macOS SwiftPM | Handler-plan publication, authorization/Drain races, sibling isolation, inbound service dispatch and handler cleanup |
| `server/swift-session-handlers/ios-simulator` | iOS Simulator | The same four native Serve tests, three ServiceRegistry tests and five StreamHandlers tests |

Both macOS SwiftPM and iOS Simulator checks require a Darwin execution host.
The Simulator checks execute on iOS 26+ using the pinned Xcode toolchain; the
Darwin registry condition does not restrict the SDK to a macOS runtime.
Run `node scripts/run-ios-simulator-test.mjs --suite server-acceptor` or
`--suite server-session-handlers` for the iOS server checks. The default suite is
`connector`; `--suite client-handlers` runs the client-handler checks. Set `FLOWERSEC_IOS_SIMULATOR_ID` to an available compatible device
UDID to select a dedicated Simulator; an invalid selection fails without falling
back to another device. Every selected test must appear as passed in the Xcode
result bundle, including the Swift Testing stream-handler cases.

The native `ProxyServer` provides HTTP and WebSocket adapters. The separate
`browser_proxy_runtime` capability remains unqualified for Swift because the
executable browser proxy matrix does not cover a Swift server.

Logical endpoint role is independent of physical direction. Import the server's
own identity and use `role: .server` for a finite direct pool source. `connect(source:)`
uses the signed route's dialer or listener direction. `accept(source:)` adds an
explicit native-listener requirement and refuses a dialer route. Configure
`listenerTLS` for network listeners. The native listener enforces the signed
host/port, path, subprotocol and Origin policy and accepts one original carrier.

For preauthorized tunnels, call
`makePreauthorizedPoolServerSource(_:identity:control:)` with independently installed
server-role credentials and the exact client certificate DER authorized to deliver
Allow. The SDK creates a finite source of at most eight original preparations,
prepays native and session resources, and returns their `bindings` after listener
routes are bound. Each binding captures its original recipient, incarnation,
attempt, Artifact and Candidate; supply it to the corresponding client's
`TransportPoolServerAllowConfiguration`. Independently prepared listener entries
must use distinct ports. The control timeout is at most 2,000 milliseconds.

Use the returned `materialSource` with `connect`, `accept` or `serve`. An
authenticated Allow must match the complete original server Grant bytes,
relay certificate, pairing, server leg, Candidate, route, binding and cutoff.
Only successful native acknowledgement write completion publishes that original
material once. A duplicate, failed delivery or historical receipt cannot reopen
publication. Pool server HOP, FSB and durable server consumption all require the
same authenticated original carrier. Ordinary pool material APIs reject tunnel
server credentials that lack this registration. Closing a source fences waiting
preparations and its HTTPS listener; acquired material retains its own admission
lifetime. Cleanup observes the original preparation, native carrier and physical
acknowledgement tails, while a successful Session owns its transferred carrier.

`makeLiveServerSource(_:identity:)` starts a bounded mutual TLS
`POST /tunnel/server-allow` listener. Its configuration pins the exact authority
client certificate DER, local TLS identity, numerical endpoint and independent
admission store. `registerOriginal(_:)` verifies the complete original Artifact
and identity pair, fixes the trusted attempt/recipient/candidate, creates an
incarnation and prepays native/session resources. Advertise the returned
`TransportLiveServerBinding` through the application's trusted registration
flow before authorizing the client.

The original `tunnel-server-allow-1` request carries the signed server Grant;
it carries no activation proof. A successful final native ACK write publishes
the prepared material into the Source. An exact duplicate can acknowledge the
retained original request without publishing a second carrier. Acquire transfers
that same preparation. The server obtains activation inside authenticated FSB,
verifies the complete closure and commits its own admission before FSA, Noise
and READY. A committed row whose original result is unknown remains a refusal;
reopening its ledger does not restore an admission capability.

`makeRelayHost(_:identity:)` creates a continuous `RelayHost` with one durable
claim ledger and a bounded publication queue. An initial preauthorized pair,
`TransportLiveRelayPublication` or `TransportLiveRelayRegistration` fixes
its original publication. `publishOriginal(client:server:)`,
`publishLiveOriginal(_:)` and `registerLiveOriginal(_:)` admit later independent
publications. Each publication writes its durable refusal before queue admission.
`run()` serves publications until stopped; a failed pair completes its own
`RelayPublication` and leaves the daemon available.

For a production live Source, install `TransportLiveRelayRegistration` before
client Prepare. Start `host.run()` and await
`host.initialPublication.waitListening()` before connecting the Source; this
joins local listener binding without probing its only physical child. The signed parent, both certificates, relay identity, future
Grant scopes and limits fix the deployment without final Grants. The host starts
its physical listeners and pinned control listener before TxB. Configure the
client Source's `relayPreparation` endpoint for this deployment. On a signed
endpoint listener route, its native listener first sends
`POST /tunnel/relay-ready`; the exact original relay dialer starts only after the
ready ACK completes. This signal issues no authorization. Once native Prepare
has completed, the Source sends the original `live-authorization-1` request to
`POST /tunnel/relay-prepare`, then sends that same request to its original
`/live/authorize` authority. Prepare remains before TxA/TxB.

The independently pinned original TxB callback sends
`POST /tunnel/relay-activate` with the canonical five-element CBOR array
`["tunnel-relay-activate-1", request, activation, clientGrant, serverGrant]`, where
all four material values are byte strings. The activation and both Grants must
match the frozen request, parent, attempt, route, identities, future scopes and
limits. The final native ACK write releases HOP on those same prepared carriers.
Exact request retries repeat only the ACK, never installation or dispatch. Set
`preparationControl` when preparation and TxB use separate pinned TLS principals
and endpoints; `control` then accepts only the original activation callback.
A logical server listener uses its Source configuration's `relayPreparation`
endpoint to announce its original listener readiness. A final
`TransportLiveRelayPublication` instead supplies the original public
`activationAuthorization` and independently configured `activationSigningKeyID`
alongside the final Grants.

Each relay leg independently dials or listens according to its signed route.
Both original HOP possession proofs, common ParentWinner confirmation and the
paired durable claim must succeed before relay proofs and opaque forwarding.
Replaying a claim, closing a ticket or reopening the ledger cannot restart
forwarding. `RelayPublication.waitCompletion()` reports the paired run's actual
result; `waitCleanup()` separately joins its physical carriers and control
callbacks. A relay ticket is not evidence that either endpoint established a Session.

## Common parent selection

Configure one `ParentWinnerAuthorityConfiguration` for all direct and tunnel
admission domains for the same parent. Attach it to server pool history,
`RelayClaimStoreConfiguration` and `LiveServerAdmissionStoreConfiguration` using
`parentWinner`. The configured authority must equal the namespace's independently
trusted `winner_authority_id`. Omitting it refuses server or relay admission;
it never falls back to a local candidate-specific table.

`TransportEnvironment.makeParentWinnerAuthority(_:)` creates a bounded native SQLite CAS
owner from `ParentWinnerStoreConfiguration`. For server pool history configured
without an adapter, call `TransportEnvironment.installParentWinnerAuthority(_:)` with that
owner's configuration before server-role pool consumption. The authority ID must
match the history's winner authority; installation is one-time. The Swift example
helper `makeCommonParentWinner` performs that installation. Alternatively,
provide a qualified common service adapter in the history during TransportEnvironment
creation and share it with relay claims and live server admissions. The adapter
must atomically select an unselected parent, match an exact selection
retry and reject any changed selection. Its immutable public
`ParentWinnerSelection` has a parent key independent of candidate, attempt,
carrier, local role and admission store. Its projection binds source, original
Artifact and activation, candidate set, chosen candidate and route, attempt,
both identities, audience, server authority and the original parent lifetimes.
The two tunnel legs and logical server therefore present the same public fact.

After authenticating original FSB, a direct server confirms this CAS before its
admission COMMIT. After both original HOP possession proofs, a relay confirms it
before its paired pool/live claim COMMIT. Durable original-claim refusals are
retained before common CAS, so a lost selection result cannot be retried through
a newly decoded material or another physical owner. These are independent real domains:
ParentWinner becomes irreversible first, then the original local admission.
Failure or COMMIT uncertainty stops that run without another candidate race.
Only a still-current native claim can consume the original CAS confirmation.
Exact CAS readback returns public evidence and cannot restore admission or
forwarding rights. The SQLite authority checks secure backing and independent
continuity before and after COMMIT; result uncertainty fences its original owner
while the committed selection remains a refusal on disk.

The live server admission, ParentWinner, relay claim and pool refill journal
groups use fixed revision-2 manifests bound to their installed deployment
identity and capacity. Reopening first uses a read-only connection to inspect
the bounded header, matching SQLite revision, exact current schema and bounded
record relationships. The accepted group is rechecked on the writable connection
before configuration; incompatible formats never enter recovery or admission.
`StorageFormatError.projection` returns only `storage_format_incompatible`, the
transaction group and wire profile, trustworthy observed revision, required
revision and a finite reason. Unknown headers and conflicting revision hints
never select a historical reader. No exact conversion tool is installed and
opening does not migrate or clear an incompatible group.

## Controller and application services

Create `ConnectionController(environment:source:requirements:maximumAttempts:initializeSession:)`
with the same configured TransportEnvironment and Source. `start()` begins acquisition;
`waitForSession()` returns a published accepting Session and `captureSession()`
returns the current one without waiting. A captured Session, byte stream or
prepared operation remains owned by that original Session after reconnect or
replacement. The controller does not replay application work.

The initializer runs against a candidate Session before current publication.
`replaceSession(retirement:capacity:)` connects and
initializes a new candidate before replacing current. Failure preserves the
previous accepting current; retirement retains its actual cleanup responsibility.
Generation and notification publication track the new original current rather
than rebinding old handles.

Bind named services with `session.bindService(...)` or `controller.bindService(...)`,
an independently chosen `ServiceDefinition`, target and `ServiceContractSource`.
A controller binding selects the current Session before each new preparation.
Exact canonical contracts, local codecs and typed/raw stream bindings determine
accepted payloads and dispatch. Request bytes cannot select another method,
handler or private-key owner. Execution references and checkpoint tokens keep
their original service/store identity; query or cancellation does not authorize
Start or replay.

See [the Swift package guide](../flowersec-swift/README.md) for named-service,
notification, execution-store, stream and replacement recipes, and
[the Swift examples](../examples/swift/README.md) for ordinary consumers.

Controller service acquisition uses the already published, accepting Session.
The asynchronous `controller.bindService(..., deadlineAtMS:)` completes the initial
contract set before returning. It never starts the controller, acquires material,
or waits for reconnection. Each binding captures the original current generation;
replacement and Close fence new preparation and late contract installation under
the original environment gate. A local supersession permits at most two fresh
selections within the same deadline. Source and contract failures are returned
without replay.

An exact binding carries its installed digest and per-method acceptance policy
into the new generation. Use `ControllerServiceClient.updateContract` to explicitly
approve a contract change. Retiring the old generation releases the facade's fixed
binding alias; already prepared operations keep their original Session and cleanup
owners. The public consumer recipe is
`examples/swift/Sources/FlowersecSwiftClientExample/ControllerServiceWorkflow.swift`.

Swift `offerRefresh: .managed` uses one Environment coordinator for installed
execution methods. It protects one original renewal query position before
binding delivery, batches methods from the same source, target and Session,
and retains physical query, decoder and source tails until they exit. Each
method has one in-flight fetch. Preparation captures its verified local snapshot;
explicit single-method and batch `refresh` join the same bounded scheduler.
A managed binding requires an accepting RPC channel and a qualified Offer
window. A drained Session cannot renew or acquire a replacement connection.
The Environment method and contract metadata pool admits at most 256 methods
(or 16 with the constrained profile), including retained old binding owners.

`ControllerServiceClient` accepts `requiredForDispatch` and unary `workloads`.
Each registered facade participates in the next candidate dependency plan.
The plan freezes declaration revisions and pays binding storage, unary targets
and required stream base storage before connection acquisition. It prepares
actual required stream and notification sources before current publication,
then rechecks its original deadline, Offers and declaration revisions at the
atomic switch. Streaming item decoding and notification publication also pass
their ordinary dispatch resource gates.

`ServiceMethodWorkload` reserves a finite number of simultaneous unary targets
with request and response byte limits. A target includes its original ordinary
encoder position, RPC position, response completion descriptor and body owners.
A queued Controller unary checks the currently published target again before
accepting its first BEGIN bytes. At most two reselections use that declaration's
prepaid targets while preserving request bytes, header, operation ID, admission
cutoff and deadline. `tryNow` does not reselect. After BEGIN acceptance the
operation remains attached to its selected fixed Session, including result
waiting and cleanup.

## Cleanup and capability scope

Closing a Source fences future Acquire and pending work without canceling an
already transferred material or established Session. Controller-bound clients
do not close their external controller. Close streams and application bindings
at their owning scope, then close the controller, Sources and TransportEnvironment.
Inspect `cleanupStatus()` and join the corresponding cleanup methods. An
incomplete physical tail retains its resources; a business close or historical
receipt does not imply reclamation.

Native WSS tunnel routes use `/flowersec/v4/tunnel` and
`flowersec.tunnel.v4`. Direct WSS and explicitly signed loopback HTTP/WebSocket
routes share the endpoint handshake and reliable-stream owners. This Apple
profile does not implement raw QUIC, WebTransport or datagrams. Inspect the
original Session's information before depending on transport guarantees.

The shared engineering driver selects the registered WSS client coordinate
`interop/swift-rust-go/wss/live-tunnel` explicitly. Its Swift consumer reads
`FLOWERSEC_PARITY_LIVE_DEPLOYMENT` independently and compares the original A
publication's tenant, audience and exact authority URL to that installation.
The relay control retains the same installed A mTLS identity and its own trust
roots. This engineering profile fixes its public WSS relay limits locally; the
SDK verifies the resulting future scope and final signed Grant against the
original namespace and parent. Runtime scratch lives under the externally
supplied `FLOWERSEC_TEST_ARTIFACT_DIR` and is removed after successful physical
cleanup. The driver supplies only A's original material and installation path
to this consumer.


## Owned duplex bridges

`DuplexBridge(a, b, options:)` takes two distinct, unused original raw
`ByteStream` endpoints in the same Environment. Construction reserves both
finite chunks, result tails and complete endpoint owners before any bytes are
consumed. External ByteStream implementations, aliases of one endpoint and
endpoints with another I/O owner are rejected locally. The overall deadline
begins at construction and bounds the prepared period before `start()`.

Call `start()` once; repeated calls join the same operation. Each source EOF
half-closes only its destination. The reverse direction continues until its
own EOF, and both normal sends finish concurrently after the two pumps end.
Canceling `wait()` cancels only that observation. `abort()` stops the owned
operation. `progress()` preserves accepted counts, finite pending tail size
and whether each I/O direction has exited. Repeated successful waits return
the same immutable result and tail owners. `cleanupStatus()` observes actual
retirement after an incomplete cleanup snapshot; live work remains charged.

On macOS and iOS, create a sealed endpoint with
`environment.connectDuplexTCP(numericAddress:port:chunkBytes:timeout:)`, then
construct `DuplexBridge(stream, tcp, options:)` or reverse its argument order.
The private nonblocking socket supports numeric IPv4/IPv6 and real TCP
half-close. It remains bound to its original Environment and cannot be read,
written or closed through a different alias while claimed. The factory reserves
native storage and provider allowances before connecting; Environment close
fences publication and joins the original cleanup owner. An ambiguous native
close failure retains its physical allowance.

Inspect `destinationKind` and `nativeSendFinished` for native output and
`sendDrained` for authenticated Flowersec output. Native send completion proves
local queue/shutdown behavior and does not establish peer authentication or
business completion. External socket/descriptor adoption, DNS, TLS and two
native endpoints are not supported. Native readiness uses bounded polling.
See the native bridge workflow in the Swift example for the public call chain.
