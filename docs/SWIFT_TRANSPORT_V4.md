# Swift transport v4 direct WSS client

`TransportEnvironment(configuration:)` creates the native Swift v4 client on
macOS and iOS. It establishes one direct WSS candidate from a preauthorized
pool, with the `transport` application profile and no optional features. Both
X25519/ChaChaPoly and P-256/AES-GCM Noise profiles are supported. The independent
`connect(lease:options:)` and `ConnectionController` entrances use transport v3.

## Independently configured trust and storage

The application configures namespace roots, tenant and peer identities, trusted
time, numerical endpoints and durable history before receiving a credential.
None of those choices may come from an unverified Artifact. This example makes
the host-owned security adapters explicit:

```swift
import Flowersec
import Foundation

func makeV4Client(
  rootKeyID: Data,
  rootPublicKey: Data,
  historyDirectory: URL,
  storeID: Data,
  generation: UInt64,
  artifactIssuerKeyID: Data,
  createHistory: Bool,
  trustedTime: @escaping @Sendable () throws -> TransportV4TrustedTime,
  checkContinuity: @escaping @Sendable () throws -> Void,
  bootstrap: @escaping @Sendable (Data) async throws -> TransportV4NamespaceSnapshot
) async throws -> TransportEnvironment {
  let namespace = TransportV4TrustNamespace(
    authority: "deployment-authority",
    rootKeyID: rootKeyID,
    rootPublicKey: rootPublicKey,
    maximumTrustLifetimeMilliseconds: 60_000,
    bootstrap: bootstrap
  )
  let history = TransportV4PoolHistory(
    directory: historyDirectory,
    storeID: storeID,
    generation: generation,
    artifactIssuerKeyID: artifactIssuerKeyID,
    spendAuthority: "deployment-spend",
    winnerAuthority: "deployment-winner",
    create: createHistory,
    checkContinuity: checkContinuity
  )
  let configuration = TransportV4ClientConfiguration(
    tenant: "example-tenant",
    audience: "example-service",
    clientSubject: "example-client",
    serverSubject: "example-server",
    namespaces: [namespace],
    endpoints: [
      TransportV4Endpoint(
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

Replace the deployment names and documentation address with independently
configured values. The history directory must already exist, be owned by the
current user, have no group or other permissions, and resolve without symlinks.
Use `create: true` only when creating the original history; reopening that same
history requires `create: false`. Store and issuer key identifiers are 16-byte
values. A store identifier must be nonzero and its generation must be positive.

`trustedTime` returns a trusted inclusive Unix-millisecond interval. There is
no system-clock fallback. `TransportV4TimePolicy` bounds clock drift, interval
width and anchor age; the default maximum anchor age is sixty seconds.
`refreshTrustedTime()` installs a fresh sample from the same configured source.
Call `invalidateTimeContinuity()` when the host cannot establish continuous
monotonic time. Refreshing a sample cannot revive work whose original time or
authorization owner has already become terminal.

The `bootstrap` adapter receives an SDK-generated nonce and returns the exact
signed `TrustBootstrapResponse` and complete `RevocationState`. The SDK checks
the pinned root, nonce, trust, head and state. The adapter must bound response
memory and time, honor cancellation, finish its original request before
returning, and authenticate its own control transport. It cannot assert that an
arbitrary peer certificate or Session is trusted. Later
`refreshNamespace(authority:head:state:)` accepts a signed full head/state only
for that original configured namespace and preserves authorization revocations.

`checkContinuity` is an independently trusted host gate against copied,
rolled-back or incomplete spend history. A no-op closure is unsuitable for a
deployment that can restore or replace its history. The SDK owns bounded SQLite
one-time consumption with WAL/FULL durability; an uncertain or completed spend
never grants a retry. History is persistent security state: closing an
Environment does not delete it or authorize its reuse under a new identity.

## Original identity, material and connection

Generate an identity with `generateApplicationIdentity(profile:)`, or import
the matching provisioned private keys with
`importApplicationIdentity(profile:signingSeed:noiseStaticPrivateKey:)`.
`TransportV4ApplicationIdentity` publishes only its profile, signing public key
and Noise static public key. The signing seed is Ed25519; the selected Noise
profile fixes the static key algorithm. Provision both public keys through the
application control plane before requesting their client certificate.

Pass the exact signed Artifact, client certificate, server certificate and pool
activation authorization into `TransportV4PoolCredential`. Then prepare an
opaque material bound to the original Environment and identity:

```swift
func connectV4(
  environment: TransportEnvironment,
  identity: TransportV4ApplicationIdentity,
  credential: TransportV4PoolCredential
) async throws -> any Session {
  let material = try await environment.preparePoolMaterial(credential, identity: identity)
  defer { material.close() }
  return try await environment.connectMaterial(
    material,
    requirements: ConnectionRequirements(
      localConsumerTLS13Verification: true,
      applicationProfile: "transport"
    )
  )
}
```

`ConnectionMaterialSource.acquire(_:)` can instead supply material through
`connect(source:requirements:)`. The source must produce material prepared by
that same Environment. Unsupported requirements fail before acquisition.
`TransportEnvironment()` without configuration reports
`TransportV4AvailabilityError.runtimeUnavailable`; it does not establish a
connection or consume material.

The native owner reserves handshake and Session storage, completes TLS and the
HTTP upgrade, commits SQLite consumption, exchanges HELLO/FSB/FSA, and completes
KKpsk0 Noise plus both READY obligations before returning `Session`.
`TransportV4ConnectError` reports redacted connection failure or authenticated
`admissionRejected(code:)`. A forged rejection fails authentication. A failed
or canceled attempt cannot reuse its material, replay its activation or adopt
another connection. There is no automatic candidate retry or reconnect.

## Native TLS policy

The signed route fixes the DNS host, port, Origin policy, direct path,
`http/1.1` ALPN and `flowersec.direct.v4` subprotocol. A configured numerical IP
address supplies the socket destination while the signed DNS name supplies
SNI, HTTP Host and CA-mode hostname identity. This entrance does not resolve
DNS, follow redirects, or support an IP literal as the signed host.

Each connection uses a dedicated native TLS 1.3 handshake. CA mode uses the
provider's default trust roots or explicit `trustRootsPEM` and requires the
actual DNS SAN. Leaf-pin mode checks SHA-256 over the actual complete leaf DER,
the signed active pin interval, X.509v3 P-256 key, positive full certificate
lifetime of at most fourteen days, signing/server-authentication usage and
critical extensions. The signed pin interval must fit within the actual
certificate validity. Pin acceptance does not require CA or hostname trust;
native TLS still verifies the certificate key proof and Finished messages.

Only pins active at original TLS preparation can match. A matching pin retains
its own deadline through Session lifetime. A future rotation entry or later
trusted-time refresh cannot extend that socket. Pin failure never falls back
to CA acceptance.

## Streams and metadata

The returned `Session` supports `openStream`, `acceptStream`, `rekey`,
`probeLiveness`, `waitTermination` and `close`. Its `ByteStream` supports reads,
writes, FIN/half-close, reset and close. Flow-control credit, stream admission,
stream retirement and incoming GOAWAY use the original Session. `StreamHandlers`
can dispatch application byte streams with its normal bounded-concurrency
contract.

Construct ordinary v4 metadata with namespace, version and bounded binary
values:

```swift
let metadata = try StreamMetadata(
  namespace: "acme/chat",
  version: 1,
  values: ["content-type": Data("application/octet-stream".utf8)]
)
let exactBytes = try metadata.encodedV4()
let decoded = try StreamMetadata(encodedV4: exactBytes)
```

`v4Namespace`, `v4Version` and `v4Values` expose the validated immutable
projection. Namespaces have two lowercase components of at most 32 bytes each,
separated by `/`, with at most 64 encoded bytes overall; `flowersec/` is
reserved. The version is `UInt16`. At most 64 NFC Unicode 15.1 keys of 1–64
UTF-8 bytes map to binary values of at most 1,024 bytes. The entire deterministic
CBOR object must fit in 4,096 bytes. Duplicate or unsorted keys, noncanonical
encoding, trailing bytes, malformed text and out-of-range values are rejected
as `StreamMetadataError.invalidValue`.

Zero bytes is the sole empty sentinel and decodes as `.empty`. An ordinary
namespaced metadata object with zero entries is distinct. Incoming streams
retain the exact validated encoding. The existing JSON initializer and `values`
projection serve the v3 entrance: JSON metadata is not silently translated
into v4, and ordinary v4 metadata is not silently translated into JSON.

## Lifetime and current support boundary

Close a Session explicitly and await `waitTermination()` to join its original
read/scheduler tasks and socket. Close identity and material handles when their
work ends, and release their aliases when no longer needed. Environment close
seals admission and cancels original work. `cleanupStatus()` reports retained
resource ownership; a noncooperative source or retained charged handle can
produce `cleanupIncomplete` instead of a false completion. Configured runtime
and provider limits do not independently qualify the deployment's total RSS.

This client does not provide v4 live-authority activation, services/RPC,
execution, notifications, accepted-server sessions, tunnel paths, raw QUIC,
WebTransport, datagrams, resume, candidate racing or a v4 controller. Its
`Session.rpc` operations fail as unavailable application work. Exported
`ReaderCursor`, `WriteOperation`, `NotificationSubscription` and operation-result
types describe owned contracts; they do not by themselves add those transport
entrances. This public client currently returns `ByteStream` without a public
cursor or prepared-write factory.

## Authenticated idle and liveness

The signed idle duration starts after dual READY. Zero disables that watchdog.
Only fully authenticated and protocol-valid input, or a successful complete
native binary record write, refreshes its original monotonic anchor. Queuing,
partial work, WebSocket Ping/Pong and ignored input do not. Idle is checked
before every Session operation and refresh, including rekey and drain.
Expiration reports `SessionError.idleTimeout`; lost time continuity reports
`SessionError.timeUnavailable`. Positive idle admission covers the locally
promised rekey preparation, rate wait, barrier/provider and confirmation window.

`Session.probeLiveness()` admits at most eight independent owners. Its successful
`Duration` starts at local acceptance, including SDK and provider queuing.
`TransportV4LivenessError` exposes a finite `TransportV4LivenessFailure` and
`TransportV4LivenessProgress`: irreversible `submitted`, actual provider
`complete`, and optional `elapsedMilliseconds`. An unavailable clock has no
elapsed value. Error values contain no nonce or internal identities.

The Session uses a role-local monotonically increasing 128-bit nonce counter.
Task cancellation and the original ten-second sample deadline conclude only
that wait and matcher. They do not close an otherwise usable Session or release
a pending provider callback. The original slot and resource reference stay
owned through actual completion. Authenticated late unmatched PONGs are ignored.
Rekey intent, server REQUEST ownership and authenticated peer INIT interrupt
ordinary probes as `rekeyInProgress`; protected COMMIT/ACK positions cannot be
consumed by PING/PONG.

Automatic liveness is disabled unless `TransportV4ClientConfiguration` supplies
`automaticLiveness: TransportV4AutomaticLivenessPolicy`. Configure explicit
positive `intervalMilliseconds`, `submissionMilliseconds`,
`responseMilliseconds` and `missThreshold`. One of the eight slots is protected
for the automatic sample. Its deadline is fixed at acceptance and includes both
budgets. A miss requires complete PING handoff within the submission budget and
a full real response interval without rekey or known local read/write/resource
stall. Successful automatic PONG or independent completed rekey clears misses.
The threshold reports `SessionError.livenessPathUnresponsive`; no application
work is replayed. These deployment values require actual workload qualification.
