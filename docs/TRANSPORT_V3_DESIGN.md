# Flowersec Transport v3 Architecture

Status: final

Version: 3.0.0

This document defines the runtime, control-plane, transport-security,
Controller, and lease architecture for Flowersec v3. Wire bytes and strict
schemas are defined by TRANSPORT_V3_WIRE.md. The registry in
stability/transport_v3_contract.json is the machine-readable contract.
The only session profile in this architecture is flowersec/3.

This file is the maintained English source for the final v3 design. It is the
faithful English transcription of the approved design at baseline commit
`026cb52d116d2a04de50d0f0621fff57c7657120`; the registry and vectors are
derived from this source and cannot add or weaken its normative requirements.

## 1. Security Boundary

Flowersec is responsible for:

- strictly parsing the artifact, candidate, and TLS policy;
- canonicalizing URLs, policies, candidates, and contract hashes;
- binding TLS policy into candidate identity, FSB3, and admission;
- selecting only candidates supported by an immutable runtime capability
  snapshot;
- enforcing CA or pin through one transport-security boundary;
- keeping TLS failure before admission and durable credential submission;
- bounding artifact refresh, retries, backoff, and one-shot lease ownership;
- maintaining identical semantics in TypeScript, Go, Rust, and Swift.

The deployment system is responsible for:

- certificate issuance, renewal, revocation, and publication;
- public and private CA trust-root installation;
- deriving pins from a trusted publication process;
- choosing overlap windows and rolling certificate deployment;
- publishing structured URL plus TLS policy endpoints to the issuer.

Flowersec does not fetch pins, implement trust on first use, install roots,
manage certificate rollouts, or expose pins through Session, RPC, Stream, or
application-message APIs. Certificate pins authenticate a transport endpoint;
they are not peer identity, admission credentials, or E2EE keys.

## 2. Internal Transport Security Policy

All carriers receive exactly one internal policy:

~~~text
CA {
  server_name,
  roots_source
}

Pin {
  server_name,
  active_leaf_der_sha256[]
}
~~~

Carriers do not parse pin encoding, choose policy time, or invent fallback
semantics. Policy is produced from a validated candidate and an active-pin
snapshot before transport construction.

CA uses platform roots unless the caller explicitly supplies deployment roots.
It never bypasses chain or hostname validation. Pin uses the leaf DER hashes as
the only certificate-identity decision, while retaining the TLS provider's
CertificateVerify, Finished, transcript, ALPN, and private-key proof.

CA and pin are mutually exclusive. A CA failure never becomes pin. A pin
failure never becomes CA. The same endpoint cannot carry both modes in one
artifact, and a refreshed artifact cannot change a triggered endpoint from pin
to CA.

## 3. Adapter Requirements

### 3.1 Browser WebTransport

CA constructs WebTransport with only the normalized URL and does not set
serverCertificateHashes. Pin constructs it with:

~~~text
serverCertificateHashes: [
  { algorithm: "sha-256", value: ArrayBuffer(32) }
]
~~~

Only active pins are passed. Each candidate attempt creates an independent
WebTransport; there is no constructor-pooling option.

A synchronous NotSupportedError for pin parameters maps to tls_unsupported and
atomically changes the owning browser capability registry from enabled to
ca_only. Old capability snapshots are immutable, but every pin construction
also reads the live gate and therefore fails closed after invalidation.

Browser WebTransport ready rejection is opaque. In CA mode it is ordinary
connection_failed with retryable disposition and does not trigger policy
refresh. In pin mode, a rejection from the WebTransport ready promise remains
public connection_failed with retryable disposition and carries only the
internal browser_pin_opaque marker. Caller cancellation, timeout, or race-loser
abort is not a ready rejection: it remains ordinary cancellation/failure,
without the marker or a policy-sensitive replacement. The marker permits one
policy-sensitive replacement, does not claim a TLS reason, and cannot emit
pin-mismatch telemetry.

### 3.2 Browser WebSocket

Browser WebSocket supports CA only because its API has no per-connection
certificate pin. Constructor, pre-open error, and pre-open close failures that
cannot be layered are opaque connection_failed failures with retryable
disposition. Error text is not parsed to guess TLS causes.

### 3.3 Native TLS

Every v3 endpoint is TLS 1.3-only. Native clients and servers reject older
protocol versions at provider configuration, while browser adapters rely on
the browser secure transport and the server-side TLS 1.3 policy.

Go, Rust, Node.js, and Swift pin adapters inspect the handshake leaf
certificate, enforce the portable X.509 profile, hash complete DER, and compare
against active pins in constant time. The standard TLS provider still proves
the handshake and private key.

Browser JavaScript cannot inspect the leaf SPKI and cannot independently prove
that a WebTransport peer is P-256-only. The browser `serverCertificateHashes`
surface may accept another non-RSA algorithm according to browser policy, so an
endpoint requiring P-256-only has no cross-runtime profile or interoperability
guarantee through browser JavaScript. Flowersec SDKs MUST NOT describe this as
JavaScript verification of P-256-only; use a native verifier or an explicitly
browser-supported profile when that property is required.

A provider callback may replace PKI identity validation for pin mode. An
alternative private socket may temporarily suppress chain rejection only if
the socket remains isolated until the standard cryptographic handshake and pin
check both succeed. Before then it cannot send HTTP Upgrade, CONNECT, FSB3, or
application bytes or be exposed as a carrier. A runtime lacking either safe
path declares CA only.

Native raw QUIC and native WebTransport use the v3 ALPN and path. WebSocket uses the
v3 path and subprotocol. TLS success alone does not imply admission or Session
success.

## 4. Runtime Capability

A capability descriptor contains exactly language, runtime, schemaVersion,
tuples, and unsupported. Schema version is 3. A tuple contains exactly:

~~~text
carrier
datagrams
migration
networkMode
path
reliableStreams
securityModes
sessionRole
~~~

`language`, `runtime`, and `unsupported.reason` match
`[a-z][a-z0-9_]{0,127}`. The language/runtime pair MUST be present in the
initial registry, and each reason MUST be the exact value registered for that
runtime, carrier, and state. A reason cannot be selected from a generic shared
set. `carrier` is one of `websocket`, `raw_quic`, or `webtransport`;
`networkMode` is `dial` or `listen`; `path` is `direct` or `tunnel`; and
`sessionRole` is `client` or `server`. `reliableStreams`, `datagrams`, and
`migration` are booleans. `securityModes` is an array whose only valid dial
values are `ca`, `pin`, or `ca` followed by `pin`, without duplicates; it is
empty for listen tuples.

Tuple identity is carrier, networkMode, sessionRole, and path. Identities are
unique and strictly ordered by ASCII comparison of those four fields.
Unsupported entries contain exactly carrier and reason and are strictly
ordered by carrier. Tuples and unsupported form an exact partition of
raw_quic, websocket, and webtransport.

Direct allows dial/client and listen/server. Tunnel allows dial/client and
dial/server. Tunnel listen, direct dial/server, and direct listen/client are
invalid. Reliable streams are always true. WebSocket datagrams and migration
are false. Listen securityModes is empty. Dial securityModes is exactly ca,
pin, or ca then pin.

The initial support matrix uses the following complete tuple sets. Field order is
`(networkMode,path,sessionRole,reliableStreams,datagrams,migration)`:

~~~text
W4 = (dial,direct,client,true,false,false)
     (dial,tunnel,client,true,false,false)
     (dial,tunnel,server,true,false,false)
     (listen,direct,server,true,false,false)
W3 = (dial,direct,client,true,false,false)
     (dial,tunnel,client,true,false,false)
     (dial,tunnel,server,true,false,false)

Q4M = (dial,direct,client,true,true,true)
      (dial,tunnel,client,true,true,true)
      (dial,tunnel,server,true,true,true)
      (listen,direct,server,true,true,false)
Q4N = (dial,direct,client,true,true,false)
      (dial,tunnel,client,true,true,false)
      (dial,tunnel,server,true,true,false)
      (listen,direct,server,true,true,false)

H4 = (dial,direct,client,true,true,false)
     (dial,tunnel,client,true,true,false)
     (dial,tunnel,server,true,true,false)
     (listen,direct,server,true,true,false)
H3 = (dial,direct,client,true,true,false)
     (dial,tunnel,client,true,true,false)
     (dial,tunnel,server,true,true,false)
~~~

`W*` applies only to WebSocket, `Q*` only to raw QUIC, and `H*` only to
WebTransport. Every dial tuple takes the security modes shown in the matrix;
every listen tuple has an empty security-mode list.

| Runtime | WebSocket | Raw QUIC | WebTransport |
| --- | --- | --- | --- |
| go/native | direct and tunnel dial plus direct listen; CA and pin | same; CA and pin; dial migration | same; CA and pin; no migration |
| typescript/browser | direct and tunnel dial; CA | browser_no_raw_udp | direct and tunnel dial; CA, with pin only for exact registered provider |
| typescript/node | direct and tunnel dial plus direct listen; CA and pin | same; CA and pin; no migration | node_webtransport_driver_unavailable |
| rust/native | direct and tunnel dial plus direct listen; CA and pin | same; CA and pin; dial migration | driver_unavailable |
| swift/ios | direct and tunnel WebSocket dial; CA and pin | swift_apple_client_profile_excludes_raw_quic | swift_apple_client_profile_excludes_webtransport |
| swift/macos | direct and tunnel WebSocket dial; CA and pin | swift_apple_client_profile_excludes_raw_quic | swift_apple_client_profile_excludes_webtransport |
| swift/linux | websocket_adapter_not_supported_on_linux | swift_apple_client_profile_excludes_raw_quic | swift_apple_client_profile_excludes_webtransport |

The complete tuple booleans and ordering are frozen in capability vectors.
The first release permits only four dynamic conversions: browser WebSocket API
absence removes W3 with `browser_websocket_api_unavailable`; browser
WebTransport API absence removes H3 with
`browser_webtransport_api_unavailable`; an unloaded Node native addon removes
Q4N with `node_native_transport_unavailable`; and a browser pin allowlist miss
keeps H3 but reduces its dial security modes to CA only. No other runtime
absence may remove tuples, change booleans/security modes, or invent a reason;
`adapter_not_composed` remains a registry token but is not emitted by the
first-release descriptor. A candidate whose mode is absent from its exact dial
tuple is skipped as tls_unsupported before transport construction.

The descriptor digest is:

~~~text
SHA-256(
  "flowersec-v3-runtime-capability\0"
  || LP(JCS(descriptor))
)
~~~

### 4.1 Browser Pin Provider

The only initial browser pin provider is family Chromium with exact full
version 151.0.7922.34, supplied by Playwright 1.62.1.

Recognition requires WebTransport to be a function and a successful
navigator.userAgentData.getHighEntropyValues request for fullVersionList. The
list contains exactly one ASCII Chromium brand entry whose version is exactly
four decimal components with no leading zeros and equals 151.0.7922.34.

Missing UA-CH, rejected entropy access, duplicate Chromium entries, malformed
or different versions, legacy user-agent text, derived families, and version
ranges remain CA only. The identity is a tested provider selection, not remote
attestation.

Each registry instance is owned by one adapter or provider and may serve
multiple Controllers. State enabled exposes CA and pin for browser
WebTransport; ca_only exposes CA. A synchronous NotSupportedError linearizes
enabled to ca_only. The transition is terminal for that instance. A rebuilt
page, worker, process, or adapter creates a new instance and repeats exact
recognition.

## 5. Errors and Phase Boundary

FSA3 admission reasons, internal transport results, and public SDK errors are
separate namespaces.

| Internal result | Detail | Meaning |
| --- | --- | --- |
| invalid_artifact | none | Schema, encoding, ordering, or binding input invalid |
| expired_artifact | none | Initiation reached exclusive expiry |
| tls_unsupported | none | Runtime tuple cannot enforce the mode |
| tls_policy_expired | none | Attempt has no active pin |
| tls_failed | ca_untrusted | Native verifier proves CA identity failure |
| tls_failed | pin_mismatch | Valid static pin profile but leaf hash differs |
| tls_failed | unknown | Native verifier localizes TLS but cannot classify further |
| connection_failed | browser_pin_opaque | Browser pin WebTransport rejection is opaque |

Public codes are artifact_invalid, expired_artifact,
transport_security_unsupported, transport_security_failed, and
connection_failed. Public retry disposition is terminal, retryable, or
retry_after with an absolute Unix millisecond integer in
0..253402300799999 inclusive. The value is a safe, non-negative integer; a
fraction, negative value, value above 253402300799999, or non-finite value is
invalid at the source/adapter boundary and is projected to artifact_invalid
terminal.

Every boundary validates a disposition. Invalid source or adapter
retry_after is a contract violation and becomes artifact_invalid terminal
before scheduler entry. Multiple valid deadlines aggregate by maximum.
Public errors never reveal URL, pin, certificate, native TLS text, credential,
lease identity, or private FSA3 reason.

When a server revalidates an FSB3 at or after its initiation expiry, it sends a
retryable FSA3 with the audited `expired_artifact` reason and refuses admission.
The client treats that as a remote redacted admission failure; it never derives
the local public `expired_artifact` code from a remote reason string. The local
code is produced only by the client's own trusted-clock checks before or after
the candidate race, before FSB3, or at the local spend boundary.

Static pin profile checks occur after a leaf is observable. A valid profile
with unmatched hash may be pin_mismatch. A TLS failure before the leaf can be
classified, an invalid profile, or a proof failure after hash match is unknown.
Both have the same public security failure and refresh behavior. Browsers never
claim these native details.

TLS failure occurs before durable spend and FSB3 and is never represented as
FSA3.

Server admission is one bounded phase across FSB3 receive, deployment
authorization, accepted-session handler resolution, FSA3 completion, and
Session establishment. The trusted authorization-record verifier receives the
opaque stored artifact and observed request, reprojects and compares the
complete FSB3 before minting a request-bound, secret-free grant. The relay
consumes only that grant, so it cannot authorize a same-credential request with
altered session, candidate, TLS, role, or endpoint claims and never receives the
Session contract or E2EE key. Listener shutdown first cancels the phase, then
force-closes non-responsive upgraded and pre-upgrade sockets at its cleanup
deadline.

The re-projection is field-exact. The common FSB3 fields are taken from the
artifact profile, session channel and contract hash, path rendezvous group and
listener audience, canonical candidate set and its hash, and the selected
candidate ID. Direct artifacts additionally project `path.routing_token` and
MUST omit `attach_token`, `endpoint_instance_id`, and `role`. Tunnel artifacts
project `path.token`, `path.local_endpoint_instance_id`, and `path.role`, and
MUST omit `routing_token`; tunnel roles `1` and `2` mean client and server
respectively. Missing fields, cross-variant fields, role mismatches, or any
unequal projected value fail admission closed.

## 6. Candidate Race and Aggregation

Unsupported candidates are skipped without transport construction. Explicitly
authorized different endpoint keys may race even when their modes differ.
This is not fallback because each endpoint and policy is artifact-bound.

A winner cancels and closes every loser; cancellation cannot overwrite the
winner. After all failures, the Controller first rechecks artifact expiry and
then aggregates independent of completion order:

1. invalid artifact is artifact_invalid terminal;
2. local initiation expiry is expired_artifact retryable and requests a new
   primary artifact;
3. an executable policy trigger may start the one replacement flow;
4. an exhausted or invalid security trigger is transport_security_failed
   terminal;
5. an exhausted browser opaque trigger is connection_failed terminal;
6. all unsupported is transport_security_unsupported terminal;
7. ordinary failures retain connection_failed and aggregate dispositions by
   latest retry_after, then retryable, then terminal;
8. any otherwise empty result is connection_failed terminal.

## 7. Policy-Sensitive Replacement

A connection cycle starts with initial Start or a reconnect decision and ends
at Session establishment or terminal failure. It may acquire multiple primary
artifacts but at most one policy-sensitive replacement lease.

A pin trigger is tls_policy_expired, native pin mismatch or unknown TLS
failure, or browser_pin_opaque. Each triggered endpoint key and declared TLS
policy digest is added to a monotonic blocked set.

Before every later race:

- the same endpoint with CA is blocked;
- the same endpoint with a blocked pin-policy digest is blocked;
- only a new, unblocked pin digest may retry that endpoint;
- other explicit endpoint keys remain eligible.

After retiring triggering primary A, the first replacement acquisition begins
immediately when the attempt budget permits. Source failures while searching
for B use normal bounded backoff and remain in replacement acquisition.
Replacement quota is consumed only when B is acquired and claimed.

B is a valid replacement only if at least one triggered endpoint remains pin
and has a different complete declared-policy digest. Its race candidates are:

~~~text
changed triggered endpoints
union endpoints new in B
union endpoints in A that neither failed nor were skipped
~~~

Apply the latest immutable capability snapshot and blocked-policy filter. A
same-endpoint pin-to-CA candidate never enters. B with no changed policy,
invalid content, or empty eligible set is retired and the cycle becomes
terminal according to trigger provenance.

A pre-race or no-winner race-end B expiry retires B and may return to ordinary
primary acquisition after backoff, but replacement quota and the blocked set
remain. A B pre-spend failure that is not expiry is terminal. A post-spend
retryable admission or Session failure may return to primary acquisition, but
B stays consumed and replacement quota never returns. A later policy trigger
is terminal.

## 8. Scheduler

One scheduler permits at most one ArtifactSource Acquire or connector attempt
at a time. Start is idempotent. Close wins over timers, retryNow, and new work.

maximumAttempts is a safe integer. Zero means unlimited. Before every primary
or replacement Acquire, the cycle counter is checked and then incremented with
saturation. Exhaustion keeps the last redacted code and phase but forces
terminal disposition and removes retry_after.

The public failure phase is the closed `artifact`, `connect`, or `session` set
in every SDK. Go exposes it through `ConnectionFailure.Phase()` while retaining
the original two-field `ConnectionFailure` layout; its internal phase carrier
preserves normal `errors.Is` and `errors.As` traversal. TypeScript carries the
same string in the failure snapshot, while Rust and Swift preserve it in their
closed failure enum cases.

Rust exposes the canonical redacted `ConnectErrorCode` through
`ArtifactSourceError::code()` and `ConnectionFailure::code()`. These accessors
preserve the source, connect, and session failure boundaries without exposing
underlying source, transport, credential, or peer diagnostics.

A source failure increments consecutive failures once. Each claimed lease
that does not establish a Session increments once at its unique final result.
Candidate failures, loser cancellation, repeated checks, and Close do not add
counts. Successful Acquire alone does not reset the count. Session
establishment resets the count and ends the cycle.

Failure ordinal n waits:

~~~text
min(250 * 2^(n-1), 30000) milliseconds
~~~

The first failure has ordinal 1 and therefore a 250 ms floor; the ordinal is
reset only after Session establishment. Jitter is exactly zero. Backoff uses a
monotonic clock and saturating arithmetic, including the exponent and the
30,000 ms ceiling. Artifact, policy, certificate, and retry-after times use a
trusted wall clock. A retry_after wait is the later of the monotonic backoff
deadline and the absolute wall-clock deadline. Wall-clock forward jumps can
satisfy only the wall condition; backward jumps delay it. Implementations
reread wall time after every wake and at least every 1,000 monotonic
milliseconds, and never convert the absolute deadline into an unbounded sleep.

retryNow wakes only an existing wait, may skip remaining backoff, and cannot
cross a future absolute deadline. It returns false outside waiting or after
terminal or closed state.

## 9. One-Shot Lease

Lease wrappers sharing one lease identity share one atomic state:

~~~text
idle -> claimed -> spending -> consumed
                  -> retired
~~~

claim is the only idle-to-claimed operation and returns an unforgeable internal
ownership token. Public one-shot connect and Controller acquisition claim at
entry. commitSpend exists only on the claimed token and starts
claimed-to-spending. Any durable-spend success, failure, cancellation, or
unknown result ends consumed. retire exists only on the claimed token and ends
retired. Both terminal states are irreversible.

A pre-spend validation, capability, TLS, cancellation, or abandonment path
retires. Once spend begins, admission and Session failures never retire.
Cleanup runs at most once; its failure is redacted and cannot restore a lease.
ArtifactSource never returns the same lease identity twice.

Acquire returns exactly one idle lease or one ArtifactSourceError. Ownership
linearizes at delivery. If cancellation wins, the source hides any late lease,
claims it through the same atomic operation, and retires it. If delivery wins,
the Controller claims and retires even if cancellation follows immediately.
Runtimes unable to atomically cancel promises drain the late result using the
same ownership rule. Close publishes closed immediately but asynchronous Close
waits for in-flight Acquire settlement and cleanup.

Claim losers and ownership contract violations become artifact_invalid
terminal and never reach a connector.

## 10. Go Control Plane

The Go v3 issuer accepts structured EndpointConfig values with an explicit,
stable ID, URL, and opaque TLSPolicy. An ID obeys the candidate-ID constraints
and MUST NOT be derived from array position or the number of endpoints using a
carrier. URL scheme mapping is exactly `wss` to `websocket`, `quic` to
`raw_quic`, and `https` to `webtransport`; every other scheme is invalid.
CAPolicy constructs CA. PinPolicy accepts 1..4 CertificatePin values, each
containing a fixed 32-byte SHA256 value and a whole-second NotAfter time. A zero
TLSPolicy is invalid and never means CA.

PinPolicy rejects empty or oversized sets, duplicate hashes, subsecond times,
and times outside 1..9007199254740991. It converts to UTC Unix seconds,
base64url-encodes internally, and sorts by encoded ASCII value rather than raw
hash bytes.

NewEndpointSet performs clock-independent structural validation for 1..4
endpoints. IssueDirect and IssueTunnelPair sample one issuance_now and repeat
full path-aware validation, URL normalization, endpoint-key uniqueness,
canonicalization, and the requirement that every pin policy has at least one
pin where issuance_now is before expiry. No issuer path connects to an
endpoint, fetches a certificate, computes a pin, or changes roots.
If every pin in a policy is expired at issuance_now, issuance returns
`invalid_tls_policy` with field path `endpoints[<index>].tls`.

ControlPlaneError is redacted and provides a stable code and field path.
Allowed codes are invalid_endpoint_count, invalid_endpoint_id,
invalid_endpoint_url, duplicate_endpoint, invalid_tls_policy, and invalid_pin.
It unwraps to ErrInvalidControlPlaneInput. Non-endpoint invalid issuer input
returns that sentinel directly. Randomness or provider failure returns the
separate ErrIssuanceFailed. Debug and string output never reveal endpoint or
certificate material.

Only Go supplies the v3 issuer. TypeScript, Rust, and Swift consume issued
artifacts; their control-plane modules do not issue or mutate v3 records.
`ControlPlaneError` has fixed `Error()`, `Code()`, `FieldPath()`, and
`Unwrap()` accessors. Callers use `errors.As` to recover `ControlPlaneError`;
`Unwrap()` returns only `ErrInvalidControlPlaneInput`, which callers may match
with `errors.Is`. `ErrIssuanceFailed` is independent and is never wrapped by or
projected as `ControlPlaneError`. The exact public symbol and error inventory
is frozen in `stability/api_contract_manifest.json`.

The typed issuer surface is normative and has no URL-only compatibility
overload:

~~~go
type EndpointConfig struct { ID string; URL string; TLS TLSPolicy }
func NewEndpointSet(endpoints ...EndpointConfig) (EndpointSet, error)
func CAPolicy() TLSPolicy
func PinPolicy(pins ...CertificatePin) (TLSPolicy, error)
type ControlPlaneErrorCode string
type ControlPlaneError struct { /* private fields */ }
func (e *ControlPlaneError) Error() string
func (e *ControlPlaneError) Code() ControlPlaneErrorCode
func (e *ControlPlaneError) FieldPath() string
func (e *ControlPlaneError) Unwrap() error
~~~

The six `ControlPlaneErrorCode` values are exactly
`invalid_endpoint_count`, `invalid_endpoint_id`, `invalid_endpoint_url`,
`duplicate_endpoint`, `invalid_tls_policy`, and `invalid_pin`. `FieldPath()`
is restricted to `endpoints`, `endpoints[<index>]` plus `.id`, `.url`, `.tls`,
or `.tls.pins[<index>].not_after`, and the pin constructor paths `pins`,
`pins[<index>]`, `pins[<index>].sha256`, and `pins[<index>].not_after`.
`Error()` is always `flowersec control-plane input is invalid`; it never
contains URLs, pins, certificates, credentials, or parser text. Endpoint and
TLS revalidation errors use `ControlPlaneError` and unwrap only to
`ErrInvalidControlPlaneInput`; invalid non-endpoint issuance input returns that
sentinel directly, while provider or randomness failures return the independent
`ErrIssuanceFailed` (`flowersec artifact issuance failed`). `PinPolicy` stores
whole-second UTC expiry and canonical base64url SHA-256 pins sorted by encoded
ASCII value, and rejects zero, duplicate, oversized, subsecond, or out-of-range
pin sets. These rules apply equally to `IssueDirect` and `IssueTunnelPair`.

## 11. Certificate Rotation

Deployment publishes an artifact containing old and new pins before switching
the server certificate, waits for distribution, switches the certificate,
keeps both pins through the overlap window, and later removes or explicitly
expires the old pin. Pin expiry is no later than certificate NotAfter.

Flowersec enforces the artifact exactly. It adds no grace period and does not
extend pin time. A deployment that switches too early can require the single
bounded refresh, but no SDK changes mode or repeatedly retries the old policy.

## 12. Implementation and Release Plan

### 12.1 Contract Freeze

Before public API implementation begins:

1. Register this English design, every field, registry rule, limit, domain
   label, and vector family in `stability/transport_v3_contract.json`.
2. Generate the v3 artifact, URL/IDNA, capability, Controller, FSB3/FSA3,
   handshake, cryptographic, session-wire, DATAGRAM, Unicode, and invalid-input
   vectors.
3. Require the stability checker to scan every v3 implementation and reject
   residual v2 magic, profiles, paths, or cryptographic labels on v3 paths.
4. Record every scalar and URL rule in section 5, the closed tuple universe in
   section 8, and every scheduler constant in section 10.4 as machine-readable
   contract data; examples alone are insufficient.
5. Freeze the registry and vectors before implementing public APIs.

### 12.2 Codecs and Core State Machines

The four SDKs MUST:

1. Implement JCS, artifact v3, candidate/TLS policy, and FSB3/FSA3 codecs in
   TypeScript, Go, Rust, and Swift.
2. Implement the complete `FSC3`, `FSH3`, `FSS3`, `FSR3`, and `FSD3` frame
   family with the v3 domain labels.
3. Update acceptor, tunnel-authorization, and admission-binding validation.
4. Implement the capability v3 schema and digest.
5. Keep v2 code paths physically isolated; helpers carrying versioned domain
   labels MUST NOT be shared between v2 and v3.

### 12.3 Adapters and Controller

The implementation MUST:

1. Use structured endpoint configuration in the Go control plane.
2. Route every carrier through the unified `TransportSecurityPolicy` and its
   runtime verifier.
3. Pass real constructor options to browser WebTransport.
4. Maintain an exact browser/runtime capability registry.
5. Implement active-pin snapshots, error projection, lease retirement, and the
   one-refresh state machine.

### 12.4 SDK Major and Deployment Isolation

The SDK and deployment boundary is explicit and versioned:

- the Go module uses the `/v3` module path;
- the TypeScript package, Rust crate, and Swift package/tag are released as
  v3 majors;
- v3 uses an independent server path, WebSocket subprotocol, and QUIC ALPN;
- v2 artifacts cannot be passed to v3 APIs, and v3 artifacts cannot be passed
  to v2 APIs;
- a parallel migration runs independent v2 and v3 listeners, with the
  application explicitly selecting the SDK major;
- Flowersec provides no runtime automatic upgrade or downgrade between v2 and
  v3.

## 13. Verification and Implementation Acceptance Gates

Before a v3 feature enters `main`, declares a capability, or forms a release,
the relevant precommit, CI, or explicit engineering workflow MUST pass all of
the following gates.

### 13.1 Cross-Language Vectors

TypeScript, Go, Rust, and Swift MUST produce byte-identical results for every
vector, including at least:

- CA, one-pin, two-pin, and four-pin candidates;
- every session, path, and correlation scalar's character set, minimum,
  maximum, fixed value, and cross-field constraint;
- pin ordering, duplicates, unknown algorithms, invalid base64url, and integer
  boundaries;
- signed safe integers, Unicode keys, array ordering, and every depth, node,
  member, string, and byte boundary in `scoped.payload`;
- single, partial, and fully expired pins, including equality with the expiry
  instant;
- initiation expiry before a race, after a primary/replacement race with no
  winner, before spend, after spend and before FSB3, and at server admission;
- UTS #46 URL normalization, Unicode 15.1 deltas, IPv4/IPv6, default and
  non-default ports, each rejection branch, duplicate endpoints, and same-
  endpoint CA/pin conflicts;
- candidate, candidate-set, TLS-policy, session-contract, and capability
  digests;
- every runtime identity, closed tuple set, carrier partition, reason token,
  and invalid boolean/path/role combination;
- `retry_after` values `0`, `253402300799999`, past/future values, and taking
  the later of multiple deadlines, plus rejection and `artifact_invalid /
  terminal` projection for negatives, fractions, strings, NaN, Infinity,
  `253402300800000`, sub-millisecond platform times, and values that cannot
  round-trip exactly;
- two- and four-pin cases where raw SHA-256 byte order differs from canonical
  base64url ASCII order, plus Go-issuer to four-language decoder round trips;
- direct/tunnel FSB3 field-by-field artifact projection, role interpretation,
  cross-variant rejection, FSA3, and admission binding;
- single- and multi-candidate acceptor-admissions hashes;
- all `FS*3` frames, transcript, KDF, MAC, AAD, rekey, and unreliable-message
  vectors;
- cross-version rejection of v2/v3 magic, profile, path, ALPN, and labels;
- unknown or missing fields, duplicate keys, non-JCS bytes, invalid UTF-8,
  boundaries, and trailing bytes;
- cross-cases proving that inherited FSH3, OPEN, and RPC codecs do not receive
  artifact-JCS rejection rules accidentally.

### 13.2 Real TLS and Browser Tests

Tests MUST use real TLS handshakes and production adapters; monkey-patching
`WebTransport` and asserting constructor parameters alone is insufficient. The
matrix MUST cover:

- public CA and pre-installed private CA;
- self-signed ECDSA P-256 pins;
- a short-profile CA-issued ECDSA P-256 leaf with the correct pin, proving pin
  mode does not use chain trust;
- old certificate, new certificate, and dual-pin overlap;
- wrong, expired, not-yet-valid, and over-1209600-second certificates;
- a public-CA-trusted certificate with a wrong pin, proving pin parameters are
  not silently ignored;
- on every native verifier/provider path, the correct pinned DER paired with a
  wrong private key or damaged `CertificateVerify`, failing before carrier
  exposure, durable spend, or FSB3;
- on every native verifier/provider path, non-P-256, overlong, currently
  invalid, and invalid-proof certificates mapping to `tls_failed + unknown`;
  a statically valid profile with a mismatched hash MAY map to `pin_mismatch`,
  while a provider failure before leaf inspection maps to `unknown`; public
  behavior and refresh are identical. Browser tests cover only standard
  WebTransport constraints and the declared profile boundary and MUST NOT
  claim JavaScript observed a non-P-256 certificate;
- CA mode without `serverCertificateHashes`, pin mode with active pins only;
- browser WebSocket pin omission and `tls_unsupported` for WebTransport
  providers without hash support;
- opaque CA-mode WebTransport DNS/QUIC/CONNECT/Origin/path/TLS `ready`
  rejections and browser WebSocket pre-open failures as ordinary
  `connection_failed / retryable`, never `transport_security_failed` or a
  refresh trigger; the same pin-mode WebTransport rejection remains public
  `connection_failed / retryable` but carries `browser_pin_opaque` and performs
  one section-10.3 replacement;
- the browser registry's exact Chromium `151.0.7922.34`, unmatched or missing
  UA-CH CA-only descriptors, synchronous `NotSupportedError` enabled-to-
  `ca_only` linearization, immutable old snapshots with a live gate, registry
  rebuild/re-identification, and a real production-adapter test proving a
  public-CA certificate with a wrong pin fails;
- no CA downgrade for pin mismatch, policy expiry, or unknown TLS failure;
- TLS 1.3-only servers, rejected 0-RTT, disabled resumption, dedicated
  non-pooled WebTransport connections, and TLS failure before durable spend or
  FSB3.

The first required pin-WebTransport browser is Chromium `151.0.7922.34`,
paired with `@playwright/test 1.62.1`. Tests and the machine-readable registry
MUST verify that exact version; the default browser job MUST NOT silently
downgrade to CA-only or skip pin coverage. Firefox and WebKit still run
capability/unsupported tests and become pin-interoperability requirements only
after entering the supported browser/version registry.

### 13.3 Controller and Security Invariants

Model, fault-injection, and concurrency tests MUST prove:

- at most one policy-sensitive replacement lease per connection cycle;
- no infinite retry of an unchanged TLS policy;
- changed policy uses a fresh artifact and fresh lease;
- an unspent retired lease is never reused;
- a lease with an unknown spend result is never reused;
- race losers are closed and cannot write FSB3;
- unsupported candidates are skipped before transport construction;
- duplicate candidates cannot create a CA downgrade path for one endpoint;
- an established Session is not interrupted when pin policy expires;
- cancellation, retry-after, backoff, and maximum attempts remain effective.

Controller vectors MUST additionally prove source/aggregate failure counting,
candidate-failure non-duplication, exactly-once expiry checks at each lease
phase, immediate first B acquisition after an A refresh, B-expiry ordinal and
backoff, no reset on successful Acquire, reset on Session establishment and
termination, the `250 ms * 2^(n-1)` 30-second cap, monotonic backoff combined
with a valid absolute Unix-millisecond deadline, wall-clock jumps and periodic
re-reads, saturating timer differences, `retryNow` skipping only backoff, and
terminal disposition on attempt exhaustion. Invalid `retry_after` becomes
`artifact_invalid / terminal` before the scheduler and creates no timer.

They MUST cover CA `ca_untrusted`, mixed CA/TLS and ordinary failures, multiple
triggers, same-endpoint pin-to-CA rejection, retryable B acquisition, B expiry
before and after a no-winner race (without restoring replacement quota),
cleanup failure, and completion-order permutations. Browser coverage includes
one `browser_pin_opaque` replacement, changed-pin success, same-endpoint
CA/same-digest filtering, exhausted opaque-trigger behavior, ordinary retry
before refresh, quota persistence across ordinary retry, exact saturated
`maximumAttempts` counts for A/B/source acquisitions, concurrent one-shot and
Controller claims, cancellation-first source retirement, delivery-first
Controller retirement, Close waiting for cleanup, and capability invalidation
barriers across two concurrent acquisitions and replacement B.

Primary and replacement paths MUST cover a TLS winner followed by
`commitSpend`, then FSA3 reject/retryable or FSH3 failure: the lease remains
consumed, terminal keeps the original error, retryable/retry-after returns to
ordinary primary acquisition, replacement quota is not restored, and a later
policy trigger cannot obtain a second replacement.

Go issuer tests MUST inject a clock and cover zero/five endpoint sets, zero-value
EndpointSet projection as `invalid_endpoint_count / endpoints`, all pins
expired at issuance, equality with expiry, zero-value and unknown TLS tags, all
six ControlPlaneError codes/paths/unwrapping/redaction, non-endpoint
`ErrInvalidControlPlaneInput`, independent `ErrIssuanceFailed`, and the raw
SHA-256 versus base64url comparator reversal. Client time tests inject internal
wall/monotonic clocks for `attempt_now == not_after_unix_s`, race-end expiry,
wall-clock jumps, and monotonic backoff; clock injection is not public or wire
API.

### 13.4 Acceptance and Release Boundary

V3 is releasable only when all of the following hold:

- the machine-readable registry and this English design's semantics agree;
- all four language codecs and vectors agree;
- every declared capability has a real production-adapter test;
- public CA, private CA, and self-signed pin environments have end-to-end
  evidence;
- v2/v3 isolation, no downgrade, and one-shot lease invariants pass;
- every public error and debug representation passes redaction tests;
- unimplemented support-matrix cells are explicitly `unsupported`, never
  disguised as skipped tests.

These tests are not run by the release command and produce no evidence,
receipt, or test artifact consumed by release. `scripts/release.sh` performs
only version/ref validation, packaging, release-artifact signing, publication,
and registry readback; test results must be established by the engineering
gates before release.

## 14. Explicit Exclusions

Transport v3 does not encode pins in URLs or imitate libp2p multiaddresses. It
provides no trust on first use, dynamic pin retrieval, first-certificate trust,
`pin-or-ca`, `prefer-pin`, or any other mixed or fallback trust mode. Artifacts
never contain a root certificate, complete certificate chain, or private key,
and Session, RPC, Stream, and application APIs never expose pins.

Flowersec does not issue certificates, manage certificate authorities, or
orchestrate deployment. Transport v3 does not redesign E2EE, RPC, stream,
DATAGRAM, or application interfaces. Production artifacts permit no plaintext
loopback. The wire protocol does not negotiate v2/v3 versions, and failure
never falls back to another version.

## 15. Final Security Invariants

All v3 implementations and subsequent changes MUST preserve these invariants:

1. A candidate's TLS mode and complete declared pin set are admission-bound
   data.
2. One endpoint has exactly one TLS policy in an artifact.
3. Pin trust is based only on active leaf-certificate hashes; no implicit CA
   path is added.
4. CA mode performs complete platform PKI validation and adds no implicit pin
   or insecure verifier.
5. Unsupported, expired, and failed candidates never trigger mode downgrade.
6. TLS failure never enters the FSA3 namespace.
7. Before TLS success, no lease is durably spent and no credential is sent.
8. A lease serves at most one attempt that might submit credentials, and a
   retired lease is never reused.
9. Each connection cycle obtains at most one policy-sensitive replacement lease
   and never loops on the same old policy.
10. V2 and v3 magic, profiles, paths, ALPN, subprotocols, hashes, and
    cryptographic domains are completely isolated.

---

# Flowersec Transport v3 Wire Contract

Status: final

Version: 3.0.0

This is the normative English wire specification for Flowersec Transport v3.
Its normative source is the final English design recorded in
`stability/transport_v3_contract.json` under `design`: version `3.0.0`,
baseline commit `026cb52d116d2a04de50d0f0621fff57c7657120`, and SHA-256
`17d85ca8f20a534c69fb78014e8942bafc7096f510c1a75019634691f250e0c0`.
The checked-in release-controlled source input is
`docs/TRANSPORT_V3_DESIGN.md`; release tooling MUST verify that file
against the recorded digest before regenerating derived artifacts. This
document is its complete English transcription. This document, the
machine-readable registry, and the vectors are derived consistency artifacts.
A conflict among them or with the source design blocks release; no derived
artifact can replace or expand a general rule from the source design. MUST,
MUST NOT, SHOULD, SHOULD NOT, and MAY have the meanings from RFC 2119 and RFC
8174.

## Normative v2 Baseline and Priority

Rules not explicitly rewritten by the English v3 design are inherited from the
frozen v2 baseline at design commit `026cb52d116d2a04de50d0f0621fff57c7657120`:

- `docs/TRANSPORT_V2_WIRE.md` and `stability/transport_v2_contract.json` for
  frame lengths, offsets, reserved values, session wire, and application codec
  rules;
- `docs/TRANSPORT_V2_ARCHITECTURE.md` and the same registry only for the
  carrier tuples, lifecycle, and Controller baseline explicitly referenced by
  v3;
- the v2 registry `wire_fixtures` vectors for fields, byte order, registry
  values, and canonical codec behavior explicitly frozen by the v2 wire
  document;
- `testdata/transport_v2/connection_controller_vectors.json` and
  `stability/connection_controller_recovery.json` only for Controller
  lifecycle and error-recovery mappings not rewritten by v3.

Normative priority is:

1. the final English v3 design;
2. the frozen v2 baseline sources listed above, only within their stated
   inherited scope; and
3. the audited v3 machine-readable registry and v3 vectors generated from the
   final design.

This English transcription is a required derived consistency artifact, not an
independent priority tier. Source code, v2 runtime behavior, and any other
document cannot add a v3 exception. A missing or conflicting derived artifact
blocks release.

## 1. Fixed Identifiers

| Item | Value |
| --- | --- |
| Artifact version | 3 |
| Session profile | flowersec/3 |
| Direct profile and raw QUIC ALPN | flowersec-direct/3 |
| Tunnel profile and raw QUIC ALPN | flowersec-tunnel/3 |
| Direct WebSocket path | /flowersec/v3/direct |
| Tunnel WebSocket path | /flowersec/v3/tunnel |
| Direct WebSocket subprotocol | flowersec.direct.v3 |
| Tunnel WebSocket subprotocol | flowersec.tunnel.v3 |
| Direct WebTransport path | /flowersec/webtransport/v3/direct |
| Tunnel WebTransport path | /flowersec/webtransport/v3/tunnel |
| Correlation and capability version | 3 |

Production candidates allow only wss, quic, and https. Cleartext loopback is
confined to a test-only profile that cannot issue production artifacts. A
connection performs no version negotiation and MUST NOT fall back to another
version after a v3 failure.

## 2. Primitive and JSON Encoding

Unsigned integer fields use big-endian byte order. LP(x) is a four-byte
unsigned length followed by x. Base64url is RFC 4648 URL-safe base64 without
padding; decoding to the required length and re-encoding MUST reproduce the
input exactly.

Fixed-schema JSON numbers are integers in 0..9007199254740991 unless a narrower
limit is stated. Floats, exponents, negative zero, non-finite numbers, and
lossy conversions are invalid.

The complete artifact, FSB3 payload, runtime capability descriptor, canonical
candidate, TLS policy, candidate set, session contract projection, and every
input explicitly named JCS use RFC 8785 JSON Canonicalization Scheme.
Decoders MUST reject duplicate keys before object construction, invalid UTF-8,
a BOM, unknown or missing fixed fields, non-canonical bytes, trailing bytes,
bad base64url, invalid array order or duplicates, and resource-limit
violations.

Those rejection rules apply only to the JCS objects listed above. The FSH3 JSON
payload inherits the frozen FSH2 canonical encoding and handshake vectors byte
for byte, with only the specified v3 version and domain replacements. RPC and
application JSON retain the fixed v2 codec and value domain. FSH3, FSS3, OPEN,
RPC, and application payloads MUST NOT be subjected to artifact/FSB3 JCS
rejection rules; each retains its own inherited or explicitly specified codec.

JCS never reorders arrays. Artifact candidates accept input order but canonical
candidates sort by candidate ID. Canonical candidates, capability tuples, and
unsupported carrier entries require their specified strict ASCII order. Pins
require strict algorithm then encoded-value ASCII order. Allowed suites require
strict numeric order. Scopes and correlation tags retain input order and reject
duplicate names.

## 3. Artifact

The raw artifact and its canonical UTF-8 form are each at most 65,536 bytes and
MUST be identical. The root contains exactly:

~~~text
v, profile, session, path, scoped, correlation
~~~

v is 3 and profile is flowersec/3.

### 3.1 Session

Session contains exactly:

~~~text
channel_id
init_expire_at_unix_s
idle_timeout_seconds
establish_timeout_seconds
rekey_prepare_timeout_seconds
rekey_completion_timeout_seconds
max_inbound_streams
e2ee_psk_b64u
allowed_suites
default_suite
selected_features
contract_hash_b64u
~~~

| Field | Constraint |
| --- | --- |
| channel_id | [A-Za-z0-9._~-]+, 1..128 UTF-8 bytes |
| init_expire_at_unix_s | integer 1..9007199254740991, exclusive expiry |
| idle_timeout_seconds | integer 0..4294967295; zero disables it |
| establish_timeout_seconds | 30 |
| rekey_prepare_timeout_seconds | 10 |
| rekey_completion_timeout_seconds | 30 |
| max_inbound_streams | integer 1..128 |
| e2ee_psk_b64u | canonical encoding of exactly 32 bytes |
| allowed_suites | non-empty, strictly ascending, values only 1 and 2 |
| default_suite | a member of allowed_suites |
| selected_features | 0 |
| contract_hash_b64u | exact 32-byte contract hash |

The session contract projection contains allowed_suites, channel_id,
default_suite, establish_timeout_seconds, idle_timeout_seconds,
max_inbound_streams, profile, rekey_completion_timeout_seconds,
rekey_prepare_timeout_seconds, and selected_features. Profile is flowersec/3.

~~~text
session_contract_hash = SHA-256(
  "flowersec-v3-session-contract\0"
  || LP(JCS(session_contract_projection))
)
~~~

Initiation is expired when trusted wall-clock now is greater than or equal to
init_expire_at_unix_s. The client checks before every race, after a no-winner
race, before durable spend, and after spend starts but before FSB3. The server
checks when it receives FSB3. A pre-spend lease is retired. Once spend begins,
the lease remains consumed, but FSB3 is not sent after local expiry.

### 3.2 Path

A direct path contains exactly kind, rendezvous_group_id, listener_audience,
routing_token, and candidates. Kind is direct.

A tunnel path contains exactly kind, rendezvous_group_id, listener_audience,
role, local_endpoint_instance_id, expected_peer_endpoint_instance_id, token,
and candidates. Kind is tunnel. Role 1 creates a client-role Session; role 2
creates a server-role Session. Endpoint instance IDs differ.

Registry IDs match [A-Za-z0-9._~-]+ and are 1..128 UTF-8 bytes. Direct routing
tokens and tunnel tokens are 1..8192 ASCII bytes.

### 3.3 Scoped and Correlation Data

There are at most eight scopes. Each contains exactly scope, scope_version,
critical, and payload. Scope matches [a-z][a-z0-9._-]{0,63}, is unique, and
has version 1..65535.

Payload is an object containing objects, arrays, strings, booleans, null, and
integers in -9007199254740991..9007199254740991. Limits are 4096 JCS bytes,
depth 16 with root at one, 256 total nodes, 64 object members, 64 array
elements, 128 UTF-8 bytes per key, and 1024 UTF-8 bytes per string.
Implementations enforce depth, node, and collection limits before recursive
allocation.

Correlation contains exactly v and tags. v is 3. There are at most eight
ordered tags. Each tag contains exactly key and value. Key matches
[a-z][a-z0-9._-]{0,31} and is unique. Value is 1..128 ASCII bytes.

## 4. Candidate and Endpoint Identity

There are 1..4 candidates. Each contains exactly id, carrier, url,
wire_profile, and tls. ID matches [a-z0-9][a-z0-9._-]*, is 1..64 bytes, and is
unique. Carrier is websocket, raw_quic, or webtransport. Wire profile matches
the path.

normalized_url is derived and is forbidden in artifact input. A canonical
candidate contains exactly carrier, id, normalized_url, tls, and wire_profile.
It is at most 2304 bytes. The canonical candidate array is at most 12,288 bytes
and is in strict ID ASCII order.

The endpoint key is carrier, path kind, and normalized URL. It is unique in an
artifact. One endpoint cannot occur once with CA and again with pin.
Certificate rotation uses multiple pins in one policy.

~~~text
candidate_set_hash = SHA-256(
  "flowersec-v3-candidates\0"
  || LP(JCS(canonical_candidates))
)
~~~

## 5. URL Normalization

Implementations apply this algorithm directly:

1. Require 1..2048 UTF-8 bytes and reject backslash, question mark, hash, or
   percent.
2. Split at the first literal colon-slash-slash. The scheme matches
   [A-Za-z][A-Za-z0-9+.-]* and is lowercased. Split the remainder at the first
   slash. Authority is non-empty and has no at sign.
3. A bracketed authority is IPv6 with an optional port. Reject zone IDs and
   embedded dotted-decimal IPv6. Emit RFC 5952 lowercase compressed form. An
   unbracketed authority has at most one colon.
4. An all-digit-and-dot host is exactly four decimal IPv4 components in
   0..255, with no leading zero except the single digit zero. Otherwise apply
   Unicode 15.1 UTS 46 lookup, non-transitional, with STD3, label, hyphen,
   ContextJ, Bidi, and DNS-length checks. Emit lowercase A-labels. Reject empty
   labels, trailing dot, labels over 63 bytes, hosts over 253 bytes, and a
   final ASCII label matching decimal digits or case-insensitive
   0x[0-9a-f]*.
5. Port is decimal 1..65535. Remove leading zeroes and omit 443.
6. WebSocket requires wss and the exact WebSocket path. WebTransport requires
   https and the exact WebTransport path. Raw QUIC requires quic, accepts only
   empty path or slash, and emits an empty path.
7. Emit scheme, normalized authority, and normalized path. The result remains
   at most 2048 bytes.

Browser adapters additionally require WHATWG parsing to preserve scheme, host,
port, and path exactly. Rejection or rewriting is artifact_invalid and starts
no connection.

## 6. TLS Policy

Every candidate has exactly one mode.
Every v3 endpoint is TLS 1.3-only. Native clients and servers configure their
TLS providers to reject older protocol versions; browser adapters rely on the
browser's secure transport and the server-side TLS 1.3 policy.

CA mode is exactly the object containing mode equal to ca. It performs
platform PKI chain, signature, validity, key-usage, security-policy, configured
revocation, and DNS-ID or IP SAN validation against the normalized host.
Common Name alone is insufficient. Public roots come from the platform;
private roots are preinstalled or explicitly supplied by deployment. The
artifact carries no roots and cannot enable an insecure verifier.

Pin mode contains mode equal to pin and pins with 1..4 entries. Each pin
contains exactly algorithm, not_after_unix_s, and value_b64u. Algorithm is
sha-256. Value is canonical base64url for SHA-256 of the complete leaf X.509
DER. Expiry is an integer in 1..9007199254740991 and is exclusive. Duplicate
algorithm and value pairs are invalid.

Pin is the sole certificate identity decision; it never adds a CA path. The
TLS provider still proves TLS 1.3 key exchange, CertificateVerify, Finished,
transcript, cipher suite, signature scheme, and ALPN. A portable pin endpoint
uses a current X.509v3 leaf valid for at most 1,209,600 seconds with ECDSA
P-256 SPKI. Native verifiers enforce that profile and compare leaf hashes in
constant time. RSA leaf keys are invalid.

Browser JavaScript cannot inspect the peer leaf SPKI or independently prove the
P-256-only profile. The browser WebTransport `serverCertificateHashes` API may
accept a non-RSA algorithm other than P-256, subject to browser policy. An
endpoint that requires P-256-only therefore has no cross-runtime profile or
interoperability guarantee when reached through browser JavaScript. The SDK
MUST NOT claim that browser JavaScript verified P-256-only; deployments needing
that proof must use a native verifier or an explicitly browser-supported
profile.

TLS 0-RTT, session tickets, and resumption are disabled. No HTTP Upgrade,
CONNECT, application byte, carrier, or FSB3 is exposed before the provider
proof and applicable policy succeed.

At attempt start, sample trusted integer wall-clock attempt_now once and retain
only pins where attempt_now is less than not_after_unix_s. Filtering occurs
before transport construction. An empty active set is tls_policy_expired,
creates no socket, and spends no lease. Hashes and FSB3 always bind the complete
declared policy. Established sessions do not close solely because policy time
later expires.

~~~text
tls_policy_digest = SHA-256(
  "flowersec-v3-tls-policy\0"
  || LP(JCS(tls_policy))
)
~~~

## 7. FSB3 and FSA3

FSB3 is 12 bytes plus a 1..32768 byte JCS payload:

~~~text
0..3   ASCII FSB3
4      version 3
5      path kind: 1 direct, 2 tunnel
6..7   reserved zero
8..11  uint32 big-endian payload length
12..   payload
~~~

Direct payload contains exactly candidate_set_hash_b64u, candidates,
channel_id, chosen_candidate_id, listener_audience, profile,
rendezvous_group_id, routing_token, and session_contract_hash_b64u.

Tunnel payload contains exactly attach_token, candidate_set_hash_b64u,
candidates, channel_id, chosen_candidate_id, endpoint_instance_id,
listener_audience, profile, rendezvous_group_id, role, and
session_contract_hash_b64u.

Every value is projected from a validated artifact. The caller cannot supply
an independent value. The projection is exact:

~~~text
common.profile                    = artifact.profile = "flowersec/3"
common.channel_id                 = artifact.session.channel_id
common.session_contract_hash_b64u = artifact.session.contract_hash_b64u
common.rendezvous_group_id        = artifact.path.rendezvous_group_id
common.listener_audience          = artifact.path.listener_audience
common.candidates                 = canonicalize(artifact.path.candidates)
common.candidate_set_hash_b64u     = candidate_set_hash(common.candidates)
common.chosen_candidate_id         = chosen_candidate.id

direct.routing_token              = artifact.path.routing_token

tunnel.attach_token               = artifact.path.token
tunnel.endpoint_instance_id       = artifact.path.local_endpoint_instance_id
tunnel.role                       = artifact.path.role
~~~

Direct FSB3 is generated only from a direct artifact and MUST omit
`attach_token`, `endpoint_instance_id`, and `role`. Tunnel FSB3 is generated
only from a tunnel artifact and MUST omit `routing_token`; tunnel role `1`
means the Flowersec client role and role `2` means the Flowersec server role.
The receiver repeats URL and TLS policy validation, ordering and endpoint
uniqueness, both hashes, chosen-candidate membership, role interpretation, and
every authorization-record equality. Any missing, cross-variant, role, or
projection mismatch fails admission closed.

~~~text
admission_binding = SHA-256(
  "flowersec-v3-admission\0" || complete_FSB3
)

acceptor_admissions_hash = SHA-256(
  "flowersec-v3-acceptor-admissions\0"
  || LP(complete_FSB3_1)
  || ...
  || LP(complete_FSB3_n)
)
~~~

For admissions hash, n is 1..4 and frames are in strict chosen-candidate-ID
ASCII order.

FSA3 is eight bytes plus at most 64 reason bytes. Magic is FSA3, version is 3,
status is zero success, one reject, or two retryable, followed by uint16
big-endian reason length and reason. Success reason is empty. Other reasons
match [a-z][a-z0-9_]* and come from the admission registry. TLS errors are
never FSA3 reasons.

Before FSA3 success, the receiver looks up the authorization record by the
credential digest, reprojects the complete FSB3 from that record's validated
artifact and the selected candidate, and compares the canonical bytes exactly.
This comparison includes every common field, the complete candidate/TLS set,
and the direct or tunnel variant fields. A missing record, variant mismatch,
role mismatch, or unequal projection fails admission closed.

When a server receives a complete FSB3 whose initiation expiry has been reached
(`server_wall_now >= init_expire_at_unix_s`), it sends a retryable FSA3 with the
audited reason `expired_artifact` and does not admit the session. This server
admission response is distinct from the client's local expiry checks. A client
must project any remote FSA3 rejection to its redacted admission failure and
must not manufacture the local public `expired_artifact` code solely from the
remote reason string; only its own trusted clock can classify local expiry.

## 8. Remaining Frame and Crypto Family

The remaining magic values are FSC3, FSH3, FSS3, FSR3, and FSD3, each with
version byte 3. Their general framing rules, inherited codec rules, lengths,
offsets, ordering, limits, and reserved values are fixed by the source design
and the v2 baseline it explicitly inherits. `testdata/transport_v3` records the
derived exact vectors and negative examples; it cannot narrow or replace those
general rules. Wrong magic, version, route, ALPN, subprotocol, reserved data,
truncation, or trailing data fails closed.

In particular, FSH3 uses the byte-for-byte inherited FSH2 canonical JSON
payload and handshake vectors rather than JCS. The v3 version and domain
replacements do not change that payload codec or its value domain.

The session rekey transition counter starts at 1 and never wraps on the wire.
`UINT64_MAX` is usable exactly once; its committed successor is the internal
zero exhaustion sentinel. A later local rekey attempt sends GOAWAY reason 5
and returns the public `resource_exhausted` error. The 32-bit session epoch
also never wraps: epoch `UINT32_MAX` is usable, and a local rekey attempt from
that epoch has the same exhaustion result. Both exhaustion checks occur before
waiting for stream frontiers or responders, freezing responders, or deriving
new roots. After accepting `UINT64_MAX`, or while receiving at epoch
`UINT32_MAX`, a receiver rejects every further SESSION_KEY_UPDATE as a
protocol failure before waiting for responders. The
`testdata/transport_v3/session_wire_vectors.json` fixture freezes both
boundaries alongside the inherited session payload vectors.

An authenticated logical-stream FIN is clean only when the carrier read side
then reaches native EOF without another byte. The receiver does not publish
clean application EOF or release stream capacity before that native EOF.
Truncation, a trailing byte or record, and any record authentication or state
failure use the inherited per-stream reset path.

The v3 path exclusively uses these domain labels:

~~~text
flowersec-v3-session-contract\0
flowersec-v3-candidates\0
flowersec-v3-tls-policy\0
flowersec-v3-admission\0
flowersec-v3-acceptor-admissions\0
flowersec-v3-runtime-capability\0
flowersec-v3-handshake\0
flowersec v3 server finished
flowersec v3 client finished
flowersec v3 epoch zero
flowersec v3 control root
flowersec v3 stream root
flowersec v3 setup root
flowersec v3 rekey root
flowersec v3 next epoch
flowersec v3 stream
flowersec v3 control
flowersec v3 record key
flowersec v3 nonce
flowersec v3 unreliable root
flowersec v3 unreliable
flowersec v3 unreliable key
flowersec v3 unreliable nonce
flowersec-v3-unreliable
flowersec-v3-setup\0
flowersec-v3-record\0
flowersec-v3-open\0
~~~

The complete v2-to-v3 domain replacement table is:

| v2 label | v3 label |
| --- | --- |
| `flowersec-v2-session-contract\0` | `flowersec-v3-session-contract\0` |
| `flowersec-v2-candidates\0` | `flowersec-v3-candidates\0` |
| `flowersec-v2-admission\0` | `flowersec-v3-admission\0` |
| `flowersec-v2-runtime-capability\0` | `flowersec-v3-runtime-capability\0` |
| `flowersec-v2-handshake\0` | `flowersec-v3-handshake\0` |
| `flowersec v2 server finished` | `flowersec v3 server finished` |
| `flowersec v2 client finished` | `flowersec v3 client finished` |
| `flowersec v2 epoch zero` | `flowersec v3 epoch zero` |
| `flowersec v2 control root` | `flowersec v3 control root` |
| `flowersec v2 stream root` | `flowersec v3 stream root` |
| `flowersec v2 setup root` | `flowersec v3 setup root` |
| `flowersec v2 rekey root` | `flowersec v3 rekey root` |
| `flowersec v2 next epoch` | `flowersec v3 next epoch` |
| `flowersec v2 stream` | `flowersec v3 stream` |
| `flowersec v2 control` | `flowersec v3 control` |
| `flowersec v2 record key` | `flowersec v3 record key` |
| `flowersec v2 nonce` | `flowersec v3 nonce` |
| `flowersec v2 unreliable root` | `flowersec v3 unreliable root` |
| `flowersec v2 unreliable` | `flowersec v3 unreliable` |
| `flowersec v2 unreliable key` | `flowersec v3 unreliable key` |
| `flowersec v2 unreliable nonce` | `flowersec v3 unreliable nonce` |
| `flowersec-v2-unreliable` | `flowersec-v3-unreliable` |
| `flowersec-v2-setup\0` | `flowersec-v3-setup\0` |
| `flowersec-v2-record\0` | `flowersec-v3-record\0` |
| `flowersec-v2-open\0` | `flowersec-v3-open\0` |
| `flowersec-v2-acceptor-admissions\0` | `flowersec-v3-acceptor-admissions\0` |

Every v3 path MUST use the corresponding v3 preimage and MUST reject a v2
magic, profile, ALPN, subprotocol, or label. The v3-only TLS-policy digest uses
`flowersec-v3-tls-policy\0`; it has no v2 predecessor. The
acceptor-admissions label is included because its hash covers the complete
chosen-candidate FSB3 frames.

A v3 path MUST NOT call a helper containing another protocol version's
preimage, HKDF info, HMAC input, AAD, frame magic, or version byte.

### 8.1 SDK Major and Deployment Isolation

The v3 SDKs are versioned and deployed as an independent contract:

- the Go module uses the `/v3` module path;
- the TypeScript package, Rust crate, and Swift package/tag are released as
  v3 majors;
- v3 uses an independent server path, WebSocket subprotocol, and QUIC ALPN;
- a v2 artifact MUST NOT be passed to a v3 API, and a v3 artifact MUST NOT be
  passed to a v2 API;
- during a parallel migration, the deployment runs independent v2 and v3
  listeners and the application explicitly selects the SDK major;
- runtime automatic upgrade or downgrade between v2 and v3 is not provided.

## 9. OPEN Metadata

OPEN metadata is not JCS. Its root is an object. Values are objects, arrays,
strings, booleans, null, and decimal safe integers. It rejects floats,
exponents, negative zero, duplicate keys, trailing bytes, and invalid UTF-8.

Keys and strings are Unicode 15.1 assigned scalars in NFC and exclude C0/C1
controls. Object keys are non-empty and sorted by UTF-16 code unit. Arrays
retain order. Strings escape only quote and backslash. Empty metadata is an
empty object.

Limits are 4096 canonical bytes, depth 4, 64 nodes below the root, 64 object
members, 32 array elements, 64 bytes per key, and 512 bytes per string. OPEN
kind uses the same Unicode rules and is 1..128 bytes.

## 10. Fixture Authority

stability/transport_v3_contract.json lists required fixtures. Generated
artifact, capability, controller, handshake, crypto, and datagram outputs are
reproducible from checked-in generators. Container member order is not wire
unless explicitly declared. Positive vectors do not enlarge the schema and
negative vectors do not replace these general rejection rules.
