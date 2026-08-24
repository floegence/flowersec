# Flowersec Transport v3 Architecture

Status: final

Version: 3.0.0

This document defines the runtime, control-plane, transport-security,
Controller, and lease architecture for Flowersec v3. Wire bytes and strict
schemas are defined by TRANSPORT_V3_WIRE.md. The registry in
stability/transport_v3_contract.json is the machine-readable contract.
The only session profile in this architecture is flowersec/3.

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

## 12. Acceptance Boundary

A release candidate must prove:

- identical artifact, TLS policy, candidate, FSB3, admission, capability,
  handshake, record, and datagram vectors in all four languages;
- real public-CA, deployment private-CA, and self-signed P-256 pin handshakes;
- correct and wrong pin behavior, overlapping rotation, exclusive expiry,
  unknown algorithm, unsupported runtime, and no mode downgrade;
- production browser adapter propagation of serverCertificateHashes for the
  exact registered Chromium build;
- deterministic Controller, retry, replacement, backoff, reconnect, and lease
  concurrency behavior;
- redacted public errors and truthful unsupported capability cells.

Release packaging does not run tests or consume a test receipt. Engineering
gates establish acceptance before release. The release step validates version
and refs, packages and signs artifacts, publishes, and performs registry
readback.

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

## 13. Explicit Exclusions

Transport v3 does not encode pins in URLs or imitate libp2p
multiaddresses. It provides no trust on first use, dynamic pin retrieval,
first-certificate trust, `pin-or-ca`, `prefer-pin`, or other mixed or fallback
trust mode. Artifacts never contain a root certificate, complete certificate
chain, or private key, and Session, RPC, Stream, and application APIs never
expose pins.

Flowersec does not issue certificates, manage certificate authorities, or
orchestrate deployment. Transport v3 does not redesign E2EE, RPC, stream,
DATAGRAM, or application interfaces. Production artifacts permit no plaintext
loopback. The wire protocol does not negotiate v2/v3 versions, and failure
never falls back to another version.
