# Flowersec Transport v3 Wire Contract

Status: final

Version: 3.0.0

This is the normative English wire specification for Flowersec Transport v3.
Its normative source is the final English design recorded in
`stability/transport_v3_contract.json` under `design`. Release tooling MUST
verify that source against the registry digest before regenerating derived
artifacts. This document, the machine-readable registry, and the vectors are
derived consistency artifacts.
A conflict among them or with the source design blocks release; no derived
artifact can replace or expand a general rule from the source design. MUST,
MUST NOT, SHOULD, SHOULD NOT, and MAY have the meanings from RFC 2119 and RFC
8174.

## Normative Contract and Priority

Transport v3 is self-contained. Its wire, application codec, Controller, carrier,
lifecycle, and error-recovery rules are defined by this document,
`docs/TRANSPORT_V3_ARCHITECTURE.md`,
`stability/transport_v3_contract.json`, and
`testdata/transport_v3`.

Normative priority is:

1. this final English Transport v3 design;
2. the audited Transport v3 machine-readable registry; and
3. the Transport v3 vectors generated or validated from that registry.

This English specification is required release input. Source code, historical
runtime behavior, and any other document cannot add an exception. A missing or
conflicting contract artifact blocks release.

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

Those rejection rules apply only to the JCS objects listed above. FSH3 uses its
canonical handshake JSON codec. RPC and application JSON use the Transport v3
application value domain. FSH3, FSS3, OPEN, RPC, and application payloads MUST
NOT be subjected to artifact/FSB3 JCS rejection rules; each uses its explicitly
specified Transport v3 codec.

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
version byte 3. Their framing rules, codec rules, lengths, offsets, ordering,
limits, and reserved values are fixed by this contract.
`testdata/transport_v3` records exact vectors and negative examples; it cannot
narrow or replace those general rules. Wrong magic, version, route, ALPN,
subprotocol, reserved data, truncation, or trailing data fails closed.

FSH3 uses the canonical Transport v3 handshake JSON payload rather than JCS.

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

Every Transport v3 path MUST use exactly the domain labels listed above. The
TLS-policy digest uses `flowersec-v3-tls-policy\0`. The acceptor-admissions
label covers the complete chosen-candidate FSB3 frames. Inputs using any other
magic, profile, ALPN, subprotocol, label, frame version, HKDF info, HMAC input,
or AAD fail closed.

### 8.1 SDK Major and Deployment Isolation

Flowersec 5.x SDKs implement only Transport v3:

- the Go module uses the `/v4` module path;
- the TypeScript package, Rust crate, and Swift package/tag use major version 4;
- server paths, WebSocket subprotocols, and QUIC ALPN are fixed by Transport v3;
- inputs from another wire generation fail closed; and
- runtime protocol negotiation, automatic upgrade, and downgrade are absent.

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
