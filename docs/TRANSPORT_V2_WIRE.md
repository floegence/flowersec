# Transport v2 Wire Contract

This document is the normative byte-level contract for `flowersec/2`. The
machine-readable registry is `stability/transport_v2_contract.json`, and the
normative vectors are the nine files registered by its `wire_fixtures` field.
All multibyte integers are unsigned big-endian. Receivers reject non-zero
reserved bytes, undeclared trailing bytes, unknown fields, non-canonical JSON,
invalid UTF-8, size violations, and values outside the registries below.

Transport v2 uses the same session wire over WebSocket, raw QUIC, and
WebTransport. WebSocket uses one hop-local Yamux session after admission. Raw
QUIC and WebTransport map every Flowersec stream directly to one native
bidirectional stream and never add Yamux. Reliable application data is never
sent as a QUIC or WebTransport datagram. An independently encrypted FSD2
unreliable message is permitted only after native DATAGRAM and the matching
FSH2 feature are negotiated; it is never carried on a reliable stream.

## Connection Order

The initiator first sends exactly one FSB2 admission request and receives one
FSA2 response. No FSC2, FSH2, FSS2, or FSR2 byte may be sent before a successful
FSA2. On success, the client opens the lifetime control stream, writes FSC2,
and performs the FSH2 handshake. The authenticated `SESSION_READY` /
`SESSION_READY_ACK` exchange is the final establishment barrier. Application
streams begin with FSS2 followed by authenticated FSR2 records.

The carrier adapter preserves these boundaries. In the QUIC family, admission,
control, reserved RPC, and application streams are separate native
bidirectional streams. A clean protocol FIN is followed by the carrier's native
FIN. A protocol or authentication failure uses native RESET_STREAM and
STOP_SENDING for the affected stream; a control-stream failure closes the
session.

## FSB2 Admission Request

FSB2 is `12 + payload_length` bytes:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | ASCII `FSB2` |
| 4 | 1 | version `2` |
| 5 | 1 | path: `1` direct, `2` tunnel |
| 6 | 2 | zero |
| 8 | 4 | canonical JSON payload length, `1..32768` |
| 12 | variable | canonical UTF-8 JSON payload |

The payload has exactly the fields represented by the direct or tunnel vectors
in `testdata/transport_v2/artifact_vectors.json`. It carries the full canonical
candidate set, its SHA-256 hash, the selected candidate ID, the session contract
hash, listener audience, and either the direct routing token or the tunnel role,
endpoint instance ID, and attach token. The selected candidate must occur in the
canonical set. Candidate ordering, normalized URLs, hashes, path variant, and
`profile == "flowersec/2"` are revalidated by the receiver.

The admission binding used by FSH2 is:

```text
admission_binding = SHA-256("flowersec-v2-admission\0" || complete_FSB2)
```

The receiver rejects a zero-length or oversized payload, an unknown path,
non-zero reserved bytes, truncation or trailing bytes, non-canonical JSON,
unknown or missing fields, hash or ordering drift, a selected candidate outside
the set, and fields from the other path variant.

## FSA2 Admission Response

FSA2 is `8 + reason_length` bytes:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | ASCII `FSA2` |
| 4 | 1 | version `2` |
| 5 | 1 | status: `0` success, `1` reject, `2` retryable |
| 6 | 2 | UTF-8 reason length, at most 64 |
| 8 | variable | reason token |

Success requires an empty reason. Reject and retryable require a reason matching
`[a-z][a-z0-9_]*` that is present in the caller-supplied audited reason
registry. Unknown status or reason, malformed UTF-8, truncation, and trailing
bytes are rejected. FSA2 reasons are deployment admission codes, not a place
for product payloads.

## FSC2 and FSH2 Handshake

FSC2 is exactly 16 bytes: ASCII `FSC2`, version `2`, opener role `1` (client),
then ten zero bytes. Any other value is rejected.

Every FSH2 frame is `12 + payload_length` bytes:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | ASCII `FSH2` |
| 4 | 1 | version `2` |
| 5 | 1 | `1` CLIENT_INIT, `2` SERVER_FINISHED, `3` CLIENT_FINISHED |
| 6 | 2 | zero |
| 8 | 4 | canonical JSON payload length, `1..8192` |
| 12 | variable | canonical UTF-8 JSON payload |

CLIENT_INIT binds the profile, channel, session contract hash, suite, client
ephemeral key, 32-byte client nonce, offered features, inbound stream limit,
admission binding, and path-specific endpoint identity. SERVER_FINISHED binds
the server ephemeral key, 16-to-32-byte handshake ID, 32-byte server nonce, the
same contract and limits, server admission binding and endpoint identity, plus
the server confirmation. CLIENT_FINISHED echoes the exact handshake ID and
carries the client confirmation. Binary JSON fields use canonical unpadded
base64url. X25519 public keys are exactly 32 bytes; P-256 public keys are exactly
65-byte uncompressed SEC1 points beginning with `0x04`.

Let `LP(x) = uint32_be(len(x)) || x`. All hashes and KDF operations use SHA-256:

```text
shared        = ECDH(local_private, peer_public)
handshake_prk = HKDF-Extract(salt = psk, IKM = shared)
h0 = SHA-256("flowersec-v2-handshake\0" || FSC2 || LP(CLIENT_INIT))
h1 = SHA-256(h0 || LP(SERVER_FINISHED_core))
server_key     = HKDF-Expand(handshake_prk,
                  "flowersec v2 server finished" || h1, 32)
server_confirm = HMAC-SHA256(server_key, h1)
h2 = SHA-256(h1 || LP(SERVER_FINISHED) || LP(CLIENT_FINISHED_core))
client_key     = HKDF-Expand(handshake_prk,
                  "flowersec v2 client finished" || h2, 32)
client_confirm = HMAC-SHA256(client_key, h2)
h3 = SHA-256(h2 || LP(CLIENT_FINISHED))
session_prk = HKDF-Extract(salt = h3, IKM = handshake_prk)
```

The exact JSON field sets, transcript slices, ECDH outputs, confirms, and KDF
results are frozen by `testdata/transport_v2/handshake_vectors.json`. Receivers
reject an unsupported suite, invalid or all-zero shared secret, wrong message
order or type, non-canonical encoding, mismatched channel/contract/limit,
invalid endpoint identity, admission-binding mismatch, handshake-ID mismatch,
or confirmation mismatch. Comparison of confirmations and established bindings
is constant-time. Application 0-RTT is forbidden. Feature bit `0x00000001` is
`unreliable_messages_v1`: the client offers it only when the selected carrier
has native DATAGRAM support, and the server echoes the intersection. Unknown
bits are rejected. The channel remains unavailable until the authenticated
`SESSION_READY` / `SESSION_READY_ACK` barrier completes.

## Epoch and Record Keys

`direction` is `1` client-to-server or `2` server-to-client. `BE32` and `BE64`
below are fixed-width big-endian encodings. `L(label, parts...)` is the UTF-8
label followed by `0x00` and the concatenated parts.

```text
epoch_secret_0 = HKDF-Expand(session_prk,
                   L("flowersec v2 epoch zero", direction), 32)
control_root = HKDF-Expand(epoch_secret, L("flowersec v2 control root"), 32)
stream_root  = HKDF-Expand(epoch_secret, L("flowersec v2 stream root"), 32)
setup_root   = HKDF-Expand(epoch_secret, L("flowersec v2 setup root"), 32)
rekey_root   = HKDF-Expand(epoch_secret, L("flowersec v2 rekey root"), 32)
next_epoch_secret = HKDF-Expand(rekey_root,
  L("flowersec v2 next epoch", h3, direction, BE32(next_epoch)), 32)
record_secret = HKDF-Expand(root,
  L(stream_or_control_label, h3, BE64(logical_id), direction, BE32(epoch)), 32)
record_key   = HKDF-Expand(record_secret, L("flowersec v2 record key"), 32)
nonce_prefix = HKDF-Expand(record_secret, L("flowersec v2 nonce"), 4)
```

The stream label is `flowersec v2 stream`; the control label is
`flowersec v2 control` with logical ID zero. The exact results are in
`testdata/transport_v2/crypto_vectors.json`.

## FSD2 Unreliable Message

FSD2 exists only on negotiated raw QUIC or WebTransport DATAGRAM support. It
has a 32-byte cleartext header followed by exactly `ciphertext_length` bytes:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | ASCII `FSD2` |
| 4 | 1 | version `2` |
| 5 | 1 | flags, zero |
| 6 | 2 | header length, `32` |
| 8 | 4 | epoch |
| 12 | 8 | sequence |
| 20 | 8 | absolute expiry in Unix milliseconds |
| 28 | 4 | ciphertext length, `17..992` |

The plaintext is `1..976` opaque application bytes, keeping the complete FSD2
wire image within the 1024-byte native WebTransport DATAGRAM limit shared by
production Chromium and raw QUIC. Empty and oversized
messages are rejected before carrier access. Expiry must be in the future when
sent. A receiver silently drops expired, duplicate, stale-epoch, malformed, or
authentication-failed datagrams and continues receiving; these outcomes never
close the reliable session. Sequence numbers are unique and increasing within
each `(direction, epoch)`, but delivery remains unordered and lossy.

The unreliable keys are independent from reliable stream and control keys:

```text
unreliable_root = HKDF-Expand(epoch_secret,
  L("flowersec v2 unreliable root"), 32)
unreliable_secret = HKDF-Expand(unreliable_root,
  L("flowersec v2 unreliable", h3, direction, BE32(epoch)), 32)
unreliable_key = HKDF-Expand(unreliable_secret,
  L("flowersec v2 unreliable key"), 32)
unreliable_nonce_prefix = HKDF-Expand(unreliable_secret,
  L("flowersec v2 unreliable nonce"), 4)
nonce = unreliable_nonce_prefix || BE64(sequence)
AAD = L("flowersec-v2-unreliable", h3, direction, FSD2_header)
```

The negotiated session suite supplies the AEAD and its 16-byte tag. Public
sends use a fixed 64-operation non-blocking budget: native acceptance reports
`accepted`, while local budget exhaustion reports `dropped_budget`. Neither is
a delivery acknowledgement. Typed `unavailable`, `oversize`, `expired`, and
closed outcomes expose no carrier, route, key, or credential detail. The exact
key, header, ciphertext, expiry, replay, and type-isolation cases are frozen by
`testdata/transport_v2/datagram_vectors.json`.

## FSS2 Stream Setup

FSS2 is exactly 56 bytes:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | ASCII `FSS2` |
| 4 | 1 | version `2` |
| 5 | 1 | opener role: `1` client, `2` server |
| 6 | 2 | zero |
| 8 | 8 | logical stream ID |
| 16 | 4 | initial send epoch |
| 20 | 4 | zero |
| 24 | 32 | setup MAC |

Client-opened IDs are non-zero odd numbers; server-opened IDs are non-zero even
numbers. The MAC is:

```text
setup_mac = HMAC-SHA256(setup_root,
  "flowersec-v2-setup\0" || h3 || FSS2[0:24])
```

An invalid role/parity, repeated or stale logical ID, unavailable epoch,
non-zero reserved field, or invalid MAC causes stream rejection/reset before an
OPEN record is accepted.

## FSR2 Authenticated Record

FSR2 has a 24-byte cleartext header followed by exactly `ciphertext_length`
bytes:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | ASCII `FSR2` |
| 4 | 1 | version `2` |
| 5 | 1 | header length `24` |
| 6 | 2 | zero |
| 8 | 4 | epoch |
| 12 | 8 | sequence |
| 20 | 4 | ciphertext length, `16..16408` |

The suite is ChaCha20-Poly1305 (`1`) or AES-256-GCM (`2`). Both have a 16-byte
tag. The 12-byte nonce is `nonce_prefix || BE64(sequence)`. The AAD is:

```text
"flowersec-v2-record\0" || h3 || BE64(logical_id) || direction || FSR2_header
```

Sequence numbers start at zero for each `(logical_id, direction, epoch)` and
must increase by exactly one. A wrong epoch, sequence, direction, logical ID,
length, tag, or ciphertext is an authentication/protocol failure. Nonces must
never be reused; sequence or epoch exhaustion closes the affected protocol
scope rather than wrapping.

## Inner Records, OPEN, and ACK

Authenticated plaintext begins with an 8-byte inner header: one-byte type,
three zero bytes, a four-byte payload length, then exactly that payload.

| Type | Name | Payload |
| ---: | --- | --- |
| 1 | OPEN | `1..8192` bytes, format below |
| 2 | OPEN_ACK | 32-byte OPEN hash |
| 3 | OPEN_REJECT | 32-byte OPEN hash + 2-byte reason |
| 4 | DATA | `1..16384` bytes |
| 5 | FIN | empty |
| 6 | STREAM_KEY_UPDATE | transition ID (8) + next epoch (4) |
| 16 | SESSION_READY | empty |
| 17 | PING | nonce (8) |
| 18 | PONG | echoed nonce (8) |
| 19 | SESSION_KEY_UPDATE | transition ID (8) + next epoch (4) + resolved watermark (8) |
| 20 | STREAM_RESET | logical ID (8) + non-zero reason (2) |
| 21 | GO_AWAY | last accepted logical ID (8) + non-zero reason (2) |
| 22 | SESSION_CLOSE | non-zero reason (2) |
| 23 | SESSION_READY_ACK | empty |
| 24 | SESSION_KEY_UPDATE_ACK | exact 20-byte SESSION_KEY_UPDATE echo |
| 25 | STREAM_KEY_UPDATE_ACK | logical ID (8) + transition ID (8) + next epoch (4) |

Unknown types and incorrect fixed sizes are rejected. Transition IDs are
non-zero, monotonic, and never wrap. Epochs advance by exactly one. A session
update commits only after all affected stream updates and the exact ACK barrier.
The STREAM_KEY_UPDATE_ACK field order is frozen by
`testdata/transport_v2/session_wire_vectors.json`.

OPEN is:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 8 | logical stream ID, equal to FSS2 |
| 8 | 32 | SHA-256 of the complete FSS2 |
| 40 | 2 | kind byte length, `1..128` |
| 42 | 4 | metadata byte length, at most 4096 |
| 46 | variable | UTF-8 kind followed by canonical JSON metadata |

The complete OPEN is at most 8192 bytes. Kind and metadata use the frozen
Unicode 15.1 rules in `testdata/transport_v2/open_unicode_vectors.json`;
metadata must satisfy the bounded canonical JSON depth, node, key, array,
string, and safe-integer limits. Empty metadata is canonicalized to `{}` before
encoding.

```text
open_hash = SHA-256("flowersec-v2-open\0" || BE32(len(OPEN)) || OPEN)
```

OPEN_ACK is exactly `open_hash`. OPEN_REJECT is `open_hash || BE16(reason)`.
Registered OPEN_REJECT reasons are `1` unsupported kind, `2` resource
exhausted, `3` policy rejected, `4` invalid metadata, and `5` going away.
Senders emit only registered reasons. Receivers reject zero; they preserve an
unknown non-zero reason as unknown instead of assigning invented semantics.
DATA and FIN are forbidden until the exact OPEN hash is acknowledged.

STREAM_RESET, GO_AWAY, and SESSION_CLOSE reasons are non-zero protocol-domain
codes. They are intentionally opaque at this layer; product or provider policy
must not be inferred from an unregistered numeric value. FSA2 uses its separate
audited string registry.

## Failure Rules

Admission failure sends one FSA2 when possible and prevents session bytes from
being written. Handshake failure resets the control stream and closes the
candidate. Invalid FSS2, OPEN, or per-stream FSR2 state resets that native
stream and sends authenticated STREAM_RESET when possible. Invalid control
records, confirmation failures, AEAD failures on the control stream, nonce
reuse, counter wrap, or contradictory rekey ACKs close the session. Receivers
must fail closed; they do not resynchronize by scanning for the next magic
value, accept prefixes, ignore trailing bytes, infer missing fields, or fall
back to another carrier using the same spent credential.

The normative fixture/runtime matrix is verified by `tools/stabilitycheck`.
A runtime without an implemented codec is recorded as unsupported with a
machine-readable reason; merely parsing a fixture as generic JSON is not
conformance.
