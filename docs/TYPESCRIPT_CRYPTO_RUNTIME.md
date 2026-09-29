# TypeScript cryptographic runtime components

The internal `src/v4/runtime` modules use the registered wire domains and fixed
profile limits. They are not exported from the normal package entry points.
They do not yet compose a complete TransportEnvironment, Noise handshake,
READY/rekey protocol, Session, transport provider or public Stream API.

`CBORDecoder.decodeMap` copies one bounded input into its original arena,
checks canonical encoding and all registered stateless field/relation rules,
and captures the declared selectors and limits. Its document lease exposes no
mutable input view. Fixed Unicode 15.1 tables validate normalization and IDNA
without platform URL/IDNA normalization. Schema validity alone confers no trust,
authorization, time, admission, replay or publication rights.

`SignedMapCodec` projects the original encoded fields, omitting only the
registered signature field. It verifies canonical, nonidentity, prime-order
Ed25519 public keys and R points, and requires S below the group order before
verification. The verification fact belongs only to the original material
lease. Software signing keys hold a private owned seed, restrict signing to
registered purposes and reverify their output. Neither these software keys nor
the record keys claim platform non-extractability or hardware custody.

`EnvelopeDecoder` has one admitted input buffer and one exclusive frame lease.
Message ingress accepts exactly one complete envelope; stream ingress consumes
only through the first complete envelope. Binary record prefixes, nonces, AAD
and key information follow generated registry domains. A framed envelope is
not an authenticated record.

`CryptoUsageLedger` is one original Session's nonrefundable cryptographic
accounting owner. It precharges calls, authentication blocks and ciphertext
bytes at key, epoch and Session levels before AEAD. Scope-zero and aggregate
budgets preserve the configured remaining rekey reserve. Retiring a key or
epoch does not reset Session totals or restore KDF permits. Each epoch uses a
fixed full-domain bitmap to reject a second derivation for the same direction
and scope, including retired keys. Only two epoch counter positions can be
live; their ordinals advance without reuse or wrap.

`RecordEpoch` holds an internal software root and handshake hash. It derives
only registered record keys through HKDF-Expand and checks both the original
authorization deadline and the root's original maximum age. `RecordCipher`
uses the pinned Noble ChaCha20-Poly1305 or AES-256-GCM implementation. Each key
has one admitted work/output position, private input/output storage and no
waiter queue. A failed precharged reliable send cannot retry its sequence.
`RecordTicketError.precharged` records crypto consumption, not provider
submission, peer receipt or business execution.

Authenticated input remains a private packet lease until the original protocol
owner validates its plaintext and calls `commitValidated`. Reliable sequences
advance only at that gate. Datagram replay uses a fixed 256-bit window and full
uint64 arithmetic; only a validated commit moves it. A successful unique commit
records good-use even when the original queue is full and immediately discards
the packet. The Session must make commit and its bounded queue decision in the
same synchronous owner turn, and recheck its delivery gate when dequeuing.

Datagram invalid-input accounting belongs to the original Session ledger across
all keys and epochs. Each actual open reserves a possible failure position;
actual tag failures count permanently, each group of eight pauses reception for
at least one conservatively measured second, and 32 disable reception until
Session closure. A provider failure with an indeterminate authentication result
disables reception without inventing a bad-tag count. Replay, length and epoch
prechecks do not consume an AEAD call. Pause and failure totals survive rekey.
Key-open exhaustion does not create a rekey request. No packet creates a timer;
the containing Session must arrange its already admitted wakeups and queue
cleanup around these synchronous gates.

The trusted internal authorization projection must enforce original
Session/generation, READY, allowed receive epoch, rekey state, scope and route
eligibility. These components do not infer those facts from peer headers or
make a staged epoch eligible. The Session also owns OPEN uniqueness across
epochs, scope error isolation, reserved maintenance scheduling, good-use soft
watermarks, retirement and provider submission. An internal key constructor is
not proof of any of those protocol transitions.

Resource charges include typed-array backing, full AEAD input/output and
transient result capacity, key/domain/replay storage and explicit runtime
allowances. Close first seals new work; packet and key tails keep their original
reservations until actual release. Owned writable secrets are cleared when
their last permitted use ends. These declarations require host allocation,
library temporary-memory and provider qualification; they are not measured
RSS guarantees or independent aggregate cryptographic security proofs.
