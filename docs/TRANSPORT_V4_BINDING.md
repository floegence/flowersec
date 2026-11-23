# Flowersec Transport v4 implementation binding

This repository is preparing the Flowersec 6.0.0 / wire v4 implementation.
The normative architecture is maintained outside this repository and is bound
by the immutable SHA below. This file intentionally does not reproduce that
design.

| Item | Value |
| --- | --- |
| Product release | `6.0.0` |
| Wire profile | `flowersec/4` |
| Architecture source | `FLOWERSEC_V4_DESIGN_PATH` (or the contract's relative external path) |
| Architecture SHA-256 | `3f155c57dc1be95d190af9ce2ac5b0113006650259372ab09521c6cff04bef79` |
| Review evidence | `FLOWERSEC_V4_EVIDENCE_PATH` (or the contract's relative external path) |
| Review evidence SHA-256 | `ada2ac7eca7655c61ad4e4699b77746e549be14a182ad55c342050a6f7f2a1ec` |
| Implementation binding | `stability/transport_v4_contract.json` |
| Schema reference | `stability/transport_v4_schema.json` |
| Schema revision | `flowersec-v4.0.0-draft.66` |
| Schema gate | `not_frozen` |

The v4 schema, registry, vectors, provider qualifications and independent
cryptographic qualification are separate implementation gates. The repository
now records a reproducible draft schema and vector manifest; these artifacts
are still non-authoritative until independently reviewed and promoted to
`frozen`. Until then, no v4 codec, handshake, carrier or public SDK
implementation may be declared production-ready. Existing v3 implementation
files remain the active baseline; this binding does not add a compatibility path
or change runtime behavior.

The Go ordinary service dispatcher accepts volatile execution unary requests
through the original authenticated Session identity, installed contract routes
and service-wide history registry. Current endpoint authorization, lease policy
and dispatcher closure order each finite transfer before input/registry gates.
Complete input, response/join backing and a
real ordinary ready/running position precede new history registration. Duplicate
requests join the same record without another handler or task. Handlers write
into the original execution result; the Session coordinator copies bounded
chunks into each request's original response owner. Session closure retains
live callbacks and records their actual later return. No-retention contracts
serve already admitted replies without promising a retained result. Ordinary
responses distinguish operation conflicts and expired results; expired initial
admission reports the deadline failure without creating history. Retained-result
readers stop copying at expiry and retain backing through actual release.
Execution notifications use the same service history and real ordinary executor,
with no response or result reservation. Execution streaming, durable storage,
public operation APIs and cross-SDK runtime qualification remain unfinished.

The volatile execution owner can accept a preadmitted ExecutionAdmission with
real original history and active positions, complete work/result backing,
the executor backing reference and both authorization references. Its charges
come from the same functions as ordinary execution and preserve the service's
exact root, Environment and account scope. Ordinary admissions cannot consume
these promised positions. A reserved admission still validates the original
fully verified input, current exact authority, route, Offer and deadlines;
duplicates attach only their response obligation and release unused work.
The reservation survives store closure until its real owner releases it, and
consumption cannot refund an actual running task or retained result. This
owner also supports a reusable short-execution floor. RPC assembly admits its
four history vectors and five Session output vectors in the original aggregate
batch before plan attachment. Work, task and result backing return together
only after real executor, join, result-reader and retained-result tails leave.
Shared history capacity is restored before ordinary admission can take a free
position. Retirement releases idle promises and obsolete Session authority
while keeping actual work and service-wide retained output charged. Eligible
short execution still runs at full root byte/reference capacity; an occupied
floor can use ordinary capacity when available. Full execution-profile admission,
durable-store reservation and reference-profile qualification remain unfinished.

The Go internal unary caller owns immutable prepared payload and contract
captures, original deadlines and execution identity/digest. Concurrent Start
calls join one original admission. A try-now miss before publication preserves
prepared rights; a queued failure is terminal. A live application context fixes
try-now before digest construction. Calls retain original captures and recheck
registration, authority, cancellation and time at each request publication gate;
releasing a binding cannot release a call's capture. Existing cancellation
preserves accepted fragment and provider tails. The internal deferred unary
caller reserves an independent result owner, credential subscriptions and future
Completion descriptor before request publication. Complete authenticated input
releases the network association without decoding. WaitStatus observes finite
metadata; TakeResult and TakeEncodedResult share one consumption gate, bounded
by four concurrent observers. Typed input enters the original decoder once and
becomes application-owned; later waits join that computation. A canceled waiter
does not close the result or restart decoding. Application error, panic and
Goexit become one normalized decode failure.

The internal prepared operation and deferred call expose AbandonResult through
the original result handoff gate. An unpublished request reports not_started
without changing its original send rights. An accepted partial request selects
its existing ABORT; a complete request selects STOP_OUTPUT only while response
input remains incomplete. Complete input withdraws an unstarted STOP and is
otherwise abandoned locally. Repeated abandonment preserves result_abandoned,
request identity and actual publication facts; a delivered typed/encoded result
remains already_delivered. Actual decoder input stays application-owned, and
late input keeps its original result-owner position until network termination.
Accepted ABORT/STOP batches also retain that owner until their actual provider
tail exits; result status distinguishes local abandonment from completed cleanup.

The original Environment coordinates detached results in a bounded index. Full
input drops Session/direction scope while preserving root, tenant, Environment
and the original result-owner position. Independent original delivery authority
survives normal I/O closure and is checked at actual private-input disclosure.
Revocation removes private input without erasing authenticated completion facts;
it cannot revoke bytes already handed to application code. Close joins real
decoder tails before refunding metadata, and never wipes application-owned
aliases. The root executor preadmits actual Completion stacks once; dormant
future descriptors consume neither a private stack nor a running worker.
Protected short unary calls preadmit six separate owners for invocation,
request, response input, route, result metadata and delivery subscriptions.
The full Session admission batch reserves actual namespace subscriptions before
its irreversible admission; repeated short calls reuse those original slots.
Session floors remain charged until actual input and decoder aliases return.
Session retirement releases idle floor anchors while an independent complete
result retains its original root, tenant and Environment charges, namespace
references and future Completion service. Complete public OperationHandle and
supported-profile resource qualification remain unfinished. Internal eager
convenience decoding remains available to its existing callers.

Go request, notification, Stream, authorization and contextual result callbacks
receive explicit application invocation contexts. SDK children pin real original
metadata through a fixed maximum of eight ancestors, including Completion
ancestors; an exited invocation cannot create work. Before a nested unary header,
a live Completion ancestor must obtain an immediately available future service
claim. Running decoders plus these claims cannot exceed the original Completion
capacity. Ordinary ancestors consume no such claim. Claims have an original
30-second local bound intersected with inherited context deadlines; expiry ends
the dependency wait while preserving actual operation and callback responsibility.
A new dependent typed waiter on an existing deferred result uses that original
future service and bounded ancestry. Rejoining cannot renew its first dependency
window, and a rejected join cannot change another observer's original ancestry
or deadline. Entry and rejoin check expiry before the next coordinator visit;
cancellation withdraws an unused claim, and known decoder self-waits
fail immediately.

Go prepared unary calls accept a trusted local synchronous codec with a complete
output bound and SDK-owned input/scratch borrows. The original batch admits all
encoding storage before callback entry and fixes the selected route, deadline,
admission window and execution identity before encoding. A live ordinary caller
reuses its actual permit and work class through at most eight direct serial
stages. Distinct bounded tokens reject suspended-parent and exited-stage reuse;
they do not infer arbitrary application goroutine identity. Completion and
external callers immediately acquire an actual ordinary permit. Neither path
creates an SDK goroutine or ready job. Callbacks execute outside protocol and
budget gates, and their actual return settles input/scratch and execution
responsibility even after cancellation, panic or Goexit. Prepared bytes survive
borrow cleanup and repeated Start never re-encodes. Explicit nested queued
admission is rejected before encoding; omitted admission becomes try_now.
Preparation opens no channel and needs no publisher. Public typed-stream
publisher integration and visible queued application dependencies remain
unfinished.

The Go internal dedicated streaming dispatcher supports transient and original
volatile/durable execution ownership. A closed byte-input event source can use
the same registration and Stream. Setup runs once; its actual return opens the
single source pump, and each event uses a fresh ordinary invocation at the
original work class. Queued and current inputs share the finite count/byte
limits. Publication acquires complete input, codec, task and alias backing before
ownership moves. Idle source and output waits retain no application running
permit. Overflow seals admission and uses the original finite streaming terminal;
its source_overflow code is rejected on ordinary RPC. Cleanup responsibility and
a real ordinary descriptor are acquired before setup, survive business closure,
and remain charged until confirmed detach and actual callback exit. The original
Stream lifetime supervisor advances that cleanup deadline even during output
backpressure. Source status reports retained inputs, actual application work and
incomplete cleanup without erasing the original execution facts.

Go's internal typed-message definition codec validates the exact local definition,
independent digest and opener-relative directions. It composes and checks the
single reserved metadata wrapper, including the 4006-byte application composition
boundary. The fixed framing cursor distinguishes empty messages from EOF and
preserves the current boundary until consumption. Concrete byte/UTF-8 output
building admits all requested segment growth before allocation, uses at most 65
blocks and retains sticky failures through finalization. Root budget waits own
finite preadmitted descriptors and complete vectors; they create no application
worker or payload queue. The internal TypedMessageStream uses those components
through the existing Stream handler plan, OpenMessageStream and the exclusive
AsTypedMessages duplex claim. Registration captures the definition before
acceptance; authorization and handler inputs contain independent ordinary
metadata snapshots. Raw calls and other adapters cannot reclaim either direction.
ReceiveEncoded and the concrete byte/UTF-8 Receive path share one cursor, body,
fixed assembly deadline and consumption gate. Typed decoding uses the original
Completion service; encoded delivery reserves no typed decoder position.

Send admits at most eight real entries, including encoder and publisher tails.
Concrete codecs run on the original ordinary executor, with explicit parent
dependencies forcing try_now and direct synchronous stages reusing only their
actual ordinary permit. The sole publisher preserves entry order, seals complete
segments before prefix acceptance and finishes a submitted suffix independently
of waiter cancellation. CloseWrite drains that same logical queue before FIN;
Finish observes the original DRAINED proof. These paths are not yet qualified by
functional or concurrency tests. Arbitrary application codec integration,
cross-SDK runtime parity and provider qualification remain unfinished.

The Go execution Session protects one actual M Stream and its fixed QueryOperation
and RequestCancel method contracts. Its original Session supervisor initializes
that channel after local READY and rebuilds only after actual stream cleanup
and protected reference return. Actual allocations, including burned or refused
OPENs, consume the client's lifetime limit of 16. The sole reader admits serials
and deadlines before payload handling; two SDK workers may complete out of order.
Two original outbound cells retain canceled late associations and untaken small
results. All envelopes use the original Stream sending ring and protected
continuous receive credit. Drain stops initialization and rebuild while keeping
an already accepted channel available for these two narrow operations. The
services profile creates no M future, initializer or ordinal. The trusted
Session resolver defaults to the original service registry and immutable caller
identity, with separately granted query/cancel access. It never infers RAM
continuity from a remote request: unknown absence is history_unknown; proven
local continuous coverage can yield not_found. Deleted results return
result_expired together with retained execution facts. Prepared responses,
including conflicts and expired results, recheck target permission at the
actual output transfer. Durable adapters, ordinary result-read routing and
public four-SDK APIs remain unfinished.

The Go connection assembly captures four semantic connection requirements
and the exact optional application profile before asynchronous acquisition.
Known unavailable local obligations fail before issuer work. Signed candidates
are filtered before preparation; original provider observations are bound to
the path and checked at final admission, claim and READY publication. Native
WebSocket TLS assurance records actual TLS 1.3 completion. WebSocket paths
retain shared ordered progress and shared input failure scope. Session Info is
a detached semantic snapshot without route, endpoint, provider or credential
identity. Four SDKs share generated requirement/guarantee types and finite
WebSocket capability definitions; public API wiring and native/relay assurance
implementations remain separate unfinished work.

The native direct WebSocket factory can compile its default policy from the
original signed public route. It reserves parsing and policy backing before
work, matches the exact route digest, numeric endpoint, authority, path,
subprotocol and Origin, and rejects credential-bearing upgrade headers. CA
mode verifies the chain and SAN over the trusted time interval. Pin mode
checks the actual full leaf DER, X.509v3 P-256 profile, full certificate lifetime
and contained signed window without CA/SAN fallback. The original active pin
set is fixed before TLS and the actual matched window is checked again at
preparation/admission/publication gates. Existing socket and TLS owners retain
all callback and policy backing through physical cleanup. Browser/native
interop qualification and complete public assembly remain separate obligations.

The native direct accepted default uses an original `WebSocketTLSListener`.
It owns an explicitly transferred listener and a fixed certificate/key
generation, reserves each connection before physical Accept, enforces TLS 1.3,
disables session tickets and keeps its original finite handshake/header cap
when the borrowed HTTP host changes deadlines. Its `ConnContext` and `ConnState`
must be installed on that host before Serve. Only the actual TLS connection
from this listener supplies the local certificate evidence; copying request
TLS fields or installing the callback on another listener grants none.
The default checks the local endpoint and Origin before upgrade, then verifies
the original signed candidate's CA/SAN or complete DER pin policy against that
same local certificate. Repeated admission checks preserve the exact Artifact,
candidate and matched pin window. Accepted observations do not claim remote
consumer TLS controls. Listener Close stops new accepts while original Sessions
continue Drain; actual socket, signing and policy tails retain their resources.
Externally terminated TLS and private loopback application authentication still
require their own explicit trusted deployment adapters. Host HTTP/TLS runtime
allowances and physical resource qualification remain explicit dependencies.

The Go consumer has a bounded independent TrustConfig owner and fresh nonce
bootstrap with exact original Head/State binding. The same independently
authenticated Head verifier feeds one bounded periodic namespace refresh
service. Trust and Head reads have separate finite cadences; push hints cannot
bypass the minimum delay, and selected State work retains its original content
and deadline. An unchanged State reuses complete authenticated bytes while
still validating the new Head and original history. HTTPS control reads keep
their original sockets, buffers and callback charge through actual exit. It
preserves immutable issuer
permission history and checks complete issuer impact evidence at installation.
A concrete TLS 1.3 / HTTP/1.1 control adapter uses a prepared numeric endpoint,
limits response headers and bodies, and joins original physical cleanup. Safe
history retirement, replacement/recovery, durable verification restoration,
reference authority publication and full SDK/provider qualification remain open.

Connection activation delegation has a bounded immutable map and a separate
full-entry digest. The reference binds the original parent namespace, issuer,
logical authority, signing key, signing interval and finite parent influence
range, preserving original history across ordinary refresh. Its fixed-purpose
entry has no self-signature or Head publishing authority. Independent complete
TrustConfig authentication, current revocation and policy, persistent authority
continuity, signatures, time and original transaction/admission owners remain
unqualified.

The internal Go Resume path uses bounded checkpoint/claims, independently
registered Ed25519 or HMAC application keys, exact execution headers and a
charged request/result codec. Preparation captures the actual accepted raw
Stream, transport context and local incarnation before creating the operation
ID, digest or reference. Its exclusive framing qualification prevents raw,
typed or bridge I/O from interleaving until the complete exchange settles.
Both directions use the original operation, Stream and dispatch owners.
The execution SQLite transaction consumes the issued token, advances generation,
binds the target and stores the recovery result together. Known token rejection
is retained as the recovery operation's result; cancellation, capacity and
ambiguous store commits do not become rejection. Explicit token issuance uses
its own idempotent execution and the same bounded history. A newer Session's
issuance duration does not rewrite an existing token's fixed expiry.
Functional/provider qualification and the public SDK facade remain unfinished.
No transport ACK grants application progress.

The rekey credit reference and four independent native test consumers check
the signed full-Session service interval, exact rational error allowance and
response-count bound against the fixed maximum epoch count. Forty-eight shared
vectors cover envelope rejection, full-width integers, role-specific elapsed
bounds, partial credit and saturation before multiplication. Credit projections
are pure: runtime must retain the original base and causal ACK anchor, deduct
once at the INIT gate, preserve post-charge at ACK and exclude pending-round
time. Actual clocks, authenticated parameters, owners and cumulative service,
work, crypto and cleanup reservations remain unqualified. No hidden time
tolerance or earlier root/policy deadline reduces the signed service commitment.
The Artifact composition reference decodes one bounded canonical original,
derives the profile/envelope/full service interval exclusively from it, and
returns its complete signed-object digest with exact independent backing
alongside the arithmetic result.
The caller supplies only the independently qualified clock rate/measurement
bounds. This reference authenticates no signature or TimeProfile and grants no
admission, consumption or service-reservation authority.

The crypto-usage registry binds the design's distinct fixed key, epoch and
Session limits for both cryptographic profiles, including root age, total
epochs and cumulative record-key derivations. Its 28 arithmetic vectors count
seal/open calls, complete authentication blocks and ciphertext including tags.
These pure charges do not authorize inputs larger than actual frame/library
limits or reserve usage. Atomic precharge, non-refund after cancellation,
independent aggregates, real root-age validation, maintenance reserves and
independent aggregate cryptographic proofs remain separate qualifications.
Independent Go, Rust, Swift and TypeScript test consumers recompute all charge
vectors from the generated registry and check block rounding and strict inputs.
Their arithmetic does not enforce live usage caps or qualify key/epoch/Session
accounting, actual invocation, independent cryptography or production behavior.

The trusted-time arithmetic reference consumes the common integer-millisecond
registry and 37 vectors. It bounds rational drift with outward rounding, counts
the complete network RTT, advances the original interval within age/width caps,
and projects conservative deadline and lower-bound proving increments. Source
sampling/encoding error and elapsed-measurement quantization are explicit,
separate bounds. Elapsed quantization bounds the difference between observed
and ideal monotonic increments and is applied before drift conversion, including
both inverse projections. Checked uint64 results use checked uint128 intermediates.
The decimal-string interface is vector tooling, not a Clock API. Independent
Go, Rust, Swift and TypeScript test consumers read the generated registry and
all 37 shared vectors, with native rounding, inverse-extrema and input checks.
Go uses bounded big integers, Rust and Swift checked 128-bit integers, and
TypeScript bounded bigint arithmetic. No time source, nonce, profile, clock incarnation, suspend continuity,
owner, timer, authority or gate reopening is qualified by these calculations.
Actual use still requires complete trusted resampling, original deadlines and
all independent security/owner gates.

The resource composition reference consumes the generated owner-key, charge-
binding, control-boundary and byte/work/item registry. It computes exact owner
unions for each supplied legal feature set before taking componentwise maxima.
Independent allocations add, and inconsistent declarations of one owner reject.
The corpus uses synthetic charges; these are not provider defaults or measured
limits. Trusted inputs must supply every real component and legal selection.
Only SDK-owned figures enter the SDK projection; provider-controlled, observable
and host-unobservable figures remain separate. Registered atomic owner transfers,
actual reservations, reference exit and physical memory measurements remain
unqualified. Independent Go, TypeScript, Rust and Swift test references consume
the generated registry and all synthetic vectors, including exact original
identity bytes, shared-owner conflicts and checked uint64 arithmetic. These
references grant no admission authority or actual provider qualification.

The partial resource-cost registry supplies coefficients for codec body buffers,
the complete two-role permanent bitmap and the fixed application baseline.
Its generated vectors cover ordinary, large-frame and constrained arithmetic,
conditional signed K presence and range, fixed query/rejection capacity and
management-channel differences. Shared schema limits supply K and the common
scope domain. These partial figures are not a complete ready_min or frame-fit
proof; actual objects, short-work protection, copies, indexes, maintenance and
cleanup obligations still require a complete qualified owner vector.
All four SDK test references independently consume the generated cost registry
and every shared partial-cost vector, including numeric and profile negatives.

The independent Go test-only CBOR reader consumes generated syntax bounds and
map descriptors, and round-trips every positive CBOR fixture. It rejects the
syntax-negative subset, including declared embedded CBOR documents, without
normalizing wire text. Its separate NFC implementation uses pinned Unicode 15.1
tables and the complete normalization conformance corpus. Owner byte caps are
explicit test inputs; forged lengths are checked before slot allocation. This
reader has a separate field layer that validates required/unknown fields,
integer widths, bounds, enums, fixed values, patterns, byte/array lengths,
declared text-map entries and nested/embedded map shapes. Generated referenced
registries and containing-map discriminators supply the field context. A further
layer validates generated closed variants and conditional numeric ranges,
including embedded certificate roles, status-specific admission codes and
authentication-specific exporter lengths. It checks required/absent fields,
constants, byte prefixes and branch-local equality/order without changing the
input. Its boundaries include P-256 encoding-prefix rejection and source-context
isolation; this grants no cryptographic or activation authority. The relational
layer adds generated equality/order, array identity/sorting, feature policy,
profile algorithm, carrier tuple and ERROR scope/retry rules. Full-map digests
use the generated domain and preserve embedded signature bytes. High uint64
timestamps are compared before subtraction. All rule layers share traversal and
containing-selector scope. The Go text layer uses the pinned Unicode 15.1 IDNA
tables and passes the complete official nontransitional ToASCII corpus. It also
checks IDNA2008 contextual rules, canonical DNS/IP spelling, exact registered
Origin syntax/default ports and local-loopback endpoint matching. Issuer input
conversion is separate from wire validation, which preserves original bytes.
Node and Go references now validate the currently registered map rules. The Go
external-oracle layer also recomputes OPEN digests and PoolSelectionSet members
from the complete signed Artifact and original candidate indices. Candidate to
Route projection consumes generated field names and IDs; received indices and
set bytes are compared without repair. Full Artifact signatures remain in the
digest, and returned public pool bytes are detached from secret-bearing input.
Candidate-set and route-set domains independently cover the same canonical set.
The Go metadata layer also composes the reserved typed shell from the generated
namespace/version, complete local definition digest and unchanged application
metadata. It verifies the definition and returns detached application bytes;
ordinary metadata parsing and required typed validation remain distinct. Exact
whole-object caps apply to composition, and malformed inner metadata remains
separate from outer OPEN validation. This layer grants no registration, codec
execution, application permission or stream ownership. The Go pool binding
reference checks received PoolSelectionRef digests, complete Artifact/proof
identity and deadline relations, and the exact paired winner ID/route under an
explicit immutable source profile. It does not infer pool authority from wire
shape or mutate caller selectors. Signature/trust/attempt ownership, actual
activation guards, authenticated context and runtime ownership remain separate
Go obligations. None of these references qualifies real DNS, TLS, Origin
headers or provider connections.

The independent Rust test-only syntax reader consumes the same generated CBOR
registry and preserves original bytes, including embedded canonical documents.
It checks shortest integer/length forms, fixed integer versus declared text-map
keys, schema-local nullable slots, depth and explicit input/capacity bounds.
It implements NFC over the pinned Unicode 15.1 tables and checks the complete
normalization corpus and Part1 complement without host normalization. Syntax
corpus, forged lengths, context boundaries and property checks remain separate
from field/variant semantics, IDNA, trust, authentication and live owner/work/
memory/cleanup qualification. A separate Rust field layer checks required and
unknown fields, integer widths/full uint64 bounds, fixed values, generated enums
and text patterns, text-map entries, nested and embedded structures, and explicit
context-selected field shapes. The pattern engine is a test-only dependency;
it matches generated ASCII patterns without changing the input. Missing public-
key/source context rejects, while a key prefix check does not validate a curve
point. Rust also traverses the generated closed variants and conditional ranges
through arrays and original embedded documents with isolated containing-map
selectors. Branch checks cover required/absent fields, constants, byte prefixes,
registered codes and equality/order. They preserve full uint64 bounds and fail
when required external context is absent. Its relational layer adds generated
ordering/equality, array identity and sorting, feature constraints, profile and
algorithm association, carrier tuples, ERROR scope/retry rules and full-map
digests. Full-width duration checks compare order before subtraction; embedded
certificate digests retain original signatures. These are stateless checks,
not validation of live carrier conditions, authenticated facts or ownership.
Rust uses the pinned Unicode 15.1 mapping, contextual, joining, script and Bidi
tables for UTS46 nontransitional conversion and IDNA2008 validation. Its separate
issuer and wire entry points enforce exact A-label identity. The text layer
validates canonical DNS/IPv4/hex-only IPv6, registered Origin schemes/ports and
local-loopback endpoint matching. Official ToASCII conformance, shared text
cases and property checks do not establish actual DNS, TLS or Origin admission.
Rust also recomputes OPEN digests and derives pool membership from complete
signed Artifact bytes and the original ordered indices. Candidate-to-Route
projection uses generated field names and IDs, and domain checks bind the
operation, schema and projection. Public pool results own their storage and do
not retain secret-bearing Artifact backing. The complete current CBOR corpus
includes both external-composition negative cases. Rust composes the reserved
typed metadata shell from generated namespace/version and complete local
definition bytes, verifies both codec directions, enforces whole-object caps
and returns detached application bytes. Metadata parsing and required typed
validation remain separate; malformed inner metadata does not become an outer
OPEN structural failure. Rust also compares PoolSelectionRef digests and
Artifact/proof identities, nonce, parent deadlines and paired winner ID/route.
An explicit immutable pool source is required, and derived crypto selectors
do not mutate caller context. These checks do not authenticate trust, consume
an attempt budget, acquire a ParentWinner/ledger guard, install codecs or
qualify live resource ownership. Full Rust receiver semantics remain unfinished.

The Swift test-only syntax reader consumes the same generated CBOR declarations
and hash-pinned Unicode 15.1 normalization tables. It checks canonical integer
and length forms, UTF-8/NFC, encoded map-key ordering and duplicates, schema-local
text-map and nullable slots, embedded documents, depth and explicit input/capacity
bounds. NFC comparison uses exact UTF-8 bytes; standard-library UTF-8 validation
preserves a leading BOM. The complete normalization corpus and Part1 complement,
shared positive/syntax-negative cases and deterministic input mutations cover
these boundaries. Parsing preserves original input but allocates test-owned
values; it does not establish aggregate live memory/work budgets. Embedded
document caps are resolved from declared lengths before payload extraction.
Swift's generated field layer checks required and unknown fields, full-width
integer bounds, enum/bitmask/constant rules, byte/text limits, ASCII patterns,
reserved namespaces, nested and embedded maps, declared text-map entries and
capacity arrays. Containing discriminators establish isolated child selectors;
caller context remains unchanged. Profile public keys have exact lengths and
P-256 prefixes checked; these checks do not validate curve points. The shared
field corpus, required/unknown mutations across 77 roots and context/boundary
mutations test these field rules. Swift also traverses generated closed variants,
conditional ranges and stateless relations through nested arrays and original
embedded documents. Rules enforce branch presence/constants, integer and byte
ordering, array identity, feature/profile/carrier constraints and ERROR scope.
Duration checks preserve full UInt64 and check order before subtraction; complete
embedded certificate digests retain the original signature bytes. Targeted
mutations distinguish valid field shapes from invalid variants/relations and
retain caller context. Swift uses the same pinned Unicode 15.1 mapping,
contextual, joining, script and Bidi tables for independent UTS46 and IDNA2008
validation. DNS labels split at scalar dots; issuer conversion and exact wire
validation remain distinct. Explicit IPv4/IPv6 parsing preserves address family
and bits, emits RFC5952 hex-only IPv6 and rejects numeric DNS aliases. Registered
Origin schemes/default ports and local-loopback endpoint relations are checked
without host URL normalization. Official ToASCII, shared text/map cases and
mutation properties do not establish real DNS, TLS or Origin admission.
Swift also recomputes OPEN digests and derives PoolSelectionSet from complete
signed Artifact bytes and original ordered indices. The generated Candidate-to-
Route projection and registered hash operation/schema/projection bind each
result. Received sets must match the derived bytes exactly; indices are never
sorted or repaired. Public pool projections own their bytes and retain no
secret-bearing Artifact backing. The complete current CBOR corpus, six shared
pool digest outputs, signature/field mutations and property checks cover this
stateless composition. Swift constructs and validates the reserved typed
metadata shell using the generated namespace/version and the full local
definition digest, including both codec directions. Whole-object caps apply
to the composed shell, and returned application bytes are detached. Invalid
inner metadata remains separate from outer OPEN structure. Swift also binds
PoolSelectionRef to the original Artifact, compares proof identities and parent
deadlines with full UInt64 precision, and requires paired winner ID/route
membership. The pool source must be explicit in immutable caller context;
derived crypto selectors stay local. These checks do not authenticate trust,
consume attempt budgets, acquire ledger/ParentWinner authority, install codecs
or establish aggregate runtime resources. Full Swift receiver semantics remain
unfinished.

The independent TypeScript test-only syntax reader consumes generated CBOR
descriptors and hash-pinned Unicode 15.1 normalization tables. It uses bigint
for wire integers and declared lengths, checks caller/schema and embedded
document bounds before extraction, and validates depth, container counts,
canonical key ordering, duplicates, schema-local text keys and nullable slots.
Fatal UTF-8 decoding preserves a leading BOM; NFC validation compares original
bytes without host normalization. Byte-string results own their storage for
both Uint8Array and Buffer inputs. Shared positive/syntax-negative cases, the
complete normalization corpus and Part1 complement, explicit capacity/embedded
bounds and deterministic mutations exercise these rules. The reference helpers
are excluded from published builds and all v4 references have a strict typecheck
target. The field-shape layer consumes the same descriptors for required and
unknown fields, full-width numeric ranges/enums/bitmasks, byte/text bounds,
full-match patterns, typed text-map entries and nested/embedded documents.
Containing discriminators override caller selectors only for their descendants;
profile-dependent public keys require an explicit or containing profile.
All positive/field-negative cases, missing/unknown mutations across 77 root
schemas, full UInt64 boundaries and 4096 input mutations exercise these checks.
The generated variant and stateless-relation layers traverse array and original
embedded-document paths with the same scoped context. They enforce branch
presence/constants, ranges and key prefixes, equalities/order, feature/profile/
carrier tuples, error scope, array identity/order and complete map digests.
Tests distinguish shape-valid contradictory roles/frontiers from legal input,
retain UInt64 precision through duration subtraction and include the original
certificate signature in its digest. Variant coverage includes 128 negatives;
relation coverage includes 725 negatives, with 12 host/Origin/external-composition
cases belonging to separate layers. The independent TypeScript IDNA reference
uses hash-pinned Unicode 15.1 UTS46/IDNA2008 tables, pinned NFC and checked
Bootstring arithmetic, with no host mapping. All 6265 official nontransitional
ToASCII cases pass; IDNA2008 adds contextual script/joiner/Bidi and assigned-code
requirements. Issuer conversion is distinct from exact original wire identity.
Explicit IPv4 and RFC5952 all-hex IPv6 parsing preserves address family/bits,
including mapped addresses, and rejects numeric aliases. Origin validation
uses registered schemes/default ports without URL correction. All 100 shared
text cases and 282 positive/735 negative CBOR maps are covered; only two
external composition negatives remain separate. Five 4096-case property paths
cover Bootstring, issuer/wire identity, IPv6 and mutated maps.
The external-composition layer covers all 282 positive/737 negative CBOR maps,
including the OPEN digest and pool membership. Generated map projections bind
the complete original signed Artifact, exact candidate indices and Route fields;
duplicate/decreasing/out-of-range selections reject without repair. Registered
SHA256 operations require the exact schema/projection and checked uint32 LP.
Public pool results own their storage, including when input is a Node Buffer.
Six shared pool domain outputs, every OPEN field, signature/selection/route
substitutions, caps and two 4096-case properties exercise these boundaries.
Typed composition binds both codec directions through the complete definition
digest and constructs the registered shell with exact application bytes.
Its 88/4096-byte boundaries, 4007-byte application overflow, nested wrappers,
owned output and inner metadata versus outer OPEN validation are tested.
Pool proof composition requires the explicit source profile, original Artifact
identity/nonce/audience, full UInt64 parent deadlines, distinct set domains and
a candidate ID/route digest belonging to the same selected entry. Derived
crypto selectors remain local to the validation; caller context is unchanged.
Two more 4096-case properties exercise metadata and pool-proof mutations.
These references do not install codecs, authenticate trust/freshness, consume
attempts, acquire ledger/ParentWinner rights or activate carriers. Full
TypeScript receiver, aggregate runtime resource/work/owner/cleanup, global error
precedence and provider qualifications remain separate.

The Go, Rust, Swift and TypeScript domain consumers independently construct inputs from all
51 generated domain descriptors and each verify all 99 positive/52 negative
cases. They check named arguments, fixed-width big-endian integers, LP lengths, exact
original map bytes, declared signature/MAC/field exclusions, selector-driven
maps, cross-input bindings and epoch/role relations. Primitive outputs cover
SHA256, HMAC and single-block HKDF Expand/Extract; Ed25519 emits signing input,
then a separate test signs the rebuilt bytes against the real public fixtures.
TLS/WT returns only the exact external label, context and output length, without
custom-domain rewriting. Raw TopUp projections retain their distinct encoding.
Tests cover missing/extra/inherited/type-invalid arguments, signature/MAC
exclusion versus full digests, original field IDs, UInt64 and QUIC stream-ID
boundaries, exact exporter parameters and 4096 mutations per language with
detached outputs. Fixture loading retains oversized tagged integers until
the domain gate rejects them; accepted integers preserve uint64 width.
Rust uses owned vectors and Swift uses value-semantic Data, with input mutation
checks for detached results. Native signing tests verify the shared signatures
against independently rebuilt inputs; Swift also verifies newly signed inputs
without requiring platform-generated signature bytes to be deterministic.
This does not qualify key custody, authenticated receivers, live exporters,
remaining domain allocations or independent cryptographic composition.

Go and TypeScript independently consume all 494 application-header cases using
generated variants and the native canonical/domain references. Exact fields,
request/response kind, type, contract, execution identifiers and management
serials must match. Complete execution bytes bind immutable options and the
exact contract shape; success/business errors keep original response limits.
Error schema and catalog matching use complete registered bytes; classification
distinguishes unknown codes and known payload-size failures without running a
codec. Exact SDK stop variants retain their independent 256-byte ceiling and
return code alone. Tests include zero limits, payload and contract boundaries,
all response kinds, malformed error maps and 4096 mutations in each language.
Go snapshots and TypeScript intrinsic byte capture bound copying and detach
outputs; TypeScript rejects proxies and shadowed view metadata without invoking
caller getters. These test-only consumers do not authenticate input, track real
channel/generation/serial owners, grant dispatch/retry rights, decide stop
eligibility or qualify aggregate runtime reservations, publication and cleanup.

The Go runtime ApplicationHeaderCodec validates the exact current generated
variants and returns detached scalar fields with explicit presence. Response
matching checks the original kind, type, contract, execution identity and control
serial; response limits come only from the original request. Application errors
obey that limit, while registered SDK errors retain their separate 256-byte
ceiling. Its explicit OrdinaryRPC classifier excludes NOTIFY, dedicated
streaming/Resume and M-control header kinds. ServiceContractCodec owns the
complete canonical contract, validates its shape and matches the exact digest,
method variant and request/response limits before starting an execution hash.
ExecutionRequestVerifier incrementally hashes contiguous payload bytes against
the original generated domain, full contract and immutable request options.
Truncation, duplication, changed offsets/options and digest mismatch fail
verification; explicit Close seals an aborted input. These codecs provide bounded backing
calculations; trusted routing, permission, operation admission, actual resource
reservations and execution dispatch remain separate runtime responsibilities.

The Go notification runtime uses `flowersec.notify.v4` with empty OPEN metadata
and the generated two-byte header-length framing. Original Session admission
protects two complete channel positions, one per opener, including continuous
16 KiB receive credit, the reader, publisher, send-ring attachment and a single
merged deadline timer per channel. All eight ordinary RPC channels and both
notification channels can coexist without consuming business Stream capacity.
Fresh channel ordinals become available only after actual cleanup returns the
original backing; retained aliases prevent reuse. The sole shared SendService
publishes their records.

Observation publication checks the exact registered contract and current
endpoint, lease, method and immutable deadline at byte acceptance. Each bounded
queued source owns an immutable payload copy, its original deadline projection
and a charged authority reference through the last provider tail. Complete local
message acceptance and physical publication cleanup have separate observations.
Cancellation before the prefix can refuse one message; cancellation after prefix
acceptance preserves the entire serial message boundary. Unbegun authorization
or deadline refusal leaves later messages usable. No notification acquires an
RPC network position, ReplySlot or result owner. Receiving observation dispatch
uses the original Session executor and bounded subscription queues, with isolated
inputs, serial callbacks and current authorization at application entry.
Public operation wrappers and supported-preset aggregate resource qualification
remain separate implementation obligations. Bare SessionCore construction cannot
claim an application profile. Internal services admission requires the original
application/RPC graph in the same batch, protected per-opener internal Stream
positions, continuous receive backing and the actual internal dispatcher in both
requirements and adoption. Execution profile admission remains closed pending
its original history and durable resource floors.

Rust and Swift consume the same application contracts independently, including
all 494 shared header cases, original response bindings, complete execution
inputs and contract limits, exact business schema/catalog bytes and SDK stop
payloads. Each has seven tests covering empty/1 MiB payloads, response limits,
malformed errors, owned digest/error results and 4096 header mutations. Rust
syntax results borrow immutable input under their checked lifetime; byte caps
precede domain argument copies. Swift captures exact bounded Data bytes before
parsing and checks output detachment from mutable Foundation backing. Its field
comparisons use canonical bytes, preserving exact text identity. These are
test-only byte relations with the same unqualified runtime boundaries above;
they do not imply typed codec execution, dispatch or completed publication.

The binding records exact hashes of the draft schema and vector manifest.
`ResponsePublicationStatus` has closed pending/flushed/unknown/not_applicable
states and finite causes only for unknown. The reference publisher binds an
original response's final byte once; full internal acceptance and ReplySlot
release cannot establish flushed. Only that complete byte frontier handed to
the actual provider before a terminal failure permits flushed. The original
policy timer starts at response publication binding, is bounded by the earlier
hard deadline, and is never renewed by waiting. First terminal outcomes remain
stable across later handoffs, tail failures and deadlines. Shared byte capture
uses an intrinsic byte-view brand check before immediate-prototype inspection,
so malformed inherited Proxy prototypes cannot execute caller traps. Native
provider attribution, actual clocks, owner transfer, maintenance policy and
cleanup remain unqualified; these local result types add no wire fields.

The dedicated streaming reference composes one complete initial request with
its exact execution/transient contract, bounded items and a final message-boundary
EOF or business error. It checks each original response binding, count and byte
limits, preserves a complete undelivered item across normal EOF, and records
local item delivery only through a separate trusted handoff observation. A
canceled status wait neither consumes nor discards input. At most one payload
assembly or result candidate is retained; the real reader must backpressure
before the next header while that candidate remains owned. These are test-only
relations over authenticated ordered byte events, not native framing, runtime
handoff, provider progress, admission or dispatch. SDK streaming terminal errors,
sender time/run limits, actual reservations/backing/cleanup and codecs remain
unqualified. The model's logical close does not assert a physical resource exit
or choose the production error scope.

The native API schema includes `DuplexResult` with two original directional
progress/tail results, source terminals, target send completion, terminal outcome
and independent cleanup. A Flowersec target reports authenticated `send_drained`;
a native Duplex target reports only `native_send_finished`. Closed variants and
private original-owner context bindings prevent the latter from claiming the
former. Normal transfer requires both source EOFs and complete target sends with
no remaining tail or first error; overall success additionally requires complete
cleanup. Generated declarations contain no private contexts or endpoint objects.
Reference matrices do not qualify actual adapters, distinct endpoint ownership,
half-close capability, first-cause preservation, tail transfer or bridge execution.

The unary fragment composition reference derives roles and lengths from actual
canonical headers and keeps request/reply tokens private. It validates complete
execution input (including empty BEGIN), interleaved offsets, original response
fields/limits, and the actual request ABORT/STOP boundary for fixed SDK codes.
Valid response ABORT retires incomplete bytes without decoding them or requiring
a guessed remote reason. Business failures remain complete bounded results.
It retains no completed serial tombstones and returns only metadata events.

This reference requires a trusted exact unary contract per request and an
already reserved Session capacity share. It models at most twice that share in
live payload buffers, each at most 1 MiB; header/contract metadata, fragment
scratch, parser/hash copies and physical backing/GC costs are separate. It does
not parse fragmented provider/record input or qualify authentication, current
routing, local refusal/discard, fixed read methods, publication, callbacks,
real reservations/cleanup, Offer/deadline/ledger checks or dispatch. Closing an
invalid reference transcript does not classify a local setup or resource error
as a peer fault or select a production transport error scope.

The Go runtime RPCFragmentParser incrementally handles every fixed prefix/header
split and multiple fragments in one read. Its retained header is at most 535
bytes; DATA pieces borrow the original bounded input without a complete-fragment
payload allocation. A reader transfers or discards each borrowed piece before
reusing input and credit. Length/kind/serial-zero errors and mid-fragment EOF
seal that parser generation. The caller still owns continuous BEGIN serials,
live request/reply lookup, exact message offsets, ABORT/STOP eligibility and
original completion resources. The same codec encodes into admitted caller
storage and validates local capacity before writing; the publisher separately
owns first-byte acceptance and serial allocation. Shared binary/header vectors,
arbitrary split/concatenation tests and a fragmented 1 MiB execution request
exercise these production codecs without asserting a complete RPC service graph.

The Go rpcv4 Network owner consumes one reserved Session aggregate for outgoing
completions and incoming ReplySlots. Each role shares the signed general K and
two fixed-query positions across ordinary channels, dedicated streaming and
live old generations. Full-to-late transitions retain the original ticket,
header and path; generation checks fence recycled slots. Only a trusted exact
query kind/type/contract binding may enter the query reserve. Canonical incoming
requests that need profile or method refusal still acquire ordinary rejection
responsibility. Closing admission retains outstanding ownership until the
original terminal-input/output or channel-cleanup gate releases each ticket.
These capacity tokens themselves establish no transport or execution facts.

RequestInput consumes separately admitted original input/hash backing, copies
or discards contiguous DATA pieces and verifies execution-only digests before
one-time payload transfer. Incomplete ABORT cannot produce validated input.
The resulting VerifiedInput permits one internal immutable byte borrow; logical
Close retains its backing and charge until actual codec/callback alias use ends.
These byte owners perform no application callback and create no worker.

The private ordinary RPC channel now couples that Session-wide table to a
single fair publisher and an incremental receiver. Outgoing requests require a
complete result reservation before BEGIN, including the independent 256-byte
SDK-error allowance. Actual whole-fragment acceptance in the original Stream
ring assigns serials, advances offsets and transfers terminal ReplySlots in one
Network gate. Unstarted cancellation burns no serial. ABORT/STOP intentions use
the same fair queues and disappear atomically when the response ends. Only the
last batch's real provider publication permits the next batch; the conservative
policy currently selects one fragment at a time. Generic Stream writers cannot
compete with this attachment. Publication facts survive slot reuse and never
turn a replaced business response into a flushed result.

The receiver validates continuous BEGIN serials, original reply associations,
exact payload offsets, SDK stop codes and complete/aborted input boundaries.
DATA aliases the original admitted read buffer until copied or discarded; no
per-message fragment buffer or completed-serial history is created. A complete
result releases the network position before application consumption, while its
original backing remains charged through transfer or outstanding byte borrows.
The channel runs finite SDK reader/publisher services on the original Stream.
Its continuous receive minimum is restored atomically in the original receive
pool, and the existing bounded maintenance service publishes credit ACKs.
This reuses the real record, credit, crypto and provider owners.

ContractRoutes owns each method's immutable exact canonical contracts and rejects
conflicting namespace/type or digest bindings. A charged capture retains its
original semantics through registry closure. It neither selects another method
by type alone nor preserves a second handler implementation.

ServiceInputs installs one protected K+2 discard/hash reserve for the original
Session. Full request capture tries the original resource root and account
scopes without waiting. Insufficient capture memory or resource metadata slots
select a local refusal; protected parsing/hashing continues while other serials
progress. Known contracts still verify execution digests when their type, shape
or limits require refusal. An unknown execution digest lacks the original
contract body required to compute the hash: its completed framing is explicitly
refusal-only, cannot be taken as verified application input and has no live
STOP_OUTPUT eligibility. No lookup scans a same-type handler. Fixed SDK reads
remain unavailable until their complete protected service is installed.

The receiver queues service refusals only after the original complete framing
and applicable digest gate. Partial rejected requests can instead accept ABORT
and produce only request_message_aborted. The input reserve returns after actual
discard/hash exit; captured bytes remain separately charged through application
borrow exit. Closing the table or registry preserves these real responsibilities.
Captured route metadata is a detached original projection, not current permission.

OutputInterest observes only its original invocation's response path. Handler
return fences future waits without inventing loss of output interest. STOP,
actual terminal output acceptance and output unavailability publish monotonic
facts; cancellation of a bounded wait does not cancel output or execution. A
retained view cannot follow a reused ReplySlot, and closed output cannot acquire
a new interested observation. Real invocation/waiter tails retain their charge.

Ordinary RPC SDK error variants cover execution/transient unary and the two
fixed ordinary reads. The canonical code registry contains the two message-stop
codes and bounded contract/limit/resource/method/authorization/deadline/service
errors. Each current payload is three bytes and uses the original independent
256-byte SDK-error reserve, including when the success limit is zero. Success
and business errors retain the original response limit. Exact request variant,
type, contract and applicable execution IDs/digests remain mandatory. Service
errors cannot replace a response whose BEGIN already won; replacing an unstarted
business response settles its original publication without claiming a flush.
These payloads assert no global nonexecution, retry permission or delivery.

The Go fixed-query codecs validate canonical 1..8 explicit targets against
actual retained known bodies, and match full/unchanged/denied/unavailable
snapshots to the original target set. One private envelope decoder and one
reused complete contract arena validate every nested contract and applicable
Offer before copying any full body into distinct admitted destinations. The
private envelope cannot be used as a general contract decoder. ServiceContract
text workspace follows its closed 128-byte security-identifier graph; opaque
application definitions remain bytes. Server encoding uses the original schema
IDs and reproduces the shared canonical responses. Offer parsing checks exact
execution semantics, digest and the trusted finite window bound; it does not
install an advertisement or prove current time/permission. Shared positive and
negative queries, eight actual 8192-byte bodies, malformed nested bodies, alias
rejection and zero partial publication on failure cover these codecs. Protected
Q2 service ownership, current authorization and Offer registry updates remain
separate runtime assembly obligations.

Complete SessionPlan installation, fixed SDK services, current authorization,
result/executor/dispatch admission, whole-call submission, application execution,
operation lifetimes and runtime/provider qualification remain unfinished. The
internal admission interface is restricted to finite SDK work. Streaming terminal
and Resume errors remain unresolved; these ordinary RPC codes do not define them.

The schema owns field definitions, constants, vector inputs and explicit
unresolved requirements. Generated constants share that schema hash across
Go, Rust, Swift and TypeScript. The current corpus covers CBOR integers, fixed
frame fields, nested handshake/identity/authorization maps, READY, rekey and
TopUp recovery structures. It checks stateless terminal, credit, role,
embedded binding and TopUp digest/projection constraints. Structural fixture
signatures and keys are public test material;
the corpus does not establish handshake cryptography, state-machine behavior,
SDK interoperability or provider qualification.

Revocation record references cover original certificate and parent Artifact
evidence, plus one original issuer authorization's two-class impact vector and
signing interval. Only schema-declared uint64 impact positions admit canonical
null. Matching and pairwise component maxima establish relations between
supplied originals, not complete permission history, State membership or safe
GC. Independent original purposes, namespace/generation attribution, full
capacity/impact bounds, permanent floors/trust retirement and real reference
exit remain mandatory implementation gates.

Issuer entries retain sorted original authorization evidence under external
capacity-derived byte/count bounds. Declared capacity arrays have separate
reference parser bounds; ordinary arrays keep their existing cap. Complete
State arrays are required even when empty. Their count limits intersect the
same original byte envelope, including zero effective item bounds; the LP width
rejects unsupported envelopes without reducing immutable namespace capacity.
The State digest binds original canonical bytes, with exact Head field/floor,
length and capacity matching. Cohort references select per-class disjoint
immutable segments, keep narrowed authorization deadlines separate from original
GC bounds, and check original issuance, later activation signing, parent/grant
intersections and segment retention. These are stateless relations over supplied
authenticated context. Full credential dependency binding, signature/trust/time,
history completeness, actual reference exit, atomic continuity/GC, subscription
resources and independent SDK codecs remain separate obligations.

Ordinary unary/streaming business-error headers have exact execution/transient
variants and a nonzero application code. Reference matching preserves original
request association and response limits. The independent error-schema domain
hashes exact pre-registered application bytes; catalog matching compares the
whole ErrorDefinition, never just code or revision. Classification distinguishes
unknown legal codes from known-definition size mismatches. It does not decode
application values, install codecs, transfer result ownership or qualify SDK
refusal, streaming-terminal or Resume behavior.

The signature primitive corpus uses public RFC8032 fixture keys and exact
registry-generated signing messages. Four library consumers check the same
positive and negative bytes. Go, Rust and TypeScript also reproduce the
deterministic signatures; Swift CryptoKit may randomize freshly signed output.
Complete strict A/R point, nonidentity and prime-order subgroup acceptance is
still unqualified, as are embedded signer identity, trusted object chains and
Noise/post-handshake composition. These fixtures do not authenticate the
placeholder signatures inside structural objects or qualify runtime keys.

The strict acceptance corpus adds schema-owned Pure Ed25519 policy and
public-scalar adversarial fixtures. Both A and R cover every torsion class and
mixed-order witnesses that satisfy the cofactored equation. Exact encoding,
scalar bounds, prehash and domain substitution cases retain the original bytes.
Four reference adapters consume the same strict corpus and post-validate signer
output without retry. TypeScript explicitly checks both prime-order groups before
Noble's cofactored verification. Go uses canonical roundtrip and the public
Edwards point operations for the subgroup predicate, then standard verification;
Rust uses Dalek's point predicates and ring verification. Swift uses the public
libsodium predicates/verifier through exact swift-sodium 0.11.0, with CryptoKit
signing. Its Apple artifact embeds libsodium 1.0.22; current execution evidence
is macOS arm64 only. The TypeScript generator and consumer share Noble.
Independent adapter equivalence review, all runtime signing and verification
entries, work/cache ownership, deployment coverage and Noise composition remain
unqualified; shared corpus success does not replace those obligations.

The profile DH reference corpus covers RFC7748 anchors, the complete X25519
noncanonical interval and high-bit aliases, twist and zero-result inputs,
private-material clamping, P-256 scalar/SEC1 boundaries and a valid P-256 point
that produces a forbidden zero shared result. Four public-library references
consume these fixtures, preserving original supplied bytes. Execution covers
macOS arm64 only. Fixed-material key derivation does not qualify entropy, key
handles, certificate binding, real Noise token/transcript processing, KDF
ordering, rekey, cancellation or resource ownership. These remain required
before runtime and full profile qualification.

The shared Noise corpus contains two captured library transcripts and 524
message negatives. Rust and test-only Go library adapters consume both profiles
and compare messages, canonical Split, final H and initial root for both roles.
The Go adapter uses pinned flynn/noise source with an explicit public-key-length
interface extension; the unchanged upstream library also compares X25519.
The included source manifest, reversible patch and license are checked, and
source/SDK inventories attribute the derivative separately. Release binary
inventories include it only when actual runtime package imports require it.
Swift/TypeScript Noise, authenticated Flowersec prologue, READY/records/rekey,
runtime ownership and independent cryptographic qualification remain open.
The exact source and qualification scope are recorded in the traceability map.

The record reference corpus derives fixed public keys from the captured Noise
root and supplies exact header, nonce, domain, length and AEAD bytes for both
profiles. Four test-only consumers independently reproduce those encodings and
cryptographic outputs, including every generated authentication mutation.
Numeric epoch/sequence boundary fixtures use synthetic public key material;
they do not authorize those values in a live Session or prove rekey history.
Payload CBOR is supplied by the reference generator. Runtime decoding/error
scope, READY, sequence/replay admission, usage budgets, lifecycle and provider
qualification remain outstanding.

The READY composition corpus uses captured Noise roots, synthetic context
digests and distinct public RFC8032 role keys. Four test-only consumers
independently encode its three maps and domain inputs, derive confirmation
keys/MACs, sign, strictly verify and reject malformed bytes, context substitution
and reflection. Valid-MAC invalid-proof cases exercise the independent identity
factor. Swift verifies its fresh signer output and computes the corresponding
MAC without requiring deterministic signature bytes. These exact READY codecs
do not qualify general payload decoding. Authenticated credentials and admission,
the full Flowersec prologue, one-shot dual-READY publication, current
authorization/resources/deadlines, runtime secret handling, rekey, independent
composition proof and provider qualification remain required.

The rekey composition corpus chains two public fixture rounds for each profile
from captured Noise roots. Four test-only consumers independently reconstruct
canonical INIT/REPLY/COMMIT/ACK, complete message digests, profile DH, the exact
Extract/Expand schedule and old/new maintenance records. The phase MAC omits
only its registered field. COMMIT/ACK use new directional keys at scope zero,
sequence zero and bind the exact supplied old maintenance frontier. Mutated,
truncated, noncanonical, reflected, substituted and stale-key cases cannot
match the expected fixed transaction. These four consumers are expected-byte
matchers, not general receiver codecs; the Node reference additionally parses
phase maps. Fixture barriers and sequence frontiers do not establish live
history, clock/credit admission, freeze, barrier satisfaction, preinstallation,
publisher ordering, epoch authority, runtime key cleanup or authenticated
Noise/READY composition. Those gates and independent crypto/provider
qualification remain required.

The native I/O result subset also defines WriteProgress and TransferProgress.
A serial reference preserves each request's local acceptance count across
cancellation, queue failure, repeated Start and canceled waits. Record tickets
never replace accepted bytes; accepted completion and cleanup remain separate.
Transfer validation conserves the one-chunk remainder in either the returned
tail or an explicit source adapter, using private original-owner context.
Generated declarations are internal to the four SDKs. These references do not
implement real input capture, queues, clocks, concurrency, provider publication,
Finish/Copy/bridge behavior or runtime ownership and cleanup guarantees.

The internal Go Copy kernel uses one reserved chunk, retains the original
receive claim for its complete lifetime and advances destination bytes through
the existing FIFO acceptance gate. Source consumption and destination acceptance
maintain separate cumulative counters at their actual copy points. A failure
returns the exact bounded unaccepted tail to its caller without retaining a
transport graph. EOF includes pending chunk acceptance; Copy does not send FIN
or reset either direction. Its native TransferProgress validator consumes the
shared corpus. Both endpoints and the chunk currently require one Environment
and budget root. A pre-admitted persistent state provides coherent metadata
snapshots for lifecycle compositions. Its full chunk reservation remains held
through actual worker exit and final payload handoff. Public adapters, other SDK
runtimes and physical resource qualification remain outstanding.

The internal Go StreamOwnership capability claims the original admission slot,
send queue and receive direction together. It rejects an existing full owner,
reader/cursor, helper writer, prepared operation or observer before consuming
its same-Environment metadata reservation. The capability pins the original
retirement index and bounds actual method aliases; accepted-byte progress is
updated in the original queue acceptance gate. Revocation closes both I/O
gates and wakes read/write/cursor/Copy waits without refunding actual tails.
Cancellation and finite close observations remain available under saturated
I/O. Trusted transport failure cancellation retains its original authority.
Copy observes both endpoint revocations and destination termination during
source waits. Copy/WriteAll and their current child write share the queue's
original aggregate method capacity, retaining it between child calls. Release
requires actual method, read, helper and prepared-write tails to exit, then
detaches the capability from its transport graph. A dormant cursor must still
be settled or closed by its owner. The private callback handoff seals application
I/O while retaining lifecycle Finish authority. Compositions bind their original
operation context and deadline to both data gates; timer scheduling never grants
additional acceptance or delivery.

The internal Go handshake retains an immutable, detached SessionContract and
its original Artifact digest and signed service span. The same original hello
snapshot is required before Noise starts. Record preparation preserves the exact
signed frame limit, keeps local positive admission separate from the signed
stream limit, and retains credit, RPC and rekey parameters for construction.
Receivers cannot narrow that frame limit. Rekey peer barriers use the signed
limit intersected with the registered barrier bound; handshake-backed rekey
credit must retain the original envelope and signed service span. Transport
permits zero positive streams while keeping ingress, rejection, maintenance and
termination responsibility; bootstrap profiles still require a positive slot.
These internal constructor checks do not constitute full Session resource
assembly, provider qualification or a public v4 connection path.

The Go record Engine separates logical closure from cleanup of its own record,
scope KDF, staging and rekey backing. Actual workspace borrows include received
and outgoing reliable and datagram packets; an idle reserved shared-reader lane
is not a borrow. Cleanup waits for the original work to leave, clears owned
buffers, and detaches packet and rekey aliases. SessionRuntime joins that cleanup
in addition to its service and reader exits. The independent handshake signer
and root remain a separate owner, and this gate does not retire or qualify a
complete Session resource vector. READY results and rekey marker validation
recheck the original Engine after unlocked work before using or publishing it.
SessionRuntime observes parent cancellation with its original Run caller and a
private context gate. Opaque parent contexts create no additional propagation
task. The gate freezes the first child error and signals cancellation before
interrupting input; actual reader exits still govern cleanup and retirement.
InitialExchange uses one private standard-library cancellation registration,
dispatched by its original watchdog or exchange gate. It preserves provider
context values, deadlines and descendant cancellation causes without creating
an opaque-parent propagation task. Its separately charged context adapter has
no handshake backpointer; actual cleanup drops the exchange's references while
provider-retained contexts remain under the provider's own lifecycle.
Each Engine constructs two fixed scope indexes and one bounded epoch KDF job
array before record use. Capacity covers scope zero, optional datagrams, local
positive streams, and the independent pending/rejection overflow positions.
Epoch changes detach the old index before recycling its array; unique key owner
identities remain with live jobs and packets. Key objects, crypto implementation
backing, DH/KDF scratch and allocator costs still require separate accounting;
the fixed indexes alone do not qualify a complete Engine resource charge.
Reserved Engine construction checks the source-sized backend charge before
allocation, borrows the same Environment dependency owner, and retains both
reservations through real record cleanup until explicit retirement. Its current
backend bound covers the pinned Go and x/crypto assembly implementation on
amd64/arm64 without BoringCrypto, runtime FIPS or a frozen FIPS module; other
backends are refused. Runtime/allocator overhead is an explicit additional
allowance, and shared registry/crypto caches remain Environment responsibility.
Reserved OPEN admission accounts for the actual slot/index/arena/bitmap/decoder
backing and logical carrier identities without counting IngressBytes twice.
SessionRuntime joins admission method tails, actual Stream ownership release,
flow/read/cursor cleanup and original carrier closure. The original shared
reader owns its logical associations; native providers report their own real
closure. Closed-session disposal releases barrier and retirement references
without manufacturing stable IDs, ACKs or DRAINED proofs. Timeout observation
never refunds unfinished ownership.

The internal transport SessionCorePlan atomically reserves the complete
Engine, OPEN, liveness, termination, rekey, retirement, ingress, send-service
and runtime graph before consuming the plan. Both roles install the same
graph on the original InitialExchange before dual READY. Shared byte and
message carriers retain whole-envelope publication ordering and one physical
close owner; cancellation can return while actual provider calls stay charged.
Message framing validates a complete bounded envelope before exposing a prefix
to the shared reader. Original Initial cleanup, service/method tails, manual
rekey references and carrier cleanup are joined before final retirement.
Environment borrows are acquired with the original plan and moved into the
Engine/carrier without allocating reference slots during authentication.
Tests exercise both crypto profiles through original Noise, dual READY, OPEN,
bidirectional Stream data, cancellation and exact aggregate refund, including
exhausted reference slots after plan construction.

The shared-carrier Stream factory uses one Session receive pool, so independent
Streams cannot multiply signed credit. It reserves each complete send/queue/
ownership vector atomically and constructs the private I/O facade before
accepted publication. Fixed OPEN notifications support one pending dispatcher
and one outcome or decision observer per original OPEN without waiter queues.
Before application metadata disclosure, an OpenPreparation reserves the sole
ordinary terminal proof and recent position. That same proof follows acceptance
or rejection; metadata and callback references survive Close until actual exit.

A frozen raw Stream handler plan can be installed before READY on either role.
Its captured registration, trusted local context and per-kind position stay
fixed through authorization, accepted publication and handler cleanup. Actual
authorization and handler callbacks use the original shared executor. A handler
permit is acquired before accepted, and the registry's final acceptance check
runs in the original OPEN commit gate. Registration Close seals future admission
without rebinding accepted handlers. One fixed invocation deadline covers both
phases; cancellation, panic and Goexit preserve real callback and I/O tails.
The local core batch also reserves one real Session position against the exact
trusted tenant and Session accounts. The enclosing admission owner can include
that batch with Initial and its own metadata in one atomic reservation. Adoption
moves existing handles and preadmitted Environment borrows; it does not race for
another reservation or reference after consumption. All positions remain held
through the original cleanup and explicit retirement.

A fixed feature envelope enumerates the canonical legal selections for the
original Artifact/candidate, local capabilities, proposed offer and route policy.
The authenticated Hello must retain the exact original local offer, candidate,
attempt and full Session contract. The current internal consumer admission path
accepts shared-carrier transport, services and execution assemblies. Resume
may be selected only with its signed enabled policy and complete execution
assembly. Unsupported datagram/native aggregate graphs are rejected before
claim. It binds the actual prepared
carrier, original Environment, tenant/Session scope and pre-spend credential
subscriptions through exclusive adoption with rollback. Both negotiation and
low-level wire publication validate the original Hello binding before sending.
The current activation authority must match the complete detached proof facts;
FSB signing and raw publication also bind its exact original proof bytes.
The original activated-preauth reservation is rechecked before claim.
Original claim completion, activation, authentication and final
READY delivery each retain their own once-only gates and actual cleanup tails.
Prepared carrier handles expose no I/O until their original admission owner
activates them, and physical Close is dispatched once even across error paths.

The internal direct Acceptor owns a bounded preauth entrance before trusted
material lookup. It retains the original ClientHello, then checks the signed
direct candidate against the same accepted provider before producing ServerHello.
The verified FSB must match its actual received bytes, original authority, full
Hello and credential closure before atomic Session/core reservation and exclusive
adoption. The original admitted continuation gates FSA and Noise; a verified
entrance can instead send one signed rejection without a claim or Noise right.
Admitted FSA signing and raw publication retain the exact original FSB binding,
server epoch and unpredictable reservation key saved by the original durable CAS.
Provider policy, store calls and all Initial/Session method tails remain charged
through actual cleanup and retirement. Prepared and accepted wrappers require
the physical provider's own Environment check, in addition to their local charge.
The once-consumed establishment component copies the original canonical material
and checks local identity keys before spend. It assembles Hello, FSB/FSA, Noise and
both READY flights for the original consumer and accepted carrier. Live proofs
are independently verified after complete TxB, or from the received FSB, against
the authority mapping captured before the result arrives. Its material and key
references stay charged until the original Session and provider have cleaned up.
The internal Environment lifecycle owns both source paths and accepted Sessions
through actual retirement. Its fixed positions include the establishment/runtime
caller and original cancellation watcher. A canceled Connect returns independently
of provider cleanup; successful dual-READY delivery detaches only that caller's
cancellation, preserving original signed deadlines and trust. Closing a Session
leaves the Environment available; closing the Environment rejects new ownership
and joins all original positions. Borrowed roots, stores, executors and providers
are not closed as shared dependencies. A blocked Close or I/O keeps its original
Session position, and task panic/Goexit never publishes a Session or refunds its
live graph. Source acquisition and carrier preparation enter that same finite
position before issuer work. The original watcher drives the fixed preparation
deadline and dependency closure even while a provider is blocked; a late carrier
is closed and joined before its position can be reused. Accepted intake owns an
original entrance before reading ClientHello or looking up material. The bounded
trusted resolver receives unauthenticated lookup bytes, with no application
authorization implied; its material enters the same complete FSB/admission path.
Hosted entrance gates reject competing manual readers and negotiation. Late
resolver results and blocked accepted I/O retain the original position until
physical cleanup. Listener/upgrade dispatch and Serve aggregation remain outer
composition.

ApplicationIdentity captures a complete verified certificate and matching local
Ed25519/static-DH capabilities with current independent issuer/policy/revocation
checks. ArtifactLease owns canonical credentials and a fixed activation source
without local private handles. Raw-byte constructors verify the original
canonical bytes using installed independent TrustConfig owners, resolve exact
issuer scope/policy and activation delegation/once-authority mappings, and check
the complete current credential closure. Material cannot provide its own trust
root or change its configured activation source. Local key-provider calls finish
before the final current-authority checks. ConnectionMaterial retains both original owners
and a local source incarnation/generation. Its once-only establishment fixes the
selected winner, current endpoint subscriptions and original key handles; multiple
material wrappers cannot repeat the lease's local claim. This local claim makes
no durable spent assertion. Closing an identity/lease advertisement prevents new
captures while existing material retains its exact keys through physical Session
retirement. String/debug/JSON projections expose no material or key data. The
current material composition admits direct routes; tunnel grant capture remains
a separate obligation. Environment static material construction admits a finite
original position before key/provider work. One shared expiry worker closes
unused snapshots at their original nonrenewable end, detaches only successful
creation from caller cancellation, and retains canceled or abnormal constructor
tails and materials attached to establishment through actual retirement. This
hosting does not implement durable pool installation or TopUp.

Static ConnectMaterial enters the same original source preparation owner with
an Environment-hosted material. Local admission checks the Environment, fixed
generation, source, role and exact application profile/K before transferring
the exclusive preparation claim. Local refusal preserves the material and all
caller references. After transfer, the admitted worker checks current keys and
trust, prepares the signed candidates and runs the same spend/admission, Noise
and dual READY path. Material close or expiry seals an unattached preparation;
blocked provider/key work retains its original material and Environment slots
until actual cleanup. Already attached establishment keeps its captured security
references independently of closed identity or lease advertisements.

Material acquisition captures the original identity before calling its trusted
issuer provider and preadmits the complete immutable result storage. It checks
the exact requested application profile and K before publication. Live material
also validates the original delegation, authority mapping and current independent
trust without manufacturing an activation proof or winner. A consumer additionally
requires a currently usable signing window for its future TxB. A verifier checks
the actual received proof's original issuance time and activation deadline;
ending new issuance does not itself invalidate an already issued proof.
Only the actual original TxB result can supply that proof. The source assembly
derives the Session contract and legal feature envelope from the acquired lease,
checks each candidate's supported graph and complete current credential closure,
and races only the original signed candidate set before admitting one Session.
A pool's exact ordered subset and cumulative address, preauthentication byte,
work and parallelism ceilings constrain the local defaults of two candidate
methods, two addresses per candidate and 250 ms between candidate starts. Each
attempt consumes its complete qualified allowance before provider work. Original
method and loser cleanup tails occupy the same two positions until actual exit;
a late result cannot become a winner. An invalid unadopted winner can be retired
while unstarted candidates continue under the original common deadline and
remaining budget. Local lease exclusivity begins before preparation without
asserting durable consumption. Final admission owns the selected handle; no
post-claim replacement or source fallback exists. A known unsupported local
application profile is refused before acquisition.

The in-process live authority can construct its original unsigned plan after
selection using previously admitted signing/dependency backing and fixed original
times. Every live consumer checks the plan against the actual complete winner
before beginning a durable claim; a plan for another route cannot first consume
the lease and fail only after signing. The complete adoption-to-claim replacement
policy and remote authority transport remain separate assembly obligations.

The concrete numeric WebSocket adapter borrows immutable deployment policy and
reserves the actual provider charge in the same root before dialing. Its trusted
route check receives only the public route; preparation receives no PSK, proof,
certificate or identity key. Wrapper failure joins the original socket/provider
before returning. A fixed finite numeric address snapshot serves each candidate;
no provider appends addresses or retries internally. Aggregate physical TLS/HTTP
read and write bytes have one original preparation ceiling, removed only after
successful upgrade. TLS or route-policy failure exhausts that candidate without
trying weaker policy. Qualified work bounds remain explicit provider inputs;
DNS selection and a public provider snapshot remain separate assembly obligations.

The complete application SessionPlan/feature ready_min, remote control delivery,
invalid-material rejection service, RPC services and public Connect/Serve
factories remain separate implementation obligations.

The internal Go AdmissionLedger uses pinned `modernc.org/sqlite` through one
private synchronous driver connection. Explicit Create and Open have separate
provisioning semantics: Open requires an existing current manifest and exact
schema, and never creates, migrates or repairs missing history. WAL, synchronous
FULL, fullfsync, checkpoint_fullfsync, exclusive locking, fixed page/cache bounds
and zero busy timeout are configured and read back. Each new connection advances
the persisted uint64 epoch without narrowing or wraparound. A prewrite checkpoint
bounds WAL accumulation across normal writes and crash recovery. Every cursor is
closed exactly once; cancellation never detaches a provider call.

The signed original FSB/activation/Hello supplies immutable admission facts. The
only lease key is tenant, Artifact issuer and lease. The reserved projection fixes
the original Acceptor invocation/carrier incarnation, authority, owner, full FSB
binding and deadlines. A single exact version/fence/projection CAS stores admitted
and its original reservation key; only the original bounded `Invocation.Dispatch`
can grant the existing accepted token's FSA/Noise continuation. Lost admit results
permit bounded read-only confirmation of the exact projection. Reserve uncertainty,
conflicting attempts, cancellation and restart never recover a dispatch guard.
The accepted aggregate retains complete FSB and Hello bytes through actual cleanup.
Finite history capacity refuses new leases; no automatic deletion refunds history.

The same bounded SQLite transaction domain has a separate SpendLedger table;
its primary key remains tenant, Artifact issuer and lease across both sources.
Pool consumption persists one absent-to-consumed TxA-P with the complete original
issuance proof, selection digests, signed budgets, winner and original Connect /
PreparedCarrier incarnation. Only definite success reaches that original local
activation gate; uncertain commits have no confirmation continuation or fallback.
The live authority freezes the original complete unsigned direct proof, signer,
intent, request, owner and client material deadline before TxA. Only original TxA
confirmation dispatches policy once. Positive policy signs the original projection
and complete TxB stores consumed plus proof before original publication. The
consumer independently validates that proof and current trust before activating
its own carrier. Denied/unknown policy results have no publication guard. Existing
rows, copied lifecycle booleans and reopened stores cannot create either guard.
The in-process live composition exercises these separate authority and consumer
gates; remote material delivery, tunnel grant sets, terminal reconciliation and
history administration remain distinct implementation obligations.

The persistent SQLite backing has a separate disk charge, retained across store
Close/reopen. Store cleanup joins its actual call and provider Close before
retirement; disk quota is released only after the trusted host has independently
removed all database/journal files. Deployment requires an independently trusted
continuity/provisioning gate and stable server/service/audience authority mapping,
an exclusive application-owned directory on a local filesystem with verified
locking/fsync semantics, and qualified driver/runtime/filesystem overhead budgets.
SQLite cannot authenticate an old backup against its own rolled-back manifest;
there is no default rollback-recovery gate, network-filesystem fallback or memory
once store. Early control-plane reservations, terminal/GC administration and the
other purpose-specific ledgers have separate implementation obligations.

The internal Go business execution store uses a separate exact SQLite purpose,
manifest, caller-domain floors, contract registry, and execution table over the
same bounded connection engine. Its trusted continuity interface is distinct
from admission and spend continuity. The immutable configured service tuple,
caller domains, method shapes and capacity are checked again on Open. Recovery
requires independent proof that the full history is current and the old actual
work has ended or been fenced; no recovered row creates an execution capability.

Registration looks up the full caller authority, stable subject and operation ID
before new-admission checks. Existing matching records require no new Offer,
registration revision, deadline window or work reservation. A new record binds
the exact original canonical contract, registration revision, history deadline
and complete response backing in one transaction. Its independent original
invocation identity prevents uncertain older cleanup from modifying a later
registration of the same key. Distinct Offer intervals are never merged or
withdrawn before definite expiry; renewal preserves accepted original terms.
Only definite new registration returns permission for an original
work owner to attempt its single durable dispatch handoff. Lost registration or
handoff commit results leave cleanup responsibilities without dispatch rights.

Work, run deadlines, cancellation requests, result formation and actual task
exit have separate ownership. An attempted result commit cannot be replaced by
another Finish. Query and result reads return facts and bounded copied bytes;
they do not construct work or reset retention. The result digest is checked on
read. Result expiration does not refund live work. Each collection turn handles
at most 16 records and commits monotonic domain floors before deleting eligible
details in that same transaction. Actual work and unexpired history or promised
results prevent detail reclamation, including unknown outcomes. Store Close and
root revocation still permit retained cleanup of the same actual work; the
connection remains charged and open until those original work pins return.

The internal verified-input adapter and execution dispatcher connect this store
to the actual root ApplicationExecutor. The original executor permit, verified
input, exact route/authorization capture, complete SDK output and storage work
are admitted before registration. Storage calls run outside finite SDK gates.
Only a definite durable handoff delivers input to the handler. Actual return,
panic and Goexit all retain the original task through its cleanup tail. A
completed result is copied before persistence and original response publication;
cancelled responses do not erase its business outcome. Duplicate dispatch calls
return existing facts without entering application code or acquiring a permit.
The finite service table retains failed actual-tail cleanup for its original
coordinator; it creates no retry worker or per-operation waiter.

The internal Session dispatcher binds either one volatile owner or one durable
owner for each trusted service tuple. A separately admitted Session provider task
performs durable registration, result reads, and actual-work settlement outside
the finite coordinator. Unary and execution notification work share that task's
bounded original indices; ordinary observations do not wait for business storage.
Original response joins retain an ephemeral result only when they joined the
live work. Later result reads require the original positive retention interval
and reuse the normal publisher's bounded copies and physical publication tails.
Management query and cancellation select the same registered owner and current
history permission, distinguishing proven absence from history below its floor.

Short durable service admission uses four original shared-scope vectors alongside
the Session's five protected output vectors. Cached, fenced store counts reserve
real record and active capacity before Session adoption without provider I/O under
construction gates. Original store, task and authorization references are acquired
at that point; only returned physical work/result/response tails permit reuse.
Unavailable capacity refuses construction or the new call without deleting old
history, changing an operation's contract, or borrowing another service's budget.

Execution admission includes streaming, checkpoint recovery and explicitly
retained content. The source and accepted intake capture bounded immutable RPC
recipes, derive the actual Session contract from the acquired material and use
the same aggregate admission before spend/acceptance. Public SDK composition,
complete functional tests and resource qualification remain unfinished. These
internal paths do not qualify a deployment's durability, anti-rollback or
filesystem guarantees.

Retained streaming content is saved only by an explicit application call on the
original executing work. The trusted local content definition and unary read
method must match the exact contract. Volatile archives belong to the original
execution record; SQLite content heads/items keep first-admission/commit origins,
fixed expiry, position/digest conflicts and bounded storage promises. Reads
require the complete original target and current authorization. Expiring payload
does not discard its conflict tombstone or claim replay of streaming items.

Prepared unary, streaming and Notify operations capture a query-only immutable
OperationReference before delivery. The reference codec binds the trusted local
domain and exact logical authority, caller and request. Query/cancel reuse the
management channel; retained unary results use the original general RPC path.
The separate SQLite reference store provides bounded create-or-compare, Load,
List and collection with fixed first-save retention. Saved references contain no
payload, credentials or Start authority. Prepared Notify exposes submission and
cleanup only and retains original bytes through the real publisher tail.

The internal Go WebSocket provider owns its Gorilla Dial/Upgrade configuration,
disables compression and pooling, requires binary messages and the registered
subprotocol, and rejects negotiated extensions before credential publication.
It bounds streaming message reads and HTTP/1.1 upgrade parsing, preserves
original policy errors, and separates logical close, physical cleanup and
retirement. Dial requires one policy-bound numeric endpoint; URL authority and
TLS verification retain the original hostname. Darwin/Linux connect and
descriptor handoff are synchronous, with two charged handles during duplication.
The owned socket deadline and close worker govern synchronous TLS; no detached
DNS, address race or cancellation observer is created. Other operating systems
reject Dial before taking the reservation. Trusted caller policy supplies DNS
preparation, endpoint, Origin, authentication and TLS trust decisions; provider/
runtime and host HTTP/TLS memory need their explicit qualification. For direct
acceptance, the provider snapshots the original Upgrade's host, port, path, subprotocol,
Origin, TLS 1.3 state and socket addresses. Signed candidate checks enforce those
observations, direct physical roles, local loopback isolation, binding mode and
the original provider's capacity for the complete signed maximum frame. Missing
original deployment policy rejects Session promotion. Policy calls are bounded
local work retained by the physical owner; Close cannot refund a pending call.
The native default supplies the original local TLS/pin checks; external
termination, consumer capabilities, application authentication and deployment
qualification still require independently trusted policy. Real-socket
tests on Darwin arm64 exercise both Noise profiles through dual READY and the
same Stream factory, then verify physical closure and aggregate refund. Linux
and Darwin amd64 are compile-checked; this is not runtime qualification there.
Handshake and rekey domain assembly validates and measures every input before
allocating one exact-capacity output. A second bounded pass writes the same
schema byte order without buffer growth. Immutable decoded labels belong to
the shared registry cache; payloads and projected map inputs retain their
original bytes and never alias that cache. Full crypto/provider charges remain
separate from this exact domain-buffer bound.

The internal Go DuplexBridge owns two distinct canonical endpoints in the same
Environment/root and clock: two Streams, or one Stream and one sealed native
TCP endpoint. Construction admits both Copy chunks, full endpoint
claims, two SDK pump/lifecycle workers, one supervisor and one bounded waiter.
The constructor's fixed deadline also expires an unstarted handle. Repeated
Start joins the original operation; canceled Wait returns metadata and leaves
the pumps running. Abort seals the original operation context before supervisor
scheduling, then uses the existing endpoint Reset and cleanup owners. The first
failure survives cancellation of the opposite direction.

Each EOF closes only its destination's sending direction. Both Copy and
CloseWrite completions precede concurrent Finish. Normal results require each
Flowersec destination's authenticated DRAINED fact; a native destination instead
reports only actual TCP CloseWrite completion after its writes have returned. Cleanup proceeds independently on the two
original endpoints. Incomplete results retain actual provider/task charges;
completion notifications continue cleanup without polling. Live progress has
no mutable chunk aliases. Final observations share one compact result owner and
the original frozen tails, which stay charged until application handoff; actual
late cleanup remains observable separately from the immutable handed-off result.
If actual pump I/O still owns a chunk at the original cleanup deadline, Wait
returns incomplete metadata without a mutable payload alias. The supervisor
continues observing the same pumps and publishes their stable tails only after
actual exit. Done and cleanup completion include the admitted observer tail.

Native ownership lives in a shared private core and the bridge freezes that
identity; copying or replacing a caller's handle cannot create another owner or
redirect cleanup. Every native read and write checks the participating Session,
original lifetime and budget before invocation. Returned positive byte counts
are recorded even with an error or cancellation; overflow is rejected before
I/O, and the exact final unaccepted suffix stays in its original chunk. A native
source read error remains an error after cleanup. Destination failure wakes a
parked native read through the existing supervisor. Abort sets a past socket
deadline outside SDK locks; actual Close and native reference joins remain on
the admitted lifecycle workers. There is no per-call cancellation worker or
future socket timer, and ordinary application executor capacity is not used.

The internal Go native TCP factory owns a fixed numeric-address dialer with
explicit IPv4/IPv6 and multipath disabled. It exposes neither raw sockets nor
an arbitrary socket-adoption hook. Separate original reservations cover its
supervisor, provider invocation, bounded observer and native endpoint. Every
invocation and delivery checks the original context, finite deadline and both
resource scopes. Observer cancellation does not cancel the connection attempt.
The provider uses a noncancelable native dial to avoid unjoined runtime context
callbacks: logical timeout seals delivery, reports incomplete cleanup and keeps
the full original provider/socket allowance until the real invocation and late
close return. The worker closes undelivered candidates; cleanup time starts at
the first failure. A successful handoff preserves the exact clock and endpoint
identity. Default socket linger is retained; native Close is not evidence of
remote receipt or disappearance of all kernel queues and OS memory.

This internal composition does not yet provide public SDK factories,
cross-clock composition or four-runtime qualification.

The internal Go ApplicationExecutor is one permanently claimed service per
actual resource root. Its ordinary try-now admission bounds running callbacks
and resident work across participating Environments, preserving a short-work
floor. Each callback keeps its original task and input reservations through all
defers and actual exit. Closing a borrower cannot replace or close the shared
service. An unstarted one-use permit reserves the original execution position
and complete task/input charge before OPEN acceptance; Start performs no new
resource admission. Explicit runtime allowances cover shared and per-task overhead. This
gate grants resources, not invocation authority; ready fairness, protected
services and full runtime qualification remain separate implementation work.

The internal Go StreamScope owns a full Stream and uses that ordinary executor
for its callback. The callback facade exposes bounded I/O, half-close, prepared
writes, Copy and scoped cursors; lifecycle authority remains private. Normal
return requires actual EOF delivery, settled callback responsibilities,
authenticated Finish and real cleanup. Unread input, dormant or undelivered
cursors and pending prepared work cannot become normal completion. Errors,
cancellation, deadlines and callback panics seal application entry and use the
original stream-local Reset, retaining stable accepted bytes and the first
cause. One supervisor and one lifecycle task retain their admitted resources
through late callback/provider/cursor exits. Cleanup timeout reports incomplete;
original completion notifications eventually finish cleanup without polling or
fabricating carrier closure. A bounded canceled Wait only stops observation;
its real reservation alias remains until the waiter exits. Completed results
detach the transport, clock and executor graph. Public four-SDK scope adapters
and physical runtime qualification remain outstanding.

The draft error subset allocates admission rejection, Session/Stream protocol
errors and OPEN rejection separately. ERROR target and optional retry hint
constraints execute against the registry. All allocated codes have generated
CBOR cases, including FSA4 rejection sentinels, OPEN rejection frontiers and
normal CLOSE/GOAWAY. Store uncertainty remains distinct from a proven rejection
of the durable admission record; no code grants replay or same-lease retry.

The stream-state helper is a reference transition model for pending
OPEN, explicit accepted/rejected outcome, monotonic credit, exact sequence and
offset checks, FIN, and immutable per-direction terminal tuples. It does not
authenticate OPEN digests, reserve Session resources, perform carrier I/O, or
qualify public SDK stream behavior.
Barrier events project externally established snapshot references and
irrevocable maintenance publication. Client cancellation requires a trusted
completed pre-INIT owner gate; a server reference can be cancelled only after
Session closure. Full submission freezing and rekey responsibility tracking
remain with the external rekey owner.
Trusted owner attribution, layered commit facts, public API projections and
actual runtime termination remain separate qualifications.

Native Read/Close result references use a separate named-field API schema.
Generated internal Go/Rust/Swift/TypeScript types preserve uint64 widths,
byte containers and optional fields. Contextual read checks use the original
method, actual transfer frontier and immutable cursor target; those inputs are
private validator context, not public fields or wire identifiers. The corpus
distinguishes target failures, committed terminals, canceled waits and empty
exact(0)/TakePrefix results. It cannot establish real host handoff, cursor
allocation or credit release. The allocated typed-error projection covers only
the current L0 error subset and grants no retry authority. Cleanup detail
snapshots report actual pending core/callback obligations independently of
direction facts; the generic lifecycle envelope and complete SDK error surface
remain unresolved. Native runtime consumption and adapter behavior remain
unqualified.

Application header references allocate closed base execution, transient,
observation and fixed query/management variants from one shared field registry.
Exact presence validation and original request matching reject response-owned
deadline, admission and limit fields. The ordinary execution request digest
binds the complete stable contract and immutable request inputs under its own
domain. Generated maximal headers and malformed variants establish structural
bounds only. Internal Go runtime codecs, streaming terminals and Resume owners
consume these schemas. Their real serial/channel ownership, authentication,
current routing, admission and dispatch require functional qualification;
generated reference consumers in the other SDKs are not runtime parity.

Reference text validation uses pinned Unicode 15.1 NFC and IDNA data with the
official normalization and nontransitional ToASCII conformance corpora. DNS
construction applies the additional IDNA2008 validity and context predicates;
wire validation checks the original ASCII A-labels without correcting them.
The host reference rejects numeric aliases and validates IPv4 and the unique
hexadecimal IPv6 spelling, including mapped addresses. The CBOR parser never
normalizes incoming security inputs. The OriginPolicy reference checks exact
serialized tuples and strictly orders complete canonical CBOR values. Its
scheme/default-port registry covers HTTP, HTTPS, WS, WSS and FTP. Custom schemes,
actual single-header admission, browser observations, route provider validation
and four-SDK text processing still require qualification.

TLS policy maps have strict CA/pin variants, signed verification requirements,
the registered DER certificate profile, bounded authorization windows and
digest-sorted pin sets. Actual DER validation, issuer authorization, browser
hash enforcement and original active-set rechecks remain implementation gates.

Leg, Route and Candidate references enforce access-class variants, physical
roles, fixed signed carrier tuples and unique namespace references. Nested legs
derive path kind from their containing signed map. Candidate-to-Route projection
and the route digest retain all selected descriptor fields; scheduling priority
and credential dependency closure remain in Candidate.

The issuer-only namespace-closure reference derives exact signed Candidate
references from the complete Artifact, both endpoint certificates and, for a
tunnel, both grants with their relay certificates. Parent and endpoint
dependencies apply to both endpoints and the tunnel relay; each grant and its
bound relay identity apply to that leg's endpoint and relay. Identical namespace
mappings merge role masks, while generation or capacity conflicts fail. Final
grants bind the complete Artifact, selected Route, contract and identity pair.
Application and relay audiences remain independent. Received references must
match the derived canonical list exactly; no received list is repaired.
The output owns only detached public bytes. This tooling must not be used to
give relays the complete Artifact or endpoints the other leg's private material.
Independent trust, signatures, expected deployment service/audience, original
issuance/activation authority, time/revocation checks, role-local verification,
actual subscription reservations, provider admission and SDK use remain open.

The Artifact reference covers all 28 required fields, complete nested policies,
candidate identity/priority ordering, local candidate exclusivity, time ordering
and authorized feature relations. SessionContract preserves full-width credit
and idle values and the profile-specific RPC/bootstrap field constraints.
SpendPolicy and ResumePolicy reject conflicting or incomplete variants. The
Artifact digest includes its signature; the signing projection excludes only
field 27. SessionContract has its own complete-map digest domain. Independent
structural witnesses cover the 57/23/3-byte contract/policy bounds and the exact
65536-byte Artifact boundary, with an otherwise legal 65537-byte negative.
Credential trust and runtime closure enforcement, actual selected features,
idle execution, once and application-history ownership, and admission capacity
remain separate gates.

The Hello/context reference binds both complete canonical hellos to the original
Artifact, selected Candidate/Route and caller's original attempt. It verifies
all server echoes and the exact known-feature intersection with the independently
compiled whole-route/policy mask, signed resume policy and native datagram
carrier requirements. Missing required features and changed binding choices
fail. Unknown optional offer bits and identity hints remain in the complete
hello transcript. TransportContext derives its fields from these originals;
tunnel/local exporter variants, wrong exporter length and received-context
substitutions fail without repair or fallback. Public outputs own their bytes.
The reference requires trusted context for actual provider/grant/policy
eligibility, the original common binding choice and the actual exporter result.
It does not derive that authority, call an exporter, validate TLS, enforce
single-flight ordering or reservations, authenticate FSB4/FSA4, or open READY.

The issuer credential-policy reference uses the complete validated original
namespace closure, including both grant-bound relay certificates. Every
credential selects its exact policy ID/revision; conflicting contents for the
same reference fail. The signed parent must be no wider in either staleness or
signer lifetime than every bound credential. A later grant cannot narrow those
requirements. Only immutable numeric minima leave this helper; it establishes
no trust mapping, freshness or admission authority. Each policy's independent
trusted namespace mapping, role-local access, activation inheritance and actual
signature/purpose validation remain external. Each namespace still needs its
own fixed publication-envelope check and authenticated State/Head/trust/time
deadline; a short current Head does not repair an incompatible signer envelope.

The admission composition reference checks FSB4 against the same original
Artifact and negotiated context, complete client certificate, explicit live or
pool source, original proof identities/deadlines and pool membership. Its
admission binding includes the complete FSB4 signature, certificate and proof.
Admitted FSA4 must match that binding, context and both complete identity
digests. Rejected FSA4 verifies only its prescribed echoes, exact zero sentinels
and certificate context; it needs no valid request proof and establishes no
admitted identity. Rejection issuer/trust, purpose, signatures, time/revocation
and actual source authorization remain independent prerequisites. Returned
epoch and opaque reservation key are client observations; the server's original
CAS/fencing/start guard, immutable nonce, real reservations, Noise and dual-READY
gates remain unimplemented by this reference. All returned bytes own storage.

PoolSelectionSet references are generated from the full signed Artifact and its
original candidate indices. The reference rejects reordered, duplicated and
nonmember indices, recomputes each complete Route, and binds the same map under
distinct candidate-set and route-set domains. Received PoolSelectionRef and
FSB4 proof/winner projections must match recomputation under the explicit pool
source context. Standalone set decoding does not prove membership or authority.
The generated set corpus includes 1, 2 and 16 candidates (94, 150 and 934 bytes),
including distinct candidates sharing an endpoint. Maximal structural references
and the unchanged 17-field activation proof occupy 533 and 1352 bytes. Atomic
ParentWinner/relay-leg claims, complete commit-confirmation reads, original
attempt budgets and trusted authority resolution remain runtime obligations.

The complete Grant reference preserves distinct parent and grant namespaces,
typed byte/mapping limits, ordered endpoint identities and leg references,
original Session deadlines and the embedded Route digest. Its signature and
digest each exclude only field 19 and use separate domains. Endpoint HELLO binds
the complete signed certificate digest, tenant and logical role to its Grant.
Current maximal structural vectors pin the derived 9302-byte Grant bound and
10346-byte endpoint HELLO bound, including a complete 980-byte P-256 certificate.
These are encoding bounds. Original issuance/proof membership, trust, expected
audiences, two-sided owner/challenge and claim-time capacity remain open.

The TopUp reference covers the fixed request, owner-fence proof, entry,
response and Ack maps. Request digests exclude binding generation and proof;
response digests exclude the response digest field without a zero placeholder;
material digests hash raw material bytes. `server_committed` and `applied` are
structurally true-only, gap authorization controls retirement-field presence,
and owner-fence proof time is ordered. Pending/Applied recovery, same-key
identity possession, durable CAS and request-dependent material limits remain
runtime qualifications.

The domain registry supplies exact label bytes, typed ordered inputs and
signature/MAC projections to all four generated SDK registries. Its separate
corpus verifies SHA-256, HMAC, single-block HKDF-Expand and HKDF-Extract results,
and records signing inputs and final TLS/WT exporter parameters. It does not
produce Ed25519 qualification or live exporter results. Explicitly deferred
domains still prevent schema freeze.

Retirement references include the complete-batch digest input and both
proposer roles under both crypto profiles. Structural witnesses pin the
9233-byte batch and 48-byte ACK bounds, including maximum uint64 batch sequence
and 1024 reliable scope IDs. These widths do not establish authorized ordinals,
terminal proof ownership, barrier fences, route capacity or physical cleanup.

Typed message references bind the complete opener-relative definition under
its independent digest domain. Ordinary metadata permits canonical text keys
only in its declared values map; fixed map keys remain integer field IDs.
The typed shell binds that definition digest and the original ordinary
application bytes. Its empty encoding is 88 bytes, and a 4006-byte application
encoding produces the exact 4096-byte combined limit. Larger ordinary metadata
can be valid alone and still fail composition. These are reference construction
and validation checks. Live registration, kind/definition matching, application
authorization, accepted publication, I/O ownership, real allocation/cleanup and
four-SDK consumption remain unqualified. Internal metadata parsing is separate
from the outer OPEN schema and does not create an accepted Stream.

ServiceContract references cover the six method variants, the complete stable
contract digest, the ordered application error catalog and content retention
policy. An otherwise legal 8193-byte contract fails the 8192-byte whole-map
limit. Stateless Offer verification recomputes the exact execution contract
digest and checks the original interval against an explicit positive uint64
policy bound. Trusted registration, actual authorization, application codecs,
execution admission, retention anchors and restart publication remain runtime
obligations. Opaque error-schema digests and content definitions are structural
fixtures; they cannot install codecs or qualify durable storage.

Contract query references validate original targets, complete known bodies,
full/unchanged variants and execution Offer membership. Generated query cases
retain those original inputs. Indexed response items match the exact request;
denied/unavailable items cannot carry contract or Offer data. Maximum structural
target, eight-target request, snapshot and eight-snapshot response encodings are
208, 1667, 8260 and 66083 bytes. Reference matching grants no current authority,
installation or admission, and does not implement the fixed query reservations,
network scheduling, source reads or immutable runtime baseline ownership.

RPC fragment references consume the sole framing and state registries. The
state model retains each direction's BEGIN high-water and only live request /
ReplySlot associations, including aborted input awaiting its small response.
Responses match the opposite direction and the original opaque request token;
terminal responses retire that association. Duplicate live STOP coalesces;
stale STOP with no live owner is ignored. The caller supplies an already
reserved share of the original Session request budget. The transition context
and explicit input-validation step model an external trusted validator; they
do not validate application header variants, execution digests or authority.
Generated state sequences and high-churn tests qualify these reference
transitions only, not production reservation, buffering, I/O or cleanup.

`node scripts/check-transport-v4-binding.mjs` checks repository references and
reports external artifact availability separately. `make
transport-v4-binding-check` is the external-input gate: both original files
must exist and match their bound SHA. The external evidence index must bind
seven independent reports covering protocol, cryptography, carriers, resources,
SDKs, ledgers and adversarial consistency in one review round. Every report must
sign the same unchanged architecture SHA. Missing, unbound, changed or incomplete
evidence fails that gate. Architecture signability does not qualify implementation.
The round, reviewer and lane recorded inside each report must match the index;
duplicating report content cannot supply another vote. The collecting agent must
verify the actual reviewer-tool origin before binding these declared identities.
`make transport-v4-schema-check` checks all generated content without writing
files and executes the CBOR and domain cases. Neither command freezes a schema
or grants implementation or release qualification.

`stability/transport_v4_traceability.json` maps design sections to source targets,
SDK entries and required test IDs. Existing registry references and vector IDs
are checked against the schema and manifest. Future source targets and required
test IDs record implementation obligations; they are not passing test evidence.

`stability/transport_v4_inventory.json` records source candidates requiring
replacement and the current release coordinates. Its generator scans tracked
and unignored source files; the inventory is checked with the architecture
contract. `node scripts/transport-v4-inventory.mjs --require-v4` additionally
rejects remaining source candidates or non-6.0.0 coordinates. Text scanning
does not replace the final review of production reachability.
