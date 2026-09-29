# Internal v4 pool control binding

The Go internal control adapter uses two transient unary application methods:
`41006` for TopUp and `41007` for Ack. Their bytes16 operation ID belongs to
the pool protocol; it is never an execution-header bytes32 operation ID.
Both contracts reserve a 524288-byte request and response limit. They declare
the configured nonzero application error code for the error envelope below.
Their exact contract digests are fixed when constructing `PoolService`.

The cold-start HTTPS adapter is independently configured with numeric routing,
TLS trust, and client authentication. It sends the original canonical request
as `POST <BaseURL>/pool/top-up` or `POST <BaseURL>/pool/ack`. The response has
`Content-Type: application/cbor` and a positive `Content-Length <= 524288`.
HTTP 200 carries success/replay, and HTTP 409 carries an application error.
Redirects, retries, cookies, ambient credentials, compression, DNS, and
connection pooling are disabled. The application must authenticate and
authorize the caller independently of the pool being replenished.

## pool-result-1

This is an application envelope, not an L0 map or a new signing domain.
Every array has the exact length shown. Integers are unsigned; byte strings
have the indicated widths; all CBOR uses the common canonical decoder.
The empty array encodes an absent variant; CBOR null is not accepted.
Unknown fields, trailing bytes, other scalar types, and indefinite lengths
are rejected. The complete envelope is at most 524288 bytes and 128 nodes.

```text
Reply = [code:text, response:bstr, terminal:[]|Terminal, fence:[]|Fence]

Terminal = [RequestFacts, state:text, binding_generation:uint,
            next_sequence:uint, retired_sequence:uint, highest_artifact:uint,
            retired_artifact:uint, permanent:bool, response:[]|ResponseFacts]

RequestFacts = [tenant:text, source:bstr16, operation:bstr16, pool:bstr32,
                identity:bstr32, request_digest:bstr32, original_generation:uint,
                deadline_ms:uint, desired_count:uint, max_item_bytes:uint]

ResponseFacts = [original_generation:uint, highest:uint, retired_through:uint,
                 gap:bool, response_digest:bstr32, entries:[Entry...]]

Entry = [sequence:uint, original_generation:uint, expiry_ms:uint,
         material_digest:bstr32, identity_digest:bstr32]

Fence = [tenant:text, source:bstr16, generation:uint]
```

`code` is the complete common `TopUpWireResult` enum. Success/replay has no
terminal or fence. A successful TopUp carries the complete original canonical
`TopUpResponse` as an opaque byte string, without re-encoding; a successful Ack
carries an empty response. Its original request/digest/material binding is
verified by the source before installation. An error has an empty response
and at most one terminal or permanent source fence.

Terminal state is `terminal` or `retired`. Its code must support the common
`write_action=terminal` projection. The receipt preserves original generation,
sequence frontiers, and whether a response was ever committed. Entries number
1–4 and match the original desired count. The decoder recomputes the canonical
original request digest. It never invents response or per-operation history
from a source fence. A fence is allowed only for `source_reset_required`.
`permission_denied` always has neither receipt nor material.

`PoolResultDecoder` is installed only on an independently authenticated control
transport authorized for the configured source. Its configuration fixes the
tenant, source incarnation, exact client SQLite identity, and current local
permission gate. CBOR parsing alone supplies no authentication. Terminal/fence
evidence is bound to those configured facts, checked again by the client
journal at the durable boundary, and explicitly released by its original
exchange owner. One outstanding receipt occupies the decoder; Close fences
future use and retains backing until release. Released aliases cannot affect
a subsequent receipt and retain no source/store/key/dependency graph.

## Server transaction ordering

Critical source changes also require the authenticated `TopUpAuditAccess` actor.
Their bounded security record commits in the same SQLite transaction as the
source state and response. See [Control audit](CONTROL_AUDIT_V4.md) for independent
read permissions, reserved safety capacity, export and retention behavior.

`PoolService` first authenticates source access through the trusted adapter's
finite local `TopUpAccess`. For RPC, the original authenticated SessionPlan
places this gate in `UnaryRequest.ApplicationContext`; payload bytes cannot
provide it. The service checks the exact registered contract digest and
transient method before dispatch.

TopUp calls `SQLiteTopUpServer.Prepare`, invokes the issuer outside store and
service locks, then calls `Commit` on the entire issuer-validated batch before
returning success. A replay uses the durable original bytes. An explicit issuer
denial must pass `Deny` and its transaction before it can become terminal;
ordinary issuer, transport, cancellation, and ambiguous commit errors do not
become terminal evidence. Ack uses retained request/response history and does
not parse or reacquire material. Retirement preserves the bounded terminal
summary, and an independently confirmed permanent source fence has a separate
receipt even when the request never reached the server. Permission is checked
again before exposing results; failed permission hides source history.

The service has one admitted invocation and fixed response backing. It joins
the actual issuer, store, and writer tail before clearing buffers or returning
its dependency borrow. Close cancels its operation without closing shared
dependencies. Deployments provide the independent source-fence authority,
issuer, and their qualified resource reservations; these interfaces are not
evidence of a deployment's provider qualification.

## pool-material-1

Each TopUp entry's opaque material is a canonical CBOR array of four byte
strings: the original signed Artifact, ActivationAuthorization, client
IdentityCertificate, and server IdentityCertificate, in that order. The
complete array is at most 65536 bytes. TopUp also applies its original
`max_item_bytes` bound to the encoded material field, including its CBOR prefix.

The material decoder uses independently installed namespace trust and verifies
the full lease/activation/identity binding before transferring it to the pool.
Each returned lease has a complete independent reservation. Closing the
decoder cannot destroy transferred leases. The bundle supplies no key locator
or authority to trust enclosed signing keys.
