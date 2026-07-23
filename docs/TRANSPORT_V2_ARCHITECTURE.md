# Transport v2 Architecture

Transport v2 is the signed and implemented architecture contract for adding raw QUIC and WebTransport without moving product or provider business logic into Flowersec. The machine-readable source of truth is `stability/transport_v2_contract.json`.

The implementation is test-driven and split by explicit runtime capability tuples. A runtime may advertise only the carrier, network-mode, role, and path combinations backed by its production adapter and conformance tests. Missing tuples remain unsupported and must never be converted into an implicit WebSocket preference.

Local unit and smoke gates prove deterministic contract behavior but do not count as release evidence. A release additionally requires a clean-final-SHA signed evidence report covering the registered real-browser, qlog, common-kernel weak-network, migration, capacity, and 15-run performance cases. `make release-check` fails closed when that report or its audited base SHA is absent.

The operational trust bootstrap, required environment, audited runner responsibilities, and exact release sequence are documented in `docs/TRANSPORT_V2_RELEASE_EVIDENCE.md`. The checked-in bootstrap-disabled signer and placeholder runner hashes intentionally prevent publication until a production runner policy is installed by a reviewed change.

## Boundaries

Flowersec owns transport-neutral secure sessions, transport adapters, protocol validation, resource limits, and interoperability contracts. It does not own environment selection, tenant routing, provider authorization, rollout cohorts, billing policy, or other business logic. Those decisions remain in the downstream control plane and applications.

All upper layers depend on a `CarrierSession` that opens and accepts bounded `CarrierStream` instances. RPC, proxy, and custom streams must not branch on WebSocket, raw QUIC, or WebTransport.

## Equal Carriers

WebSocket, raw QUIC, and WebTransport are equal carrier candidates. Adaptive selection has no permanent primary carrier and does not interpret registry order as preference.

The signed performance matrix keeps the same forced coverage for every adverse
network profile: direct WebSocket, direct raw QUIC, direct WebTransport,
WebTransport over a WSS tunnel, and WebTransport over a QUIC tunnel are all
separate cells. Native adaptive selection races WSS against raw QUIC, while
browser adaptive selection races WSS against WebTransport. Capacity evidence
also includes direct WebTransport and both WebTransport tunnel directions; a
mixed bridge is covered by the browser tunnel cells and the native mixed-leg
conformance cases.

| Carrier | Multiplexing | Required behavior |
|---|---|---|
| WebSocket | Hop-by-hop Yamux | The endpoint or tunnel terminates Yamux and exposes bounded carrier streams. |
| Raw QUIC | One native bidirectional stream per logical stream | Yamux imports and construction are forbidden. |
| WebTransport | One native bidirectional stream per logical stream | Yamux imports and construction are forbidden. HTTP/3 protocol streams are not Flowersec application streams. |

The tunnel terminates carrier multiplexing but never terminates end-to-end encryption. Mixed WebSocket/QUIC/WebTransport legs bridge opaque per-stream ciphertext through the same carrier contract.

## Fixed Paths and Profiles

Transport v2 uses the session profile `flowersec/2`. Carrier routing is path-specific:

| Path | Wire profile / raw QUIC ALPN | WebSocket path and subprotocol | WebTransport path |
|---|---|---|---|
| direct | `flowersec-direct/2` | `/flowersec/v2/direct`, `flowersec.direct.v2` | `/flowersec/webtransport/v2/direct` |
| tunnel | `flowersec-tunnel/2` | `/flowersec/v2/tunnel`, `flowersec.tunnel.v2` | `/flowersec/webtransport/v2/tunnel` |

Cross-path combinations are invalid. A runtime declares flat exact tuples of
carrier, network mode, session role, and one path; consumers must not form a
Cartesian product from independent capability lists.

Every SDK encodes the same strict descriptor shape:
`language`, `runtime`, `schemaVersion`, `tuples`, and `unsupported`. Tuple
fields are `carrier`, `networkMode`, `path`, and `sessionRole`. Keys and arrays
use the frozen canonical order in
`testdata/transport_v2/capability_vectors.json`; unknown fields, duplicate or
unsorted tuples, non-canonical JSON, and a carrier that is neither supported
nor explicitly unsupported are rejected. The acquisition digest is
`SHA-256("flowersec-v2-runtime-capability\0" || uint32_be(json_length) ||
canonical_json)`.

## Security Policy

Flowersec application 0-RTT is forbidden. Raw QUIC must use non-early dial and listen APIs. The Go WebTransport adapter must override the dependency's early-dial default with `quic.DialAddr`; server configuration keeps `Allow0RTT=false`.

Reliable Flowersec streams never use QUIC DATAGRAM frames. Raw QUIC and
WebTransport may expose the same carrier-neutral `UnreliableMessageChannel`
only when native DATAGRAM support and the `unreliable_messages_v1` FSH2
feature are both negotiated. The channel is unavailable on WebSocket and must
never fall back to a reliable stream. Its payloads use an independent,
directional, epoch-bound AEAD domain; admission, handshake, control, Artifact,
and credential values are not valid channel payload types.

Every QUIC-family logical stream maps to a native bidirectional stream and uses native FIN, RESET_STREAM, STOP_SENDING, stream limits, and stream/connection flow control. Structural tests use qlog and a Yamux factory spy because the public WebTransport stream wrapper does not expose its underlying QUIC stream ID.

The Flowersec carrier-facing inbound bidirectional-stream capacity is exactly
`N + 2`: one lifetime control stream, one persistent reserved RPC stream, and
the negotiated `N` application streams. WebSocket applies the same budget to
its hop-local Yamux session, and raw QUIC applies it directly to QUIC
`MaxIncomingStreams`. WebTransport still exposes exactly `N + 2` native
WebTransport streams to Flowersec and never uses Yamux, but its HTTP/3 server
configures the underlying QUIC `MaxIncomingStreams` to `N + 3` because the
long-lived extended CONNECT request consumes one additional HTTP/3
bidirectional stream. That HTTP/3 stream is infrastructure-only and is never
available as Flowersec application capacity.

Every carrier session reports that exact physical capacity. Go uses
`MaxIncomingStreams()`, TypeScript and Swift use
`inboundBidirectionalStreamCapacity`, and Rust uses
`inbound_bidirectional_stream_capacity()`. Session establishment validates the
reported value before opening or accepting the lifetime control stream and
before writing FSC2/FSH2. Native TypeScript admission validates it before FSB2
credential bytes. `N = 1` therefore requires exactly three Flowersec-visible
physical bidirectional streams in every SDK.

The complete release evidence is checked with
`make transport-v2-signed-evidence-check`. The command requires an explicit
report and audited base SHA and rejects dirty repositories, missing 15-run
performance cells, missing required case IDs, absent qlog/pcap/resource
artifacts, inconclusive thresholds, and artifact digest mismatches. Capacity
evidence includes 1,000 concurrent direct WSS, raw QUIC, and WebTransport
sessions, plus 1,000 sessions for each WW, QQ, WQ, QW, WebTransport-over-WSS,
and WebTransport-over-QUIC tunnel topology. The signed manifest freezes a
30-second ramp, 60-second hold, 30-second cleanup, 120-second watchdog, and
RSS, CPU, file-descriptor, goroutine, and task ceilings. Each capacity case
must report attempted, succeeded, and failed sessions; prove a unique active
peak of exactly 1,000 with no hold disconnect; record ramp/hold/cleanup
resource samples; and finish with zero watchdogs and zero residual sessions.
Linux system evidence includes netns/tc,
eBPF counters, common-kernel behavior, real path migration, and IPv4/IPv6 PMTUD.
Every performance phase records the exact profile ID, phase, manifest digest,
canonical effective network JSON, its SHA-256, and the audited tc/eBPF config
SHA-256. The checker recomputes these values from the frozen manifest and
rejects a configured-but-unobserved UDP queue overflow. Ratio samples use the
frozen `transport-ratio-v1` operand graph rather than report-supplied summary
fields. Each operand binds its exact cell, run, variant, profile, phase, kind,
field, and artifact digest, including clean revision, QUIC-to-WSS, adverse-to-
clean topology, adaptive-stage, and native interactive-to-idle comparisons.

Migration captures must show an ordered local `AddrPort` change on one UDP
remote path; a same-address source-port rebind is valid, while unrelated UDP
flows are not. The qlog old/new/remote paths must match that pcap 5-tuple and
carry the same connection ID. The path validation event must name the new
local and remote path, and the first RPC completion must follow validation.
Rebind and outage schedules are frozen in effective config and reproduced as
strictly monotonic raw trace events. The checker recomputes their counters and
durations from those events and requires config, metrics, trace, qlog, and pcap
evidence to identify the same connection where applicable.
QUIC PMTUD captures must show an oversized datagram followed by a constrained
datagram on the same connection ID and tuple. Kernel cases require an IPv4 or
IPv6 ICMP PTB whose quoted transport tuple is the oversized flow; the parser
accepts the standards-minimum quoted IP header plus eight transport bytes.
The PMTUD qlog must order packet-too-large, recovery metrics, and a successful
post-recovery RPC on that same connection ID.
WSS recovery cases apply the same quoted-tuple rule to TCP and bind the PTB
between monotonically increasing TCP_INFO observations for one socket tuple and
socket cookie. Runner trust is pinned to an exact kernel release and exact
effective tc/eBPF config digest, not a kernel-family prefix.
The checked-in `flowersec-release-linux-bootstrap-disabled` entry is a valid,
non-low-order Ed25519 public key whose private key was not retained. It keeps
verification fail-closed during bootstrap; enabling release evidence requires
an audited repository change that installs the production signer public key
and matching fixed runner policy.

## Signed Go Slice 0

Go 1.26.5 signed the following exact pair:

- `github.com/quic-go/quic-go v0.60.0`
- `github.com/quic-go/webtransport-go v0.11.1`

Both modules declare Go 1.25.0 and use the MIT license. The spike proved raw QUIC dial/listen, native bidirectional streams, FIN, reset/stop, limits, configurable flow windows, TLS 1.3 and ALPN state, non-0-RTT establishment, application close, active path migration, NAT rebinding, and WebTransport dial/listen with bidirectional streams.

Go raw QUIC and WebTransport fail closed before network use: clients must provide a non-empty explicit root pool and cannot set `InsecureSkipVerify`; servers must provide a certificate and private key or a dynamic certificate callback. Hostname and chain verification remain mandatory during the TLS 1.3 handshake.

The WebTransport dependency implements draft-ietf-webtrans-http3-15. Production readiness still requires the registered real-browser interoperability matrix; Slice 0 dependency compilation alone is not browser sign-off.

## Signed Rust Slice 0

Rust pins `quinn =0.11.11` with default features disabled and only `runtime-tokio` plus `rustls-ring` enabled. The retained raw QUIC adapter requires caller-provided certificates and keys; `rcgen` is forbidden as a runtime dependency so self-signed certificate generation cannot become an implicit path. This dependency slice does not advertise a production runtime capability tuple by itself.

## Runtime Capability Decisions

- Go native: WebSocket, raw QUIC, and WebTransport.
- TypeScript browser: WebSocket and WebTransport when their constructors are
  present; `detectBrowserRuntimeCapabilityV2(...)` removes unavailable APIs at
  runtime. Raw UDP is unavailable.
- TypeScript Node.js: no production Transport v2 carrier. The package has no
  committed v2 WebSocket admission/carrier adapter, and raw QUIC plus
  WebTransport remain unavailable until a production-grade runtime API passes
  the dependency gate.
- Rust native: no production Transport v2 carrier tuple. The raw QUIC adapter
  remains public and tested, but raw QUIC is registered as
  `rust_transport_v2_connector_not_committed` until complete ArtifactV2
  acquisition, equal-candidate race, durable-spend, and server admission paths
  are committed. Its carrier-neutral Yamux adapter likewise does not advertise
  WebSocket Transport v2.
- Swift Apple: portable Transport v2 protocol/session code only. No network carrier tuple is advertised until a production WebSocket admission/carrier adapter is committed; raw QUIC and WebTransport remain blocked by the Network.framework contract across supported deployment targets.

Unsupported states carry registered reason tokens. Missing tuples are unsupported; they must not be inferred by combining other modes or roles.

## Custom Tunnel Endpoint Sets

Custom tunnel discovery uses the versioned, business-neutral
`flowersec-tunnel-endpoint-set/2` contract implemented by Go `endpointsetv2`.
It binds one rendezvous group and tunnel endpoint instance to an exact,
canonically sorted listener tuple set. Every tuple names carrier, network mode,
tunnel path, accepted dialing-peer session role, wire profile, and either a dial
URL or a listen bind endpoint. The session role is independent of the network
acceptor role: one physical tunnel listener publishes distinct tuples when it
accepts both client-role and server-role peers. Listen tuples also carry a canonical public
`advertised_url`, so the control plane can issue a reachable candidate without
deriving public routing from a local bind address.

The codec rejects unknown or duplicate JSON fields, duplicate or unsorted
tuples, direct/tunnel cross-path values, non-canonical URLs and bind endpoints,
and carrier/profile mismatches. A registration is usable only while its
issued/expires freshness window is current and its issue time is no more than
`endpointsetv2.MaxFreshnessAgeSeconds` old, its listener audience is ready, and
its certificate readiness covers every dial or advertised URL hostname through
a canonically sorted verified-server-name set. Raw QUIC and WebTransport listen
tuples bind UDP; WebSocket listen tuples bind TCP. The schema and shared vectors
are frozen in `stability/transport_v2_contract.json` and
`testdata/transport_v2/endpoint_set_vectors.json`.

Requester intersection maps a listen tuple to the requester's dial network mode
without changing its session role. A role-specific tunnel endpoint therefore
cannot be issued to the opposite role, and an endpoint that accepts both roles
must register both tuples explicitly.

## Artifact and Session Lifecycle

The signed artifact initiation expiry bounds transport establishment and is
checked before racing, before durable spend, and after spend. No expired path
writes FSB2. If expiry becomes visible while durable spend succeeds, the lease
remains spent because the durable transition cannot be rolled back.

Session termination is observable independently of the carrier. Go exposes
`Termination()` and `WaitClosed(ctx)`; TypeScript exposes `termination` and
`waitClosed()`; Rust exposes `SessionV2::wait_closed()`; Swift exposes
`SessionV2.waitClosed()`. The TypeScript reconnect manager requires refreshable artifacts
for automatic reconnect, acquires a new lease for every attempt, and treats a
serialized one-time artifact as consumed across subsequent connect calls. Its
artifact acquisition context always carries the exact version policy, runtime
descriptor, and verified capability digest; a mismatch fails before invoking
the downstream source callback.

Graceful carrier close is bounded by the caller's cleanup deadline. Go carrier
sessions implement `CloseWithErrorContext(...)` and must become locally unable
to open or write before that call returns, including when the context expires.
TypeScript and Swift carrier session and stream contracts additionally require
a synchronous, idempotent `abort` primitive. Abort starts forced teardown
without awaiting peer or transport cleanup and guarantees that pending and
future carrier operations settle. Session deadlines use that primitive after
graceful close has exhausted its budget, so no detached close task owns
Flowersec waiters or capacity indefinitely.
