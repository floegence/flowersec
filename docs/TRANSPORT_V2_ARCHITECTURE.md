# Transport v2 Architecture

Transport v2 is the implemented architecture contract for adding raw QUIC and WebTransport without moving product or provider business logic into Flowersec. The machine-readable source of truth is `stability/transport_v2_contract.json`.

The implementation is split by explicit runtime capability tuples. A runtime may advertise only the carrier, network-mode, role, path, reliable-stream, DATAGRAM, and migration combinations backed by its production adapter. Missing tuples remain unsupported and must never be converted into an implicit WebSocket preference.

Local unit and smoke gates prove deterministic contract behavior. External workloads run natively on one capability-compatible Ubuntu host and are judged only by protocol assertions and process exit status. Release checks only repository state, versions, and tags before performing publication work.

The operational runner, required environment, and cleanup contract are documented in `docs/UBUNTU_TEST_RUNNER.md`.

## Boundaries

Flowersec owns transport-neutral secure sessions, transport adapters, protocol validation, resource limits, and interoperability contracts. It does not own environment selection, tenant routing, provider authorization, rollout cohorts, billing policy, or other business logic. Those decisions remain in the downstream control plane and applications.

The dependency direction is application API -> connection controller -> artifact source -> one-shot connector -> session engine -> carrier contract -> runtime adapter. All upper layers depend on a `CarrierSession` that opens and accepts bounded `CarrierStream` instances. RPC, proxy, handshake, liveness, and custom streams must not branch on WebSocket, raw QUIC, WebTransport, browser, Node.js, or a native library.

The session lifecycle is `opening -> open -> closing -> closed`. Candidate admission is `attempt -> ready -> winner -> admitted -> established -> terminated`: runtime adapters create and close carriers, the connector selects one winner, durable spend precedes the single credential write, and only the session engine performs the Flowersec handshake. Control-plane artifact issuance, direct/tunnel topology, carrier selection, and runtime resources remain separate ownership boundaries.

Admission rejection reasons are deployment-owned tokens. Servers validate them against their configured registry before emitting FSA2. SDK clients validate only the bounded token syntax and project every non-success response to the stable redacted admission failure; deployment reason registries are not connector configuration.

Internal errors follow the same ownership: runtime startup, native libraries,
TLS, and HTTP/3 are runtime errors; stream, DATAGRAM, reset, and carrier close
are carrier errors; Flowersec handshake, RPC, liveness, and protocol state are
session errors. Adapters map native failures into the first two classes and
must never manufacture a Flowersec handshake result.

## Equal Carriers

WebSocket, raw QUIC, and WebTransport are equal carrier candidates. The connector races the exact candidates authorized by an artifact and does not interpret registry order as preference.

The performance matrix keeps the same forced coverage for every adverse
network profile: direct WebSocket, direct raw QUIC, direct WebTransport,
WebTransport over a WSS tunnel, and WebTransport over a QUIC tunnel are all
separate cells. A native runtime can race WSS against raw QUIC, while a browser
runtime can race WSS against WebTransport. Capacity coverage
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
fields are `carrier`, `datagrams`, `migration`, `networkMode`, `path`,
`reliableStreams`, and `sessionRole`. Keys and arrays
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

Every QUIC-family logical stream maps to a native bidirectional stream and uses native FIN, RESET_STREAM, STOP_SENDING, stream limits, and stream/connection flow control. Native adapter contracts verify these mappings directly; qlog and pcap are optional diagnostic inputs and never part of ordinary acceptance.

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

The complete Transport v2 workload is executed by the single-host runner and is judged by protocol assertions and process exit status. Successful runs retain no output; a failure retains only the bounded first-failure diagnostic.

Capacity tests include 1,000 concurrent direct WSS, raw QUIC, and WebTransport sessions, plus 1,000 sessions for each WW, QQ, WQ, QW, WebTransport-over-WSS, and WebTransport-over-QUIC tunnel topology. The performance package freezes a 30-second ramp, 60-second hold, 30-second cleanup, 120-second watchdog, and RSS, CPU, file-descriptor, goroutine, and task ceilings. Each capacity case counts attempted, succeeded, and failed sessions; proves a unique active peak of exactly 1,000 with no hold disconnect; records ramp/hold/cleanup resource samples; and finishes with zero watchdogs and zero residual sessions.

The three browser stream-capacity cases additionally prove 100 production sessions with 128 simultaneously live bidirectional streams per session. They use a 60-second ramp and a dedicated 32,768 aggregate process-tree descriptor ceiling plus a 240 CPU-second aggregate ceiling. Those ceilings preserve measured headroom over the Chromium calibration; the 1,000-session browser cases remain at 12,288 descriptors and non-browser capacity cases remain at 8,192.

Linux system tests include netns/tc, eBPF counters, common-kernel behavior, real path migration, and IPv4/IPv6 PMTUD. The default diagnostic path asserts observed fault counters and protocol behavior directly. Qlog and pcap are optional troubleshooting inputs for an explicitly selected diagnostic; they are not required outputs and do not decide whether an ordinary run is GREEN. Capacity, soak, resource-growth, and A-B metrics remain confined to explicit performance targets.

## Go Native Adapters

Go 1.26.5 validated the following exact pair:

- `github.com/quic-go/quic-go v0.60.0`
- `github.com/quic-go/webtransport-go v0.11.1`

Both modules declare Go 1.25.0 and use the MIT license. The native adapters implement raw QUIC dial/listen, bidirectional streams, FIN, reset/stop, limits, configurable flow windows, TLS 1.3 and ALPN state, non-0-RTT establishment, application close, active path migration, NAT rebinding, and WebTransport dial/listen with bidirectional streams.

Go raw QUIC and WebTransport fail closed before network use: clients must provide a non-empty explicit root pool and cannot set `InsecureSkipVerify`; servers must provide a certificate and private key or a dynamic certificate callback. Hostname and chain verification remain mandatory during the TLS 1.3 handshake.

The WebTransport dependency implements draft-ietf-webtrans-http3-15. Browser support remains a separate runtime-adapter smoke contract and is not inferred from native Go support.

## Rust Native Adapter

Rust pins `quinn =0.11.11` with default features disabled and only `runtime-tokio` plus `rustls-ring` enabled. The raw QUIC adapter requires caller-provided certificates and keys; `rcgen` is forbidden as a runtime dependency so self-signed certificate generation cannot become an implicit path. Runtime capabilities are declared only by the complete adapter, connector, and acceptor path.

## Runtime Capability Decisions

- Go native: WebSocket, raw QUIC, and WebTransport.
- TypeScript browser: WebSocket and WebTransport when their constructors are
  present; `detectBrowserRuntimeCapabilityV2(...)` removes unavailable APIs at
  runtime. Raw UDP is unavailable.
- TypeScript Node.js: WebSocket and WebTransport direct client dialing and
  tunnel dialing for both session roles, plus direct WebTransport listening.
  WebTransport uses the pinned native libquiche adapter; raw QUIC remains
  unsupported.
- Rust native: raw QUIC direct client dialing and runtime-owned direct server
  listening, plus tunnel dialing for both session roles. The one-shot
  connection path owns opaque artifact acquisition, equal-candidate race, durable spend, and client
  admission; the runtime listener owns server admission. WebSocket and
  WebTransport remain unsupported.
- Swift macOS and iOS: WebSocket direct client dialing and tunnel dialing for
  both session roles. Raw QUIC, WebTransport, DATAGRAM, and migration remain
  unavailable across the supported deployment targets.
- Swift Linux: every carrier is explicitly unsupported; the SDK does not infer
  runtime support from the availability of the Swift toolchain.

Unsupported states carry registered reason tokens. Missing tuples are unsupported; they must not be inferred by combining other modes or roles.

## Artifact and Session Lifecycle

The signed artifact initiation expiry bounds transport establishment and is
checked before racing, before durable spend, and after spend. No expired path
writes FSB2. If expiry becomes visible while durable spend succeeds, the lease
remains spent because the durable transition cannot be rolled back.

Session termination is observable independently of the carrier. Go exposes
`WaitTermination(ctx)`; TypeScript exposes `Session.waitTermination()`; Rust exposes
`Session::wait_termination()`; Swift exposes `Session.waitTermination()`. Each returns
the same stable `SessionTermination` concept, while Go reports cancellation of the wait
separately through its context error. Establishing another session always
requires a distinct lease; the one-shot connector never retries with a
credential whose durable spend may have committed. A refreshable
`ArtifactSource` feeds the single `ConnectionController`, whose lifecycle is
`idle -> connecting -> connected -> waiting -> failed -> closed`. The
controller alone owns structured `terminal`, `retryable`, and absolute
`retry_after` decisions, deterministic backoff, cancellation, and current
session replacement. It never migrates streams or replays RPCs and writes.

Graceful carrier close is bounded by the caller's cleanup deadline. Go carrier
sessions implement `CloseWithErrorContext(...)` and must become locally unable
to open or write before that call returns, including when the context expires.
TypeScript and Swift carrier session and stream contracts additionally require
a synchronous, idempotent `abort` primitive. Abort starts forced teardown
without awaiting peer or transport cleanup and guarantees that pending and
future carrier operations settle. Session deadlines use that primitive after
graceful close has exhausted its budget, so no detached close task owns
Flowersec waiters or capacity indefinitely.
