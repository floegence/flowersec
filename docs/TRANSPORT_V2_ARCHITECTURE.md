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

## Carrier Profiles

The required native server profile has 18 runtime-role-carrier tuples and 24
path-specific units. Conformance is counted independently as 18 direct
client/server cells and 18 pairwise tunnel topologies.

WebSocket and raw QUIC are the required server carriers. Go, Rust, and Node.js
implement both for client, direct-server, and opaque tunnel-runtime roles.
WebTransport is an optional adapter profile. The connector races only the exact
supported candidates authorized by an artifact and does not interpret registry
order as preference.

A profile decides only whether a runtime exposes a carrier adapter. It never
changes Flowersec application wire semantics. Runtimes that support the same
carrier share Artifact admission, FSH2 handshake and record protection, RPC,
notification, stream metadata and termination, datagram framing, rekey,
liveness, authenticated close, cancellation, and cleanup behavior. Required
carrier conformance therefore uses every Go/Rust/Node client-server pairing,
not a language-private self-test or a one-way reference peer.

Performance and interoperability runners execute only registered supported
cells. Native runtimes can race WSS against raw QUIC, while browsers can race
WSS against browser-native WebTransport. Go supports direct WebTransport. Rust
and Node.js do not advertise a production WebTransport adapter.

| Carrier | Multiplexing | Required behavior |
|---|---|---|
| WebSocket | Hop-by-hop Yamux | The endpoint or tunnel terminates Yamux and exposes bounded carrier streams. |
| Raw QUIC | One native bidirectional stream per logical stream | Yamux imports and construction are forbidden. |
| WebTransport | One native bidirectional stream per logical stream | Yamux imports and construction are forbidden. HTTP/3 protocol streams are not Flowersec application streams. |

The tunnel runtime terminates only hop-local carrier multiplexing. It never
receives a Session contract or E2EE key and never terminates application
encryption. WebSocket and raw QUIC legs bridge opaque per-stream ciphertext
through the same carrier contract; the two endpoint runtimes perform the
application handshake across that bridge.

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
`MaxIncomingStreams`. A WebTransport adapter reports exactly `N + 2`
Flowersec-visible streams and never exposes HTTP/3 infrastructure streams as
application capacity. Its upstream implementation owns the corresponding
HTTP/3 stream accounting.

Every carrier session reports that exact physical capacity. Go uses
`MaxIncomingStreams()`, TypeScript and Swift use
`inboundBidirectionalStreamCapacity`, and Rust uses
`inbound_bidirectional_stream_capacity()`. Session establishment validates the
reported value before opening or accepting the lifetime control stream and
before writing FSC2/FSH2. Native TypeScript admission validates it before FSB2
credential bytes. `N = 1` therefore requires exactly three Flowersec-visible
physical bidirectional streams in every SDK.

Ordinary protocol acceptance and the three Chromium smoke topologies run on the
local development host. Privileged kernel diagnostics and performance workloads
use the single-host runner. Every layer is judged by assertions and process exit
status: success retains no output, while failure retains only a bounded
first-failure diagnostic.

Required performance is Go-owned. It measures the production Go runtime's connection and stream control-plane capacity, connect and liveness latency, cleanup, and resource growth; it is not multi-language performance parity and does not represent application business throughput. Six required capacity IDs cover direct WSS/raw QUIC and the WW/QQ/WQ/QW native tunnel topologies. They freeze 1,000 concurrent sessions, a 30-second ramp, 60-second hold, 30-second cleanup, 120-second watchdog, and RSS, CPU, file-descriptor, goroutine, and task ceilings. Each case counts attempted, succeeded, and failed sessions; proves a unique active peak of exactly 1,000 with no hold disconnect; records ramp/hold/cleanup resource samples; and finishes with zero watchdogs and zero residual sessions.

`performance/throughput/{wss,raw-quic}` separately measures production encrypted stream payload transfer with a fixed 64 KiB payload, four concurrent streams, three five-second samples, bytes per second, and p50/p95 acknowledgement latency. Static minimum throughput and maximum p95 budgets decide each sample. No historical baseline, confidence interval, or generated performance evidence is used.

Optional Go/Chromium WebTransport capacity and soak run only in the explicit `performance-optional` suite. The three browser stream-capacity cases prove 100 production sessions with 128 simultaneously live bidirectional streams per session. They use a 60-second ramp and a dedicated 32,768 aggregate process-tree descriptor ceiling plus a 240 CPU-second aggregate ceiling. Those ceilings preserve measured headroom over the Chromium calibration; the 1,000-session browser cases remain at 12,288 descriptors and required non-browser capacity cases remain at 8,192. Missing optional capability fails that selected profile's preflight; it is neither a required performance failure nor a skipped GREEN.

Linux diagnostics separate three boundaries. `diagnostic/kernel/*` proves netns, tc, eBPF schedules, counters, topology cleanup, and socket traversal. `diagnostic/weaknet/*` is a local userspace Flowersec fault smoke. `diagnostic/flowersec-weaknet/*` runs production WSS/raw QUIC Sessions and representative opaque tunnel topologies inside the kernel fault lab, with independent IDs for delay/jitter, periodic and burst loss, outage behavior, routed PMTU discovery from 1500-byte endpoint links to a 1280-byte bottleneck with large payloads, measured 5/1 Mbps shaping, reorder/duplicate, RPC, stream FIN, and cleanup. Raw QUIC direct weaknet additionally checks unreliable messages. Required diagnostics parse `go test -json`; skip, missing target execution, and `[no tests to run]` are RED. Fault-schedule tests compile, verifier-load, own, and clean their BPF object; topology and socket-traversal tests own their namespace and socket resources. Qlog and pcap are optional troubleshooting inputs and never decide GREEN.

## Go Native Adapters

Go 1.26.6 is the minimum security baseline and validates the following exact pair:

- `github.com/quic-go/quic-go v0.61.0`
- `github.com/quic-go/webtransport-go v0.12.0`

Both modules declare Go 1.25.0 and use the MIT license. The native adapters implement raw QUIC dial/listen, bidirectional streams, FIN, reset/stop, limits, configurable flow windows, TLS 1.3 and ALPN state, non-0-RTT establishment, application close, active path migration, NAT rebinding, and WebTransport dial/listen with bidirectional streams.

Go raw QUIC and WebTransport fail closed before network use: clients must provide a non-empty explicit root pool and cannot set `InsecureSkipVerify`; servers must provide a certificate and private key or a dynamic certificate callback. Hostname and chain verification remain mandatory during the TLS 1.3 handshake.

The WebTransport dependency owns its HTTP/3 wire version and conformance.
Browser support remains a separate runtime-adapter smoke contract and is not
inferred from native Go support.

Runtime tuples in `stability/transport_v2_contract.json` describe individual
carrier leg adapters, not deployment-profile claims. `NewWebTransportTunnelListener(...)`
is a low-level listener adapter only; it is not a supported endpoint-client
tunnel path or TunnelRuntime capability because the production opaque relay
does not provide complete paired WebTransport datagram forwarding.
`webtransport-server` remains unclaimed until its complete direct-server and
opaque-tunnel conformance set is registered. Required server parity never
infers WebTransport support from those lower-level tuples.

## Rust Native Adapter

Rust pins `quinn =0.11.11` with default features disabled and only `runtime-tokio` plus `rustls-ring` enabled. The raw QUIC adapter requires caller-provided certificates and keys; `rcgen` is forbidden as a runtime dependency so self-signed certificate generation cannot become an implicit path. Runtime capabilities are declared only by the complete adapter, connector, and acceptor path.

## Runtime Capability Decisions

- Go native: WebSocket and raw QUIC for direct and tunnel paths, plus
  WebTransport for direct paths. Go retains an optional low-level WebTransport
  tunnel listener adapter, but it is not a supported endpoint-client tunnel
  path or TunnelRuntime capability and does not claim the complete
  `webtransport-server` profile.
- TypeScript browser: WebSocket and WebTransport when their constructors are
  present; `detectBrowserRuntimeCapabilityV2(...)` removes unavailable APIs at
  runtime. Raw UDP is unavailable.
- TypeScript Node.js: WebSocket and raw QUIC direct/tunnel endpoint dialing,
  direct server acceptance, and opaque tunnel runtimes. Raw QUIC is provided
  by the Flowersec-owned optional native addon and platform packages.
  WebTransport is an optional profile and no production Node.js adapter is
  currently registered.
- Rust native: WebSocket and raw QUIC direct/tunnel endpoint dialing,
  runtime-owned direct listeners, and opaque tunnel listeners. WebTransport
  is an optional profile and no production Rust adapter is currently
  registered.
- Swift macOS and iOS: WebSocket direct client dialing and tunnel dialing for
  both session roles. Raw QUIC, WebTransport, DATAGRAM, and migration remain
  unavailable across the supported deployment targets.
- Swift Linux: every carrier is explicitly unsupported; the SDK does not infer
  runtime support from the availability of the Swift toolchain.

Transport capability descriptors use registered reason tokens. Server parity entries use stable English reasons and never claim an entrypoint or test ID when unsupported. Missing tuples are unsupported; they must not be inferred by combining other modes or roles.

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
