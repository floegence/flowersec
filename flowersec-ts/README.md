# Flowersec for TypeScript

`@floegence/flowersec-core` is the ESM-only Flowersec SDK for browsers and
Node.js. It provides encrypted sessions, RPC, notifications, reliable byte
streams, connection recovery, server runtimes, and browser proxy integration.

## Install

```bash
npm install @floegence/flowersec-core
```

Node.js 24.20.0 or newer is required.

## Entrypoints

- `@floegence/flowersec-core` exports the portable artifact, lease, Session,
  RPC, stream, metadata, error, and connection-controller contracts, plus the
  explicit v4 Environment, resource and result contracts.
- `@floegence/flowersec-core/browser` adds browser `connect(...)`,
  `createConnectionController(...)`, WSS, optional WebTransport, and the
  isolated private-loopback profile. `configureV4BrowserWSS(...)` adds the
  explicit v4 direct WSS client with a host-supplied IndexedDB pool adapter.
- `@floegence/flowersec-core/node` adds Node `connect(...)`,
  `createConnectionController(...)`, `createAcceptor(...)`,
  `createTunnelRuntime(...)`, `ProxyServer`, `SessionHandlers`, and
  `RPCHandlers`. `configureV4NodeWSS(...)` adds the explicit v4 direct WSS
  client with a durable SQLite pool adapter. The Node entrypoint also exposes
  `openV4SQLiteExecutionStore` for durable execution history and unary results;
  explicit reopen requires an independent host continuity proof.
- `@floegence/flowersec-core/proxy` provides the browser HTTP/WebSocket proxy
  runtime, Service Worker integration, and exact-origin window bridges.

## Transport v3 Client Sessions

Parse an opaque artifact, bind its durable spend callback, and connect:

```ts
import { createArtifactLease, parseArtifact } from "@floegence/flowersec-core";
import { connect } from "@floegence/flowersec-core/node";

const artifact = parseArtifact(serializedArtifact);
const lease = createArtifactLease(artifact, persistSpendExactlyOnce);
const session = await connect(lease, { origin: "https://app.example" });
```

`Artifact` hides credentials and candidate selection. `ArtifactLease` exposes no
public spend method. `Session` exposes RPC, streams, unreliable messages when
negotiated, liveness, rekeying, termination, and close without revealing its
carrier.

`StreamHandlers` serves bounded application handlers on any Session.
`ConnectionController` is the only reconnect scheduler and obtains a fresh
lease for each attempt. Work from a terminated Session is never migrated or
replayed.

## Node Servers and ProxyServer

`createAcceptor(...)` accepts direct application Sessions. `SessionHandlers`
binds accepted RPC, notification, and stream handlers before establishment.
`createTunnelRuntime(...)` pairs and forwards opaque relay legs without
terminating the end-to-end Session.

`ProxyServer` registers the bounded HTTP and WebSocket application protocol on
`StreamHandlers` or `SessionHandlers`. It enforces fixed upstream hosts,
origins, header and cookie policy, body/frame limits, timeouts, cancellation,
and a close barrier. The `/proxy` browser runtime uses the same application
wire through a Service Worker or exact-origin window bridge.

HTTP proxy responses preserve coded bytes and origin `Content-Encoding`.
The Service Worker decodes gzip, zlib deflate, and Brotli once for its synthetic
Fetch response; encoding chains are limited to four layers. Brotli uses the
bundled streaming WASM decoder. `maxDecodedBodyBytes` defaults to 64 MiB and
limits each decoding layer and the presented body. Origin representation
headers remain visible unless an explicit HTML transformation rewrites the
representation. The decoded byte limit does not bound all browser memory or CPU.

## Supported Connections

### Transport v3

Browsers support WSS and optional browser-owned WebTransport. Node.js supports
WSS and raw QUIC client, direct-server, and tunnel-runtime roles. Raw QUIC uses
the optional Flowersec native package for macOS or glibc Linux on arm64/x64.
Node.js does not expose WebTransport or an artifact issuer; use an application
control plane such as the Go control-plane package.

CA candidates use platform or configured private roots. Pin candidates verify
only the complete artifact-bound active pin set and never fall back to CA.
Public errors remain closed and redacted.

## Environment WSS connections and serving

Create an Environment with `createV4TransportEnvironment(...)`, install either
`configureV4NodeWSS(...)` or asynchronous `configureV4BrowserWSS(...)`, bootstrap
its credential namespace, then call `environment.connect(...)` with a registered
pool source or `environment.connectMaterial(...)` with verified pool material.
The client publishes a Session only after the actual durable once transaction,
authenticated HELLO/FSB/FSA exchange, Noise handshake and both READY messages.

Both clients implement direct WSS, explicit pool or live-authority activation,
transport/services/execution profiles, reliable streams, rekey and liveness
with X25519/ChaCha20 or P-256/AES-GCM. Node verifies TLS 1.3 and the signed CA or leaf-DER pin policy.
Browser WSS is CA-only and requires a trusted immutable deployment binding for
TLS 1.3, early-data refusal, HTTP/1.1 and exact Origin enforcement; it reports
`controlled_terminator`, never independent JavaScript TLS verification.

The optional browser IndexedDB adapter is an explicit host integration. It
requires actual strict-durability transactions and independent continuity
evidence outside the database/origin. Browser users are not asked to provision a
database. This SDK currently has no remote pool-consume service adapter. Both
local stores reject missing continuity and retain consumed leases across reopen;
uncertain commits cannot activate a connection through later readback.

Node servers use `createNodeWSSListener(...)`, `createHandlerPlan(...)`, and
`environment.serve(...)` from the normal Node entry. The listener owns bounded
TCP/TLS/HTTP admission. Serve captures five application callbacks, verifies
FSB before application authorization, reserves the Session graph before the
durable admission CAS, and publishes only after dual READY. Its
`drain`/`waitDrain`/`close`/`waitCleanup` lifecycle retains real native, Session,
lease and callback cleanup while borrowing the Environment.

See [TypeScript transport runtime](../docs/TYPESCRIPT_TRANSPORT_V4.md) for
configuration, supported providers and storage continuity. Schema and provider
qualification are tracked by the
[implementation binding](../docs/TRANSPORT_V4_BINDING.md).

## CLI

The package installs `flowersec-ts-cli`. Its client and server commands accept
only Transport v3 artifacts. The server requires a TLS certificate and private
key for its WebSocket listener.

## Verify

```bash
npm run build
npm test
npm run verify:package
```

See the [TypeScript cookbook](../examples/ts/README.md),
[API contract](../docs/API_CONTRACT.md),
[TypeScript Transport v4](../docs/TYPESCRIPT_TRANSPORT_V4.md),
[Transport v3 architecture](../docs/TRANSPORT_V3_ARCHITECTURE.md),
[wire contract](../docs/TRANSPORT_V3_WIRE.md), and
[error model](../docs/ERROR_MODEL.md).

### Connection retry status

While a connection controller is `waiting`, its snapshot and diagnostic include
`nextRetryAtUnixMilliseconds`, the scheduler-owned wall-clock estimate of the next
attempt. It accounts for both exponential backoff and any server `retry_after`
minimum. Hosts may display a countdown without duplicating the retry policy. The
field is absent outside `waiting`. `retryNow()` can skip backoff but cannot bypass
a server minimum; `close()` cancels the wait. Wall-clock corrections can change
the displayed estimate; the scheduler still enforces its monotonic backoff.

## Session-bound HTTP events

Request preparation supports browsers that expose `Body.blob()` without a `Request.body` stream. Both paths preserve the request bytes, headers, body limit and cancellation boundary before opening a carrier stream.

Use `createProxyRuntime({ session, externalOrigin }).fetch("/api/events", { headers: { Accept: "text/event-stream" }, signal })` to read a standard streaming `Response` over the existing session. Consume or cancel the body and dispose the runtime when its session is replaced. The runtime never retries requests. It shares policy, framing, cancellation and admission with the browser bridges. The Go and Node proxy servers support negotiated SSE with bounded backpressure and activity deadlines; ordinary requests retain finite response limits. Default HTTP admission is 24 requests, including at most 16 event streams. Rejected event subscriptions report `resource_exhausted` immediately.
