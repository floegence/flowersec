# Flowersec for TypeScript

`@floegence/flowersec-core` is the ESM-only Flowersec SDK for browsers and
Node.js. It gives both runtimes the same encrypted session, RPC, notification,
and byte-stream API through the root, `/browser`, `/node`, and `/proxy`
entrypoints.

## Install

```bash
npm install @floegence/flowersec-core
```

## Public API

- `@floegence/flowersec-core` exports the portable artifact, lease, session, stream, RPC, stream-metadata, and connection-controller API, plus profile-owned unreliable messages when negotiated.
- `@floegence/flowersec-core/browser` adds `connect(...)`, `createConnectionController(...)`, and their options.
- `@floegence/flowersec-core/node` adds `connect(...)`, `createConnectionController(...)`, direct-only `createAcceptor(...)`, opaque `createTunnelRuntime(...)`, `SessionHandlers`, `AcceptedSession`, `Issuer`, authorization record/request/response types, `authorizeRuntime(...)`, `authorizeTunnelRuntime(...)`, and `ProxyServer`.
- `@floegence/flowersec-core/proxy` adds the `Session`-based HTTP/WebSocket runtime, Service Worker and controller/app-window bridges, strict `proxy.runtime@2` validation, and `connectProxyBrowser(...)` composition.

The root type exports are:

- Artifact lifecycle: `Artifact`, closed `ArtifactError` parse failures, and `ArtifactLease`.
- Sessions: `Session`, `SessionTermination`, `RpcPeer`, `RpcResult<Response>`, `ByteStream`, `IncomingStream`, `StreamMetadata`, `OperationOptions`, and `StreamOpenOptions`. Create metadata with `createStreamMetadata(...)`; invalid values throw `StreamMetadataError` before opening a stream.
- Unreliable messages: `UnreliableMessageChannel`, `UnreliableMessageSendOptions`, and `UnreliableMessageSendResult`.
- JSON values: `JsonPrimitive`, `JsonValue`, and `JsonObject`.
- Errors: `ConnectErrorCode`, `SessionErrorCode`, and structured `RetryDisposition`.
- Connection lifecycle: `ArtifactSource`, `ArtifactSourceResult`, `ConnectionController`, `ConnectionState`, `ConnectionSnapshot`, `ConnectionControllerFailure`, `ConnectionControllerError`, and `RetryDisposition`.

Retry ownership belongs to `ConnectionController`; applications do not classify error text or run a parallel retry scheduler. Public failures remain redacted and reveal no carrier, candidate, URL, credential, stage, key, or diagnostic details.

`RpcResult<Response>` is a discriminated union. `RpcPeer.call(...)` requires a decoder for successful payloads, so the typed success value has passed application validation before it is returned. Check `result.ok` before reading either the typed success `payload` or bounded application `error`; a result cannot contain both. RPC call and notify accept only `JsonValue` payloads and reject values that cannot be represented on the wire before sending. TypeScript `RpcPeer.onNotify(typeId, decoder, handler)` receives peer outbound notifications through the local Session's inbound reserved RPC stream. A notification reaches the handler only after its decoder succeeds; decoder and handler failures are isolated from RPC serving.

When connector options omit a connection timeout, browser and Node.js connectors use the shared ten-second default.

### One-shot Node client

```ts
import { RPCHandlers, connect } from "@floegence/flowersec-core/node";

const rpcHandlers = new RPCHandlers();
rpcHandlers.handleRPC(7, async (payload) => ({ payload }));
rpcHandlers.handleNotification(8, (payload) => onNotice(payload));
const session = await connect(lease, {
  origin: "https://app.example",
  rpcHandlers,
});
```

### Long-lived Node client

```ts
import { RPCHandlers, createConnectionController } from "@floegence/flowersec-core/node";

const rpcHandlers = new RPCHandlers();
rpcHandlers.handleRPC(7, async (payload) => ({ payload }));
const controller = createConnectionController(source, {
  origin: "https://app.example",
  rpcHandlers,
});
controller.start();
const session = await controller.waitForSession();
```

The immutable callback definition applies to every generation, while each
Session gets a fresh router. Terminated Session work is never replayed.

### Application streams on any Session

```ts
import { StreamHandlers } from "@floegence/flowersec-core";

const streamHandlers = new StreamHandlers({ maxConcurrentStreams: 32 });
streamHandlers.handleStream("files/read", async (incoming) => serveFile(incoming));
await streamHandlers.serve(session);
```

The portable root, browser, and Node entrypoints share this dispatcher. The
sealed registrar used by Node `ProxyServer.register(...)` is exported only from
the Node entrypoint.

For the complete durable `ArtifactLease` spend workflow, see the
[TypeScript cookbook](../examples/ts/README.md). Node raw-QUIC-only artifacts
may omit `origin`; providing an absolute HTTP(S) origin enables WebSocket
candidates. Secure raw QUIC still requires an explicit `tls.ca` trust root.

### Accepted Node server Session

```ts
import { SessionHandlers, createAcceptor } from "@floegence/flowersec-core/node";

const handlers = new SessionHandlers({ maxConcurrentStreams: 32 });
handlers.handleRPC(7, async (payload) => ({ payload }));
handlers.handleNotification(8, (payload) => onNotice(payload));
handlers.handleStream("files/read", async (incoming) => serveFile(incoming));
const acceptor = await createAcceptor({
  listeners,
  maxInboundStreams: 32,
  authorize,
  resolveHandlers: () => handlers,
});
const accepted = await acceptor.accept();
await accepted.serve();
```

`RPCHandlers` is available only from the Node entrypoint and cannot register
application streams. `SessionHandlers` is accepted-server-only.

## Connection Lifecycle

The Browser and Node `connect(...)` operations are one-shot and never reconnect. Long-lived applications can create the runtime-specific `ConnectionController` with a refreshable `ArtifactSource`. Every attempt must return a fresh `ArtifactLease`; a one-time artifact or lease is not a controller source.

The controller has one scheduler and one in-flight attempt. Its states are `idle`, `connecting`, `connected`, `waiting`, `failed`, and `closed`; immutable snapshots expose `ConnectionSnapshot.retryDisposition` while the corresponding retry decision applies and clear it before a new attempt, after connection, and on close. Call `start()` once, observe snapshots with `subscribe(...)`, await an established session with `waitForSession(...)`, and use `retryNow()` only to wake a `waiting` controller. `close()` cancels acquisition, connection, and waiting before closing the current session.

`StreamHandlers` and Node `SessionHandlers` accept application stream kinds containing 1 through 128 canonical UTF-8 bytes, reject leading or trailing Unicode whitespace, controls, and unassigned scalars, and reserve `flowersec.rpc.v2` for Flowersec RPC. Successful handlers half-close their stream. A rejected handler Promise resets only that stream; the accept loop and unrelated streams continue.

Reliable streams apply bounded per-stream receive backpressure instead of buffering application data without limit. A slow consumer pauses carrier progress until reads release capacity; records retain carrier order, so a rekey behind backpressured DATA completes after the consumer resumes. `closeWrite()` sends the graceful FIN and keeps reads available. `reset()` and `close()` abort both directions. If a write is canceled or fails after its wire commit may have started, only that stream becomes terminal and cannot be reused.

Source failures return a structured `terminal`, `retryable`, or `retry_after` disposition. Thrown or malformed source failures are terminal. Retry delay is deterministic exponential backoff from 250 ms, doubling to a 30-second maximum with no jitter; `retry_after` is never attempted before its specified Unix-millisecond boundary. Attempts are unlimited unless `maximumAttempts` is explicitly set.

A newly established session replaces `currentSession` atomically. The controller never migrates or replays streams, RPC calls, or writes from a terminated session; callers start new application operations on the new session.

A negotiated `Session.unreliableMessages` channel sends defensively copied `Uint8Array` values and returns `accepted`, `dropped_expired`, `dropped_budget`, or `dropped_carrier`. `receive(...)` also returns a fresh `Uint8Array`. Invalid payloads, unavailable channels, cancellation, closure, and internal failures remain redacted public operation errors.

## Supported Connections

Browsers support WebSocket. Browser WebTransport is capability-dependent on
the browser's WebTransport API and is an optional browser adapter, not a
required native-server carrier. Through
`/node`, Node.js supports WebSocket and raw QUIC client connections, direct
server sessions, and opaque `TunnelRuntime` relay legs. Raw QUIC uses the
Flowersec-owned optional native addon wrapper and one of its supported
prebuilt platform packages; it never loads from the browser entrypoint. The
wrapper selects the matching optional package for macOS arm64/x64 or Linux
arm64/x64 glibc. Windows and musl packages are not published. The same Node entrypoint provides the
control plane and `ProxyServer`, and the relay never terminates an E2EE
Session. WebTransport is an optional adapter profile and the Node.js runtime
does not currently expose a production adapter.
The `/proxy` entrypoint adds browser bridges for applications that need to keep
the session behind a Service Worker or another window.

## Opaque Boundaries

`Artifact` is an opaque handle. Applications cannot inspect its connection data or serialize it back to protocol JSON. `ArtifactLease` exposes no spend operation; only the connector may invoke the durable callback. `Session` exposes RPC, stream operations, liveness, rekeying, `waitTermination()`, and closure without revealing the selected transport or peer endpoint identity. Public streams expose their kind and terminal state, but no protocol stream identifier.

`ConnectError` and `SessionError` expose only a closed `code`. They do not retain raw causes, credentials, URLs, candidate diagnostics, transport objects, peer details, or internal routing and handshake state.

Connection negotiation and cryptographic state are not package exports.

Admission rejection reasons are server-authorized bounded protocol tokens. Clients validate their wire form without carrying a deployment-specific reason registry; the public error boundary remains closed and redacted.

The proxy entrypoint accepts an opaque `ArtifactLease` or an already connected `Session`. Cross-window bridges require an exact allowed origin and may require a bounded capability nonce; runtime failures are mapped to closed status/code values before reaching Service Worker or Window messages.

## Connection Notes

Browser applications receive a ready `Session` from `connect(...)`. The browser
connector supports WSS, restricted plaintext loopback WebSocket direct
connections, and WebTransport when the browser exposes that API. WebTransport
uses browser-owned HTTP/3 streams and is not available in the Node entrypoint.

Chromium does not support a WebTransport pooling option; each carrier creates an independent native WebTransport connection.

Cold-connection diagnostics require every independent carrier to meet the declared deadline. A `dial_failed` result remains a test failure and is not hidden by pooling, retry, or timeout relaxation.

Node.js applications receive the same `Session` contract from `connect(...)`.
The Node connector supports WSS, restricted plaintext loopback WebSocket
direct connections, and raw QUIC through the optional native package. WebSocket
candidates require an absolute HTTP(S) `origin`; raw-QUIC-only artifacts may
omit it. Custom certificate authorities can be supplied through `tls.ca`, and
secure raw QUIC requires an explicit trust root.

The connectors choose an eligible connection path from the invitation. They do
not expose transport selectors, candidate lists, or native carrier objects to application code.

## Verify

```bash
npm run build
npm test
npm run verify:package
```

See the [API contract](../docs/API_CONTRACT.md), [Transport v2 architecture](../docs/TRANSPORT_V2_ARCHITECTURE.md), [threat model](../docs/THREAT_MODEL.md), and [error model](../docs/ERROR_MODEL.md).
