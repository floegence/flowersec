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

`RpcResult<Response>` is a discriminated union. `RpcPeer.call(...)` requires a decoder for successful payloads, so the typed success value has passed application validation before it is returned. Check `result.ok` before reading either the typed success `payload` or bounded application `error`; a result cannot contain both. RPC call and notify are portable across SDKs. TypeScript `RpcPeer.onNotify(...)` receives peer outbound notifications through the local Session's inbound reserved RPC stream.

When connector options omit a connection timeout, browser and Node.js connectors use the shared ten-second default.

## Connection Lifecycle

The Browser and Node `connect(...)` operations are one-shot and never reconnect. Long-lived applications can create the runtime-specific `ConnectionController` with a refreshable `ArtifactSource`. Every attempt must return a fresh `ArtifactLease`; a one-time artifact or lease is not a controller source.

The controller has one scheduler and one in-flight attempt. Its states are `idle`, `connecting`, `connected`, `waiting`, `failed`, and `closed`; immutable snapshots expose `ConnectionSnapshot.retryDisposition` while the corresponding retry decision applies and clear it before a new attempt, after connection, and on close. Call `start()` once, observe snapshots with `subscribe(...)`, await an established session with `waitForSession(...)`, and use `retryNow()` only to wake a `waiting` controller. `close()` cancels acquisition, connection, and waiting before closing the current session.

Node `SessionHandlers` accept application stream kinds whose UTF-8 encoding is 1 through 255 bytes and reserve `flowersec.rpc.v2` for Flowersec RPC. `AcceptedSession.serve(...)` half-closes successfully handled streams. A rejected handler Promise resets only that stream; the accept loop and unrelated streams continue.

Source failures return a structured `terminal`, `retryable`, or `retry_after` disposition. Thrown or malformed source failures are terminal. Retry delay is deterministic exponential backoff from 250 ms, doubling to a 30-second maximum with no jitter; `retry_after` is never attempted before its specified Unix-millisecond boundary. Attempts are unlimited unless `maximumAttempts` is explicitly set.

A newly established session replaces `currentSession` atomically. The controller never migrates or replays streams, RPC calls, or writes from a terminated session; callers start new application operations on the new session.

A negotiated `Session.unreliableMessages` channel sends defensively copied `Uint8Array` values and returns `accepted`, `dropped_expired`, `dropped_budget`, or `dropped_carrier`. `receive(...)` also returns a fresh `Uint8Array`. Invalid payloads, unavailable channels, cancellation, closure, and internal failures remain redacted public operation errors.

## Supported Connections

Browsers support WebSocket. Browser WebTransport is capability-dependent on
the browser's WebTransport API and is an optional browser adapter, not a
required native-server carrier. Through
`/node`, Node.js supports WebSocket and raw QUIC client connections, direct
server sessions, and opaque `TunnelRuntime` relay legs. Raw QUIC uses the
Flowersec-owned optional native addon and prebuilt platform package; it never
loads from the browser entrypoint. The same Node entrypoint provides the
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
direct connections, and raw QUIC through the optional native package. It
requires an absolute HTTP(S) `origin`; custom certificate authorities can be
supplied through `tls.ca`, and raw QUIC requires explicit trust roots.

The connectors choose an eligible connection path from the invitation. They do
not expose transport selectors, candidate lists, or native carrier objects to application code.

## Verify

```bash
npm run build
npm test
npm run verify:package
```

See the [API contract](../docs/API_CONTRACT.md), [Transport v2 architecture](../docs/TRANSPORT_V2_ARCHITECTURE.md), [threat model](../docs/THREAT_MODEL.md), and [error model](../docs/ERROR_MODEL.md).
