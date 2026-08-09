# Flowersec for TypeScript

`@floegence/flowersec-core` is the ESM-only Flowersec v2 SDK for browsers and Node.js. Its public package surface is limited to the root, `/browser`, `/node`, and `/proxy` entrypoints.

Flowersec 2.3.5 is the published TypeScript SDK release.

## Install

```bash
npm install @floegence/flowersec-core@2.3.5
```

## Public API

- `@floegence/flowersec-core` exports the portable artifact, lease, session, stream, RPC, stream-metadata, and connection-controller API, plus profile-owned unreliable messages when negotiated.
- `@floegence/flowersec-core/browser` adds `connect(...)`, `createConnectionController(...)`, and their options.
- `@floegence/flowersec-core/node` adds `connect(...)`, `createConnectionController(...)`, `createAcceptor(...)`, `SessionHandlers`, and `AcceptedSession`.
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

The controller has one scheduler and one in-flight attempt. Its states are `idle`, `connecting`, `connected`, `waiting`, `failed`, and `closed`; snapshots expose the current structured `retryDisposition` while waiting. Call `start()` once, observe immutable snapshots with `subscribe(...)`, await an established session with `waitForSession(...)`, and use `retryNow()` only to wake a `waiting` controller. `close()` cancels acquisition, connection, and waiting before closing the current session.

Source failures return a structured `terminal`, `retryable`, or `retry_after` disposition. Thrown or malformed source failures are terminal. Retry delay is deterministic exponential backoff from 250 ms, doubling to a 30-second maximum with no jitter; `retry_after` is never attempted before its specified Unix-millisecond boundary. Attempts are unlimited unless `maximumAttempts` is explicitly set.

A newly established session replaces `currentSession` atomically. The controller never migrates or replays streams, RPC calls, or writes from a terminated session; callers start new application operations on the new session.

A negotiated `Session.unreliableMessages` channel sends defensively copied `Uint8Array` values and returns `accepted`, `dropped_expired`, `dropped_budget`, or `dropped_carrier`. `receive(...)` also returns a fresh `Uint8Array`. Invalid payloads, unavailable channels, cancellation, closure, and internal failures remain redacted public operation errors.

## Capability Layers

The portable core is the same application model used by every Flowersec SDK:
opaque artifact parsing, a durable single-use lease, one-shot connection,
carrier-neutral sessions, RPC, reliable streams, redacted public errors, and
the optional single-owner `ConnectionController`. Callers should not compare
raw TypeScript error-code strings with other SDKs.

Portable core, connection control, session/RPC/stream lifecycle, accepted-session
workflows, and published consumer workflows align across every applicable SDK.
Platform-limited profiles are unsupported only with an explicit alternative
boundary and executable test ID in `stability/language_capabilities.json`.

The TypeScript SDK profile is split by entrypoint: browsers own WebSocket and
WebTransport dialing, while Node.js owns WebSocket and WebTransport dialing through
the native `@fails-components/webtransport` adapter. Its language convenience
includes static generic RPC result typing, notification subscriptions, and
proxy composition. These conveniences do not expand the
portable core required from Go, Swift, or Rust.

## Opaque Boundaries

`Artifact` is an opaque handle. Applications cannot inspect its connection data or serialize it back to protocol JSON. `ArtifactLease` exposes no spend operation; only the connector may invoke the durable callback. `Session` exposes RPC, stream operations, liveness, rekeying, `waitTermination()`, and closure without revealing the selected transport or peer endpoint identity. Public streams expose their kind and terminal state, but no protocol stream identifier.

`ConnectError` and `SessionError` expose only a closed `code`. They do not retain raw causes, credentials, URLs, candidate diagnostics, transport objects, peer details, or internal routing and handshake state.

Candidate lists, runtime capability descriptors, transport factories, admission state, Yamux, wire messages, cryptographic state, keys, and spend-ledger internals are not package exports.

Admission rejection reasons are server-authorized bounded protocol tokens. Clients validate their wire form without carrying a deployment-specific reason registry; the public error boundary remains closed and redacted.

The proxy entrypoint accepts an opaque `ArtifactLease` or an already connected `Session`. Its public runtime never exposes the selected carrier, a Yamux stream, raw artifact fields, or proxy wire frames. Cross-window bridges require an exact allowed origin and may require a bounded capability nonce; runtime failures are mapped to closed status/code values before reaching Service Worker or Window messages.

## Transport v2 Support

WebSocket, raw QUIC, and WebTransport are equal carrier candidates. Browser and Node.js support below describes this SDK's profiles, not the portable API.

Raw QUIC and WebTransport preserve native FIN, RESET_STREAM, STOP_SENDING, flow control, and migration behavior. The TypeScript SDK support below is narrower than the protocol carrier set.

WebSocket uses Yamux only inside its carrier adapter. Yamux has no independent STOP_SENDING primitive, so that operation is explicitly unavailable rather than emulated with a full stream reset.

Browser applications receive a ready `Session` from `connect(...)`. The browser connector supports WSS, restricted plaintext loopback WebSocket direct connections, and WebTransport. WebTransport uses native HTTP/3 bidirectional streams and does not use Yamux.

Chromium does not support a WebTransport pooling option; each carrier creates an independent native WebTransport connection.

Cold-connection diagnostics require every independent carrier to meet the declared deadline. A `dial_failed` result remains a test failure and is not hidden by pooling, retry, or timeout relaxation.

Node.js applications receive the same `Session` contract from `connect(...)`. The Node.js connector supports WSS and WebTransport for direct and tunnel artifacts, plus restricted plaintext loopback WebSocket direct connections. It requires an absolute HTTP(S) `origin`; a custom certificate authority can be supplied through `tls.ca`. Invalid origin and TLS options fail as `ConnectError` with `invalid_options` and are terminal to the optional connection controller.

The Node WebTransport direct listener/server is owned by the Node runtime and the `flowersec-ts-cli` server path. It uses the same native carrier acceptor and session engine as the client connector; it is not a second protocol implementation.

The connectors select an eligible transport from the opaque artifact internally. They do not accept a public transport selector, capability manifest, candidate factory, or admission-reason override. Unsupported artifacts fail closed. The TypeScript package does not expose raw QUIC dialing.

Transport v2 production carrier support: browsers support WebSocket and WebTransport; Node.js supports WebSocket and WebTransport dialing for direct clients and both tunnel roles. Node WebTransport uses the pinned native quiche adapter and is covered by a real admission/session integration test without Playwright.

Flowersec disables application 0-RTT. Reliable streams never use QUIC DATAGRAM; runtimes with negotiated native DATAGRAM expose it only through carrier-neutral unreliable messages.

## Verify

```bash
npm run build
npm test
npm run verify:package
```

See the [API contract](../docs/API_CONTRACT.md), [Transport v2 architecture](../docs/TRANSPORT_V2_ARCHITECTURE.md), [threat model](../docs/THREAT_MODEL.md), and [error model](../docs/ERROR_MODEL.md).
