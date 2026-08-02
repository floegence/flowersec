# Flowersec for TypeScript

`@floegence/flowersec-core` is the ESM-only Flowersec v2 SDK for browsers and Node.js. Its public package surface is limited to the root, `/browser`, `/node`, `/reconnect`, and `/proxy` entrypoints.

The current source is a Flowersec 2.0 release candidate and has not yet been published as the coordinated 2.0 SDK release. The install command below refers to the registry package; verify its published version before depending on source-only 2.0 APIs.

## Install

```bash
npm install @floegence/flowersec-core
```

## Public API

- `@floegence/flowersec-core` exports the portable artifact, lease, session, stream, RPC, stream-metadata, and error-classification API, plus profile-owned unreliable messages when negotiated.
- `@floegence/flowersec-core/browser` adds `connectBrowserSession(...)` and `BrowserSessionOptions`.
- `@floegence/flowersec-core/node` adds `connectNodeSession(...)`, `NodeSessionOptions`, and `NodeSessionTLSOptions`.
- `@floegence/flowersec-core/reconnect` adds artifact-source acquisition and reconnect orchestration without a redundant v2 version policy.
- `@floegence/flowersec-core/proxy` adds the `Session`-based HTTP/WebSocket runtime, Service Worker and controller/app-window bridges, strict `proxy.runtime@2` validation, and `connectProxyBrowser(...)` composition.

The root type exports are:

- Artifact lifecycle: `Artifact`, closed `ArtifactError` parse failures, and `ArtifactLease`.
- Sessions: `Session`, `SessionTermination`, `RpcPeer`, `RpcResult<Response>`, `ByteStream`, `IncomingStream`, `StreamMetadata`, `OperationOptions`, and `StreamOpenOptions`. Create metadata with `createStreamMetadata(...)`; invalid values throw `StreamMetadataError` before opening a stream.
- Unreliable messages: `UnreliableMessageChannel`, `UnreliableMessageSendOptions`, and `UnreliableMessageSendResult`.
- JSON values: `JsonPrimitive`, `JsonValue`, and `JsonObject`.
- Errors: `ConnectErrorCode`, `SessionErrorCode`, `RetryAction`, and `ErrorRetryClassification`.

The `/reconnect` entrypoint exposes `ArtifactAcquireContext`, `ArtifactSource`, and the reconnect types. `createSessionReconnectManager(...)` resolves a lease for each connection attempt. A refreshable source acquires a fresh lease; a one-time source can be consumed only once.

`classifyConnectError(...)` and `classifySessionError(...)` map redacted public errors to stable application retry decisions. They expose only `action`, `callerCanceled`, and `sessionClosed`; retryability and fresh-artifact acquisition are represented by `action` instead of duplicate booleans. They do not reveal carrier, candidate, URL, credential, stage, key, or diagnostic details.

`RpcResult<Response>` is a discriminated union. `RpcPeer.call(...)` requires a decoder for successful payloads, so the typed success value has passed application validation before it is returned. Check `result.ok` before reading either the typed success `payload` or bounded application `error`; a result cannot contain both. RPC call and notify are portable across SDKs, while `RpcPeer.onNotify(...)` is a TypeScript-specific subscription convenience.

When connector options omit a connection timeout, browser and Node.js connectors use the shared ten-second default.

A negotiated `Session.unreliableMessages` channel sends defensively copied `Uint8Array` values and returns `accepted`, `dropped_expired`, `dropped_budget`, or `dropped_carrier`. `receive(...)` also returns a fresh `Uint8Array`. Invalid payloads, unavailable channels, cancellation, closure, and internal failures remain redacted public operation errors.

## Capability Layers

The portable core is the same application model used by every Flowersec SDK:
opaque artifact parsing, a durable single-use lease, one-shot connection,
carrier-neutral sessions, RPC, reliable streams, redacted public errors, and
error classifiers. `classifyConnectError(...)` and
`classifySessionError(...)` return the stable cross-language recovery decision;
callers should not compare raw TypeScript error-code strings with other SDKs.

Only this portable core is required to align across languages. Complete SDK
profiles and language conveniences intentionally differ by runtime.

The TypeScript SDK profile is split by entrypoint: browsers own WebSocket and
WebTransport dialing, while Node.js owns WebSocket dialing. Its language convenience
includes static generic RPC result typing, notification subscriptions, reconnect
orchestration, and proxy composition. These conveniences do not expand the
portable core required from Go, Swift, or Rust.

## Opaque Boundaries

`Artifact` is an opaque handle. Applications cannot inspect its connection data or serialize it back to protocol JSON. `ArtifactLease` exposes no spend operation; only the connector may invoke the durable callback. `Session` exposes RPC, stream operations, liveness, rekeying, `waitTermination()`, and closure without revealing the selected transport or peer endpoint identity. Public streams expose their kind and terminal state, but no protocol stream identifier.

`ConnectError` and `SessionError` expose only a closed `code`. They do not retain raw causes, credentials, URLs, candidate diagnostics, transport objects, peer details, or internal routing and handshake state.

Candidate lists, runtime capability descriptors, transport factories, admission policy, Yamux, wire messages, cryptographic state, keys, and spend-ledger internals are not package exports.

The proxy entrypoint accepts an opaque `ArtifactLease` or an already connected `Session`. Its public runtime never exposes the selected carrier, a Yamux stream, raw artifact fields, or proxy wire frames. Cross-window bridges require an exact allowed origin and may require a bounded capability nonce; runtime failures are mapped to closed status/code values before reaching Service Worker or Window messages.

## Transport v2 Support

WebSocket, raw QUIC, and WebTransport are equal carrier candidates. Browser and Node.js support below describes this SDK's profiles, not the portable API.

Raw QUIC and WebTransport preserve native FIN, RESET_STREAM, STOP_SENDING, flow control, and migration behavior. The TypeScript SDK support below is narrower than the protocol carrier set.

Browser applications receive a ready `Session` from `connectBrowserSession(...)`. The browser connector supports WSS and WebTransport production connections. WebTransport uses native HTTP/3 bidirectional streams and does not use Yamux.

Node.js applications receive the same `Session` contract from `connectNodeSession(...)`. The Node.js connector supports WSS production connections for direct and tunnel artifacts. It requires an absolute HTTP(S) `origin`; a custom certificate authority can be supplied through `tls.ca`. Invalid origin and TLS options fail as `ConnectError` with `invalid_options`, so callers can use the normal connection classifier.

The connectors select an eligible transport from the opaque artifact internally. They do not accept a public transport selector, capability manifest, candidate factory, or admission-reason override. Unsupported artifacts fail closed. The TypeScript package does not expose raw QUIC dialing.

Transport v2 production carrier support: browsers support WebSocket and WebTransport; Node.js supports WebSocket dialing for direct clients and both tunnel roles.

Flowersec disables application 0-RTT. Reliable streams never use QUIC DATAGRAM; runtimes with negotiated native DATAGRAM expose it only through carrier-neutral unreliable messages.

## Verify

```bash
npm run build
npm test
npm run verify:package
```

See the [API contract](../docs/API_CONTRACT.md), [Transport v2 architecture](../docs/TRANSPORT_V2_ARCHITECTURE.md), [threat model](../docs/THREAT_MODEL.md), and [error model](../docs/ERROR_MODEL.md).
