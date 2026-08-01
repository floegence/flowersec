# Flowersec for TypeScript

`@floegence/flowersec-core` is the ESM-only Flowersec v2 SDK for browsers and Node.js. Its public package surface is limited to the root, `/browser`, `/node`, and `/proxy` entrypoints.

The current source is a Flowersec 2.0 release candidate and has not yet been published as the coordinated 2.0 SDK release. The install command below refers to the registry package; verify its published version before depending on source-only 2.0 APIs.

## Install

```bash
npm install @floegence/flowersec-core
```

## Public API

- `@floegence/flowersec-core` exports `Artifact`, `parseArtifact(...)`, `TRANSPORT_V2_VERSION_POLICY`, `createArtifactAcquireContext(...)`, `createArtifactLease(...)`, `createArtifactResolver(...)`, `createSessionReconnectManager(...)`, `classifyConnectError(...)`, `classifySessionError(...)`, `ConnectError`, and `SessionError` at runtime.
- `@floegence/flowersec-core/browser` adds `connectBrowserSession(...)` and `BrowserSessionOptions`.
- `@floegence/flowersec-core/node` adds `connectNodeSession(...)`, `NodeSessionOptions`, and `NodeSessionTLSOptions`.
- `@floegence/flowersec-core/proxy` adds the `Session`-based HTTP/WebSocket runtime, Service Worker and controller/app-window bridges, strict `proxy.runtime@2` validation, and `connectProxyBrowser(...)` composition.

The root type exports are:

- Artifact acquisition: `ArtifactAcquireContext`, `ArtifactAcquireContextOptions`, `ArtifactLease`, `ArtifactSource`, and `ArtifactVersionPolicy`.
- Sessions: `Session`, `SessionTermination`, `RpcPeer`, `RpcResult<Response>`, `ByteStream`, `IncomingStream`, `OperationOptions`, and `StreamOpenOptions`.
- Unreliable messages: `UnreliableMessageChannel`, `UnreliableMessage`, `UnreliableMessageSendOptions`, and `UnreliableMessageSendResult`.
- JSON values: `JsonPrimitive`, `JsonValue`, and `JsonObject`.
- Reconnection: `SessionAutoReconnectConfig`, `SessionReconnectConfig`, `SessionReconnectManager`, `SessionReconnectState`, and `SessionReconnectStatus`.
- Errors: `ConnectErrorCode`, `SessionErrorCode`, `RetryAction`, and `ErrorRetryClassification`.

`createSessionReconnectManager(...)` resolves a lease for each connection attempt. A refreshable source acquires a fresh lease; a one-time source can be consumed only once.

`classifyConnectError(...)` and `classifySessionError(...)` map redacted public errors to stable application retry decisions. They expose only `action`, `retryable`, `refreshArtifact`, `callerCanceled`, and `sessionClosed`; they do not reveal carrier, candidate, URL, credential, stage, key, or diagnostic details.

`RpcResult<Response>` is a discriminated union. Check `result.ok` before reading either the typed success `payload` or bounded application `error`; a result cannot contain both. RPC call and notify are portable across SDKs, while `RpcPeer.onNotify(...)` is a TypeScript-specific subscription convenience. Generic response typing is static only and does not add runtime schema validation.

When connector options omit a connection timeout, browser and Node.js connectors use the shared ten-second default.

A negotiated `Session.unreliableMessages` channel returns `accepted`, `dropped_expired`, `dropped_budget`, or `dropped_carrier` from `send(...)`. Invalid payloads, unavailable channels, cancellation, closure, and internal failures remain redacted public operation errors.

## Opaque Boundaries

`Artifact` is an opaque handle. Applications cannot inspect its connection data or serialize it back to protocol JSON. `Session` exposes RPC, stream operations, liveness, rekeying, termination, and closure without revealing the selected transport or peer endpoint identity. Public streams expose their kind and terminal state, but no protocol stream identifier.

`ConnectError` and `SessionError` expose only a closed `code`. They do not retain raw causes, credentials, URLs, candidate diagnostics, transport objects, peer details, or internal routing and handshake state.

Candidate lists, runtime capability descriptors, transport factories, admission policy, Yamux, wire messages, cryptographic state, keys, and spend-ledger internals are not package exports.

The proxy entrypoint accepts an opaque `ArtifactLease` or an already connected `Session`. Its public runtime never exposes the selected carrier, a Yamux stream, raw artifact fields, or proxy wire frames. Cross-window bridges require an exact allowed origin and may require a bounded capability nonce; runtime failures are mapped to closed status/code values before reaching Service Worker or Window messages.

## Transport v2 Support

WebSocket, raw QUIC, and WebTransport are equal carrier candidates. Browser and Node.js support below describes this SDK's profiles, not the portable API.

Raw QUIC and WebTransport preserve native FIN, RESET_STREAM, STOP_SENDING, flow control, and migration behavior. The TypeScript SDK support below is narrower than the protocol carrier set.

Browser applications receive a ready `Session` from `connectBrowserSession(...)`. The browser connector supports WSS and WebTransport production connections. WebTransport uses native HTTP/3 bidirectional streams and does not use Yamux.

Node.js applications receive the same `Session` contract from `connectNodeSession(...)`. The Node.js connector supports WSS production connections for direct and tunnel artifacts. It requires an absolute HTTP(S) `origin`; a custom certificate authority can be supplied through `tls.ca`.

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
