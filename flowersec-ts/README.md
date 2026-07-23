# Flowersec for TypeScript

`@floegence/flowersec-core` is the ESM-only Flowersec v2 SDK for browsers and Node.js. Its public package surface is limited to the root, `/browser`, and `/node` entrypoints.

## Install

```bash
npm install @floegence/flowersec-core
```

## Public API

- `@floegence/flowersec-core` exports `Artifact`, `parseArtifact(...)`, `TRANSPORT_V2_VERSION_POLICY`, `createArtifactAcquireContextV2(...)`, `createArtifactLeaseV2(...)`, `createArtifactV2Resolver(...)`, `createSessionReconnectManagerV2(...)`, `ConnectError`, and `SessionError` at runtime.
- `@floegence/flowersec-core/browser` adds `connectBrowserSessionV2(...)` and `BrowserSessionConnectorV2Options`.
- `@floegence/flowersec-core/node` adds `connectNodeSessionV2(...)`, `NodeSessionConnectorV2Options`, and `NodeSessionTLSOptionsV2`.

The root type exports are:

- Artifact acquisition: `ArtifactAcquireContextV2`, `ArtifactAcquireContextOptionsV2`, `ArtifactLeaseV2`, `ArtifactSourceV2`, and `ArtifactVersionPolicyV2`.
- Sessions: `SessionV2`, `SessionTerminationV2`, `RpcPeerV2`, `RpcResultV2`, `ByteStreamV2`, `IncomingStreamV2`, `OperationOptionsV2`, and `StreamOpenOptionsV2`.
- JSON values: `JsonPrimitiveV2`, `JsonValueV2`, and `JsonObjectV2`.
- Reconnection: `SessionAutoReconnectConfigV2`, `SessionReconnectConfigV2`, `SessionReconnectManagerV2`, `SessionReconnectStateV2`, and `SessionReconnectStatusV2`.
- Errors: `ConnectErrorCode` and `SessionErrorCode`.

`createSessionReconnectManagerV2(...)` resolves a lease for each connection attempt. A refreshable source acquires a fresh lease; a one-time source can be consumed only once.

## Opaque Boundaries

`Artifact` is an opaque handle. Applications cannot inspect its connection data or serialize it back to protocol JSON. `SessionV2` exposes RPC, stream operations, liveness, rekeying, termination, and closure without revealing the selected transport or peer endpoint identity. Public streams expose their kind and terminal state, but no protocol stream identifier.

`ConnectError` and `SessionError` expose only a closed `code`. They do not retain raw causes, credentials, URLs, candidate diagnostics, transport objects, peer details, or internal routing and handshake state.

Candidate lists, runtime capability descriptors, transport factories, admission policy, Yamux, wire messages, cryptographic state, keys, and spend-ledger internals are not package exports.

## Transport v2 Support

WebSocket, raw QUIC, and WebTransport are equal carrier candidates.

Raw QUIC and WebTransport preserve native FIN, RESET_STREAM, STOP_SENDING, flow control, and migration behavior. The TypeScript SDK support below is narrower than the protocol carrier set.

Browser applications receive a ready `SessionV2` from `connectBrowserSessionV2(...)`. The browser connector supports WSS and WebTransport production connections. WebTransport uses native HTTP/3 bidirectional streams and does not use Yamux.

Node.js applications receive the same `SessionV2` contract from `connectNodeSessionV2(...)`. The Node.js connector supports WSS production connections for direct and tunnel artifacts. It requires an absolute HTTP(S) `origin`; a custom certificate authority can be supplied through `tls.ca`.

The connectors select an eligible transport from the opaque artifact internally. They do not accept a public transport selector, capability manifest, candidate factory, or admission-reason override. Unsupported artifacts fail closed. The TypeScript package does not expose raw QUIC dialing.

Transport v2 production carrier support: browsers support WebSocket and WebTransport; Node.js supports WebSocket dialing for direct clients and both tunnel roles.

Flowersec disables application 0-RTT and does not use QUIC DATAGRAM.

## Verify

```bash
npm run build
npm test
npm run verify:package
```

See the [API contract](../docs/API_CONTRACT.md), [Transport v2 architecture](../docs/TRANSPORT_V2_ARCHITECTURE.md), [threat model](../docs/THREAT_MODEL.md), and [error model](../docs/ERROR_MODEL.md).
