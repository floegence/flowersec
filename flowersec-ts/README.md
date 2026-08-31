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
  RPC, stream, metadata, error, and connection-controller contracts.
- `@floegence/flowersec-core/browser` adds browser `connect(...)`,
  `createConnectionController(...)`, WSS, optional WebTransport, and the
  isolated private-loopback profile.
- `@floegence/flowersec-core/node` adds Node `connect(...)`,
  `createConnectionController(...)`, `createAcceptor(...)`,
  `createTunnelRuntime(...)`, `ProxyServer`, `SessionHandlers`, and
  `RPCHandlers`.
- `@floegence/flowersec-core/proxy` provides the browser HTTP/WebSocket proxy
  runtime, Service Worker integration, and exact-origin window bridges.

## Client Sessions

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

## Supported Connections

Browsers support WSS and optional browser-owned WebTransport. Node.js supports
WSS and raw QUIC client, direct-server, and tunnel-runtime roles. Raw QUIC uses
the optional Flowersec native package for macOS or glibc Linux on arm64/x64.
Node.js does not expose WebTransport or an artifact issuer; use an application
control plane such as the Go control-plane package.

CA candidates use platform or configured private roots. Pin candidates verify
only the complete artifact-bound active pin set and never fall back to CA.
Public errors remain closed and redacted.

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
[Transport v3 architecture](../docs/TRANSPORT_V3_ARCHITECTURE.md),
[wire contract](../docs/TRANSPORT_V3_WIRE.md), and
[error model](../docs/ERROR_MODEL.md).
