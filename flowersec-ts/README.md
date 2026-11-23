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

The browser and Node connectors use the same `commitSpend(signal)` contract.
Its `Promise<void>` must fulfill only after an atomic, durable first spend of
this credential. Reject on duplicate, unavailable storage, or uncertain commit.
The SDK does not send the credential until the promise fulfills and does not
reuse this lease after attempting the commit. Use a stable credential key in
your own store across processes and restarts; there is no default database.

`StreamHandlers` serves bounded application handlers on any Session.
`ConnectionController` is the only reconnect scheduler and obtains a fresh
lease for each attempt. Work from a terminated Session is never migrated or
replayed.

## Node Servers and ProxyServer

`createAcceptor(...)` accepts direct application Sessions. `SessionHandlers`
binds accepted RPC, notification, and stream handlers before establishment.
`createTunnelRuntime(...)` pairs and forwards opaque relay legs without
terminating the end-to-end Session.

In a Direct `authorize(request, { signal })` callback, use `request.lookupKey()`
to find the authoritative record. Check `request.matchesDirectArtifact(artifact)`
before spending it. Atomically recheck the record's current authorization and
expiry and consume it in the host store; return `{ accepted: true, artifact }`
only after that transaction commits. Duplicate spends, missing records and
uncertain commits must not produce an acceptance.

In a Tunnel `authorize` callback, check the authority-provisioned record with
`verifyTunnelAuthorizationGrant(request, record, { leaseId })`, then return
`{ decision: "allow", grant }` only after the host has durably consumed the
credential and acquired that lease. Reject or throw on failure or an uncertain
commit. `release(leaseId, { signal })` releases only the connection lease; it
must never make the credential spendable again. Ordinary calls, streams and
forwarding need no store. Neither runtime imports SQLite; a host choosing it
supplies the same callbacks as any other backend.

`ProxyServer` registers the bounded HTTP and WebSocket application protocol on
`StreamHandlers` or `SessionHandlers`. It enforces fixed upstream hosts,
origins, header and cookie policy, body/frame limits, timeouts, cancellation,
and a close barrier. The `/proxy` browser runtime uses the same application
wire through a Service Worker or exact-origin window bridge.

## Supported Connections

Browsers support WSS and optional browser-owned WebTransport. Node.js supports
WSS, raw QUIC, and WebTransport for clients, direct listeners, and
opaque tunnel listeners. Raw QUIC and WebTransport require the Flowersec native
package for macOS or glibc Linux on arm64/x64. Node does not issue artifacts.

For WebTransport, pass `webTransportProfile: "native_h3"` or `"draft02"`
and a canonical HTTP(S) `origin` to `connect` or `createConnectionController`.
Use `carrier: "webtransport"`, the matching `profile`, and a nonempty
`allowedOrigins` list on the corresponding listener. An absent Origin is
rejected. With a wildcard bind address, supply the public HTTPS URL with the
same port and the exact `/flowersec/webtransport/v5/direct` or
`/flowersec/webtransport/v5/tunnel` path. `native_h3` requires negotiated QUIC
reliable stream reset and `webtransport-h3` Extended CONNECT.

CA candidates use platform or configured private roots. Pin candidates verify
only the complete artifact-bound active pin set and never fall back to CA.
Public errors remain closed and redacted.

## CLI

The package installs `flowersec-ts-cli`. Its client and server commands accept
only `flowersec/5` artifacts. The server requires a TLS certificate and private
key for its WebSocket listener. The client requires `--spend-marker PATH`.
The server records acceptance next to its artifact, keyed by credential digest;
use `--spend-marker PATH` to choose a different durable location. All processes
for the same role and credential must share a marker, and the client and server
must use distinct markers. Use a trusted directory on a persistent filesystem
that supports exclusive creation and syncing both files and directories. Keep
the marker after closing the session and across restarts.

## Verify

```bash
npm run build
npm test
npm run verify:package
```

`npm run build` compiles the public SDK and CLI. Use `npm run build:interop`
when preparing the separate interoperability or capacity tools; `dist/interop`
is excluded from the published SDK.

See the [TypeScript cookbook](../examples/ts/README.md),
[API contract](../docs/API_CONTRACT.md),
[Transport v5 architecture](../docs/TRANSPORT_V5_ARCHITECTURE.md),
[wire contract](../docs/TRANSPORT_V5_WIRE.md), and
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

Applications that require requests to survive arbitrary session stalls may explicitly select `sessionBound: true` in the TypeScript fetch init for an individual request and `ProxyServerOptions.SessionBoundRequests` in Go. This host policy removes HTTP establishment, elapsed-response and SSE-idle deadlines; caller cancellation, session termination, finite body/chunk limits and HTTP/event admission caps remain enforced. A peer's request metadata cannot enable the server policy. Requests are never replayed by the proxy. Both ends must opt in; the default finite policy remains unchanged. Node proxy servers retain the default finite policy.
