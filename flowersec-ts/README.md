# Flowersec for TypeScript

`@floegence/flowersec-core` is the ESM-only Flowersec SDK for browsers and
Node.js. It provides encrypted sessions, RPC, notifications, reliable byte
streams, connection recovery, server runtimes, and browser proxy integration.

## Install

```bash
npm install @floegence/flowersec-core
```

Node.js 24.20.0 or newer is required.

Node SQLite storage and native carriers use the matching optional native package
installed with the SDK on macOS arm64/x64 and glibc Linux arm64/x64. Keep optional
dependencies enabled when deploying those features.

## Entrypoints

- `@floegence/flowersec-core` exports the current Transport v4 Environment,
  Session, ConnectionMaterial, connection/controller entrypoints, credential
  source contracts, streams, RPC, results, and resource contracts.
- `@floegence/flowersec-core/browser` adds browser WSS and WebTransport client
  configuration with optional host-provided IndexedDB pool storage.
- `@floegence/flowersec-core/node` adds WSS, raw QUIC, and WebTransport client
  and listener APIs, current `Acceptor`/Serve owners, SQLite admission and pool
  storage, `ProxyServer`, and opaque tunnel owners.
- `@floegence/flowersec-core/proxy` provides the current-Session browser HTTP
  and WebSocket proxy runtime, Service Worker integration, and exact-origin
  window bridges.

## Supported Connections

`connect(...)` establishes current v4 sessions over the supported WebSocket and native carrier entrypoints. `ConnectionController` handles qualified reconnects without replaying accepted application work.

## Current Client Sessions

Create a `TransportEnvironment`, install the platform client with the matching
`./node` or `./browser` entrypoint, register and bootstrap a credential
namespace, then connect with a registered material source:

```ts
import { createTransportEnvironment } from "@floegence/flowersec-core";
import { configureNodeWSS } from "@floegence/flowersec-core/node";

const environment = createTransportEnvironment(environmentConfig);
const client = configureNodeWSS(environment, clientConfig);
const namespace = client.namespace(namespaceOptions);
// Authenticate the namespace bootstrap response before registering a source.
const source = client.registerPoolSource(credentialPolicy, credentialProvider);
const session = await environment.connect(source, { application_profile: "transport" });
```

The host supplies the credential, trust, storage-continuity, and carrier
configuration. `Session` exposes reliable streams, RPC, liveness, rekeying,
and cleanup without exposing candidate selection or native carrier handles.
`ConnectionController` is the SDK-owned replacement scheduler; it obtains fresh
material for each attempt and does not migrate work from a terminated Session.

## Durable material pools

Node and browser configured clients expose
`registerDurablePoolSource(policy, configuration)`. It uses the configured
original SQLite or IndexedDB pool store owned by the same Environment. It
journals pending TopUp intent, material availability, Applied entry facts and
sequence frontiers in one durable transaction; consuming a material does not
erase its bounded Applied history. Acquisition removes availability durably
before returning material and never performs an implicit TopUp.

Call `source.topUp(options)` explicitly. `desiredCount` defaults to four;
`maxItemBytes` bounds the complete encoded material ByteString. Concurrent
callers observe the original adopted options. The returned opaque handle
discloses only its immutable ID; `handle.status()` preserves the original
operation's proven state even when a query is canceled or its source is closed.
Current journal observations use a signed owner-fence proof, and
`source.recoverPendingTopUps(tenant, sourceIncarnation)` recovers the original
pending handles. A stale handle retains its original facts and never observes
another operation. `handle.cleanupStatus()` and `handle.waitCleanup()` join
only that operation's actual callbacks; later operations do not extend its
cleanup. Local cancellation or timeout never retires a pending server operation.

`createSessionPoolControl(client, topUpMethod, ackMethod, replyDecoder, timeoutMS)`
uses the already bound service client's actual transient unary
methods 41006 and 41007. The host installs their byte codecs and authenticated
response/error contract. A pending operation can read the server's original
committed replay or terminal result after its append deadline using the same operation ID, request digest and
unchanged wire deadline. A confirmed installed batch can recover and Ack after
the original append deadline with a separate bounded recovery call. It does
not parse old identity keys or reinstall consumed material. A recovery read
preserves the original append ID and deadline.
Fresh append requests retain their original hard deadline and complete current
identity binding.

## Node Servers and Proxy

Node applications create a current listener with `createNodeWSSListener(...)`
and pass it to `environment.serve(...)` with a captured handler plan. The
listener and Serve handle own bounded admission, authenticated application
authorization, Session publication, and cleanup. The `./node` entrypoint also
provides current raw QUIC and WebTransport client/listener APIs and opaque
tunnel-runtime owners.

Registered live tunnel clients and servers can install an independent relay
process through `control.relayControl`. It contains `endpoint`, `authority`,
`tls` (`certificatePEM`, `privateKeyPEM`, `trustPEM`), and a bounded `workMS`
interval. Engineering deployment JSON carries the same optional installation
as top-level `relay_control`, with `workMS` encoded as a decimal string. The
endpoint must be a fixed HTTPS root URL with an explicit port and a numeric
address or `localhost`. `localhost` connects directly to `127.0.0.1` while
retaining `localhost` for HTTP authority and TLS hostname verification; other
hostnames are rejected. The relay connection uses the endpoint's original
registered control certificate and private key, with independently installed
relay server trust.

An endpoint reports relay readiness only after its actual listener binds and
only when its original signed Candidate declares that endpoint as the physical
listener. A's original live provider sends the selected preparation request,
then the authority's activation proof and A's client Grant. It returns the
signed response to the SDK only after the relay's exact CBOR acknowledgement.
Cancellation retains each request body and native connection through actual
cleanup, and does not retry the original control transaction.

`ProxyServer` declares bounded HTTP and WebSocket handlers for the current
Session stream API. Browser applications use `createProxySurface(...)` to capture
an explicit trust boundary, exact host and content origins, method/path scope,
and either a fixed Session or the controller's current Session at admission.
`connectProxyBrowser(...)` composes this Surface with connection and lifetime.
An isolated Surface attaches only the expected content Window and discloses a
narrow content capability; it requires an explicit path scope and cannot own a
host Service Worker. The host may give the attachment a finite
`attachmentLifetimeMS` and revoke it with an observed
`attachmentLifecycleSignal`; a new attachment requires a new host
authorization. A trusted Surface can own the exact controlled Service Worker
through an explicit runtime registration token. A `capture_current` binding re-captures the Controller's current Session for
each new request OPEN under the Controller's authorization gate. Existing Streams remain
bound to the Session that opened them.

Credentials default to `none`. Managed Node credentials require
`upstream_cookie_session`, trusted `resolveScope` and `authorize` callbacks,
existing ProxyServer resource accounts, and explicit delegated first-party
scope. Each Surface owns an independent volatile jar. Unknown contexts never
create jars. Incoming Cookie and Authorization conflict with managed mode;
Set-Cookie stays inside the server and presented responses use `no-store,
no-transform`. Standard domain, path, Secure, HttpOnly, prefix and SameSite
selection uses the maintained Cookie implementation and the Environment clock.
WebSocket Cookie use requires an explicit server option.

`surface.clearUpstreamCredentials({ reuseAfterClear: true })` seals all actual
host and worker delivery gates before requesting server revocation. Its result
reports `serverInvalidation`, `ownedDeliveryFence`, and
`associationInstallation` independently. `clearedForThisSurface` requires
confirmed server revocation and delivery fencing; `readyForReuse` additionally
requires installation of the new association. `reuseAfterClear` defaults to
true and is fixed for the original Clear operation. False intent retains the
reserved candidate without installation. Cancellation, a malformed ACK, or
worker replacement never reopens the Surface. `cleanupStatus()` continues to
report physical request, body-reader and worker cleanup after an observer stops.

## Connection and server lifecycle

Both clients select the carrier before material acquisition and publish a
Session only after the actual authorization transaction, authenticated carrier
exchange, Noise handshake, and dual READY messages. Node verifies TLS 1.3 and
the signed CA or leaf-DER pin policy. Browser carriers rely on trusted immutable
deployment bindings for browser-unobservable TLS and HTTP/3 facts; browser WSS
is CA-only. Required guarantees that the selected carrier cannot provide are
rejected before acquisition.

The optional browser IndexedDB adapter requires strict-durability transactions
and independent continuity evidence outside the database/origin. The TypeScript
SDK has no built-in remote pool-consume service. Node SQLite stores retain
consumed leases across reopen and reject uncertain commits without exact
original-transaction confirmation.

Node serving uses a current listener, captured handler plan, and
`environment.serve(...)`. Serve owns bounded TCP/TLS/HTTP admission, authenticated
application authorization, durable admission, Session publication, and the
actual listener, Session, lease, and callback cleanup. See the
[TypeScript transport runtime](../docs/TYPESCRIPT_TRANSPORT_V4.md) for supported
providers and storage continuity.

## CLI

The package installs `flowersec-ts-cli` for current Transport v4 Environment
workflows. Run `flowersec-ts-cli client --config ./flowersec.config.mjs` or
`flowersec-ts-cli server --config ./flowersec.config.mjs`. The explicitly chosen
local ES module exports a `configuration` (or default export) with a `client`
or `server` setup function. A client setup supplies the original Environment,
a registered material source, and optional connection requirements; a server
setup supplies an existing current `Acceptor` or its trusted `AcceptorOptions`.
The CLI does not parse peer credentials or select endpoints; trust and listener
keys are configured by the explicitly selected local module.

## Verify

```bash
npm run build
npm test
npm run verify:package
```

See the [TypeScript cookbook](../examples/ts/README.md),
[API contract](../docs/API_CONTRACT.md),
[TypeScript Transport v4](../docs/TYPESCRIPT_TRANSPORT_V4.md),
[Transport v4 binding](../docs/TRANSPORT_V4_BINDING.md), and
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
