# Swift Cookbook

This example uses Flowersec's current `TransportEnvironment` and
SDK-owned, closed `ConnectionMaterialSource` connection path. The selected
engineering fixture supplies a preauthorized local pool. The example imports
its complete identity first and calls `makePreauthorizedPoolSource`; it does
not implement Acquire or assemble material inside a custom callback. Connect
acquires once and proceeds through the native Prepare/spend/activation/READY
path. Its named `ServiceClient` makes a
typed unary call and publishes a notification. A raw reliable stream exercises
write, read and FIN, followed by liveness and explicit Session/TransportEnvironment close.

## Run

Requirements: macOS 15+ and the exact Swift toolchain in `toolchains.json`.

```bash
swift run --package-path ./examples/swift
```

Without connection material, the example prints:

```text
transport=v4
connection_api=environment+source
service_api=named
```

The connected workflow uses an explicitly selected local engineering authority.
Provide its current material bundle, TLS trust root and a new durable receipt
path:

```bash
FSEC_MATERIAL_PATH=/secure/path/material.json \
FSEC_SPEND_RECEIPT_PATH=/durable/state/material.spent \
FSEC_TRUST_ROOT_PEM_PATH=/secure/path/custom-root.pem \
  swift run --package-path ./examples/swift
```

`EngineeringMaterial.swift` accepts the bounded engineering JSON envelope used
by the repository's interop harness. Its byte fields contain base64-encoded
complete signed maps. The example supports role 0, a preauthorized pool and a
direct WebSocket candidate. The authority's independently supplied namespace
records pin the root key, tenant and bootstrap endpoint. Bootstrap URLs must be
explicit HTTP or HTTPS endpoints at `localhost` or `127.0.0.1` with an explicit
port. HTTPS uses independently supplied PEM roots and TLS 1.3. Redirects are
rejected, and URLSession invalidation is joined before the callback returns. Each
bootstrap request carries the SDK's original fresh nonce, and the SDK verifies
the complete signed response and revocation state before admitting credentials.
The local test host explicitly supplies wall-clock trusted-time bounds and the
loopback address for the signed TLS hostname.

This engineering input contains fixture private seeds and trust configuration.
Use it only with an explicitly trusted engineering host. Production applications
supply their own independently trusted configuration, identity provider,
trusted time, durable history continuity and refreshable material source.

## Application Contract

`ParityApplication.swift` declares the local `flowersec.parity` service. Its JSON
codec accepts only `{ "value": "..." }`, with a 4096-byte encoded payload limit.
Schema revisions are `1`.

- Unary type `7001` uses transient semantics, a bounded response of at most
  4096 bytes, a 30000 ms message lifetime and a 30000 ms transient run limit. The
  client sends `{ "value": "ping" }` and requires an equal response.
- Notification type `7002` uses observation semantics, a 30000 ms message
  lifetime and no response. The client sends `{ "value": "notify" }`.
- Both contracts disable restart flush and contain an empty application error
  catalog. Their exact canonical encodings are declared locally by
  `ParityApplication.contract`; the peer must register matching contracts.
- The raw `parity.echo` stream uses the current `application/json` metadata
  namespace, version `1`, and field `cell` containing an encoded JSON string
  (`direct` by default). The client writes `hello`,
  sends FIN, then requires `world` followed by peer FIN.

Before binding, the example queries both contracts through the fixture's
independently fixed QueryBinding: type `7`, a 32-byte digest whose first byte is
`9` and whose remaining bytes are zero, and a 30000 ms maximum lifetime. The
query includes the exact locally known and wanted contract digests. A full
response must match them; an unchanged response can reuse only those original
local snapshots. The connection requires the `services` application profile and
local TLS 1.3 verification.

The application target pins the server identity digest from the explicitly
selected fixture material; successful connection admission independently
verifies that material against the configured trust. Received application bytes
cannot choose a codec, method, target or dispatch route.

## Durable Spend and Cleanup

The example creates a private, exclusive `<receipt-path>.history` directory and
uses the SDK's native SQLite pool-spend transaction. A fresh locally generated
store identifier and the original directory identity supply this one-shot
host's continuity gate. Existing history directories are rejected. Retain the
history directory after success or failure; acquiring another artifact does
not justify replacing or resetting an existing spend history.

After the original connection reaches READY, the example writes
`flowersec-v4-material-spent` to the receipt with no overwrite, restricts the file
to the current user, and synchronizes the file and parent directory. The receipt
contains no credential or key material. The native SQLite history remains the
authoritative record, including when connection establishment fails after a
spend and no readable receipt is produced. The source admits one acquisition
and never retries the same original material.

The client explicitly closes its service binding, Session and TransportEnvironment.
Connection and Session failures expose structured retry dispositions. A
long-lived application can use `ConnectionController` with a refreshable
`ConnectionMaterialSource` and a controller service binding.

## Configured online controller

`ConfiguredController.swift` provides `makeLiveController` with explicit
TransportEnvironment trust/time configuration, application private keys and a
`TransportLiveAuthoritySourceConfiguration`. Each independent control
endpoint uses TLS 1.3 with caller-supplied mutual TLS credentials and numerical
routing. The issuer uses the reference `/issue/direct` application protocol or the
configured tunnel issuance path; activation uses the same
`live-authorization-1` request as the Go and TypeScript adapters. A tunnel source
also supplies independently configured future Grant scope, exact limits and
relay certificate. The response's original activation and local Grant must both
complete that captured preparation before native HOP_AUTH, Noise and READY. The controller's next transport attempt acquires a fresh Artifact
through this source. It never retries the previous activation invocation or
replays application work. Its optional `initializeSession` callback receives the
exact candidate before controller publication. Register through methods bound to
that Session, using the application's existing trusted contract/authority. A
failure stops automatic reconnection of that initialization and preserves the
possibility of an unknown business outcome.

`LiveServer.swift` demonstrates the independent server Source. Configure the
server-allow listener's exact mutual TLS peer, secure durable admission backing,
application identity and original Artifact/certificates. `registerOriginal` returns
the trusted binding to publish through the application's authority flow before
client authorization. A tunnel registration uses its independently configured
server Grant scope; the reference server-allow request carries that Grant without
activation. The SDK owns preparation and ACK, then verifies the original signed
FSB and commits server admission before Noise/READY. `connectLiveServer` uses
the signed route direction. `acceptLiveServer` adds an explicit listener
requirement; a signed server dialer uses the connection recipe. The same recipe exposes
`publishLiveRelay` for a running continuous `RelayHost`: every publication has a
separate original paired run and completion ticket, while the shared durable
ledger prevents canceled, failed or completed claims from reopening.

`makeRegisteredLiveRelay` installs a pending live relay before the production
client Source prepares its physical carrier. Configure `relayPreparation` for
its pinned preparation control endpoint. Listener readiness permits only the
original relay dialer; TxA still follows native Prepare. The original issuer
callback supplies the matching activation and both Grants through the pinned
TxB activation endpoint, and the final ACK write releases HOP. The caller owns
`host.run()`, cancellation and cleanup, and awaits
`startRegisteredLiveRelay(host)` before connecting the Source; the helper starts
`host.run()` and joins listener/control readiness, stopping and joining the daemon
if startup fails. `makeCommonParentWinner` creates the independent common CAS
owner and installs its configuration on the TransportEnvironment's pool history. Pass
that same `configuration` as `parentWinner` to relay claims and live server
admissions. This makes server direct-pool and tunnel-pool candidates compete on
the same parent key; missing configuration fails closed at server consumption.
Pool-spend and relay-claim refusal records precede CAS. Live-server registration
is durably fixed before carrier preparation. Admission and paired forwarding
claims commit only after CAS. Public winner readback cannot recreate a carrier,
admission or forwarding right.

`consumeCapturedStream` captures one Session before starting a long-lived
terminal/editor transfer. Writes, FIN, reads and cleanup remain on that Session
while the controller is free to establish a later Session for future work.
The callback receives each chunk immediately. Cancellation or callback failure
closes only the original stream. The application separately closes the shared
controller, source and TransportEnvironment when their owning scope ends.

## Troubleshooting

- Existing receipt or history: obtain fresh material and select an unused
  durable state path. Keep the previous history intact.
- Trust/bootstrap rejection: verify the independently selected authority pins,
  nonce-aware bootstrap endpoint, signed trust response and current state.
- TLS, Origin or admission rejection: check the exact signed direct WebSocket
  route, its TLS trust root and signed Origin policy.
- Application contract mismatch: register the exact local parity contracts and
  the current notification/stream handlers on the fixture server.

## Fixed backend proxy forwarding

`ProxyForwarding.swift` creates a `ProxyServer` for an already-established Session
and registers both current proxy stream kinds with `StreamHandlers`. Supply the
application's fixed HTTP/HTTPS origin, numeric endpoint, TLS trust roots and
`ProxyForwardingPolicy`. Add the application's other stream handlers to the returned
registry before invoking `serveProxyForwarding`; its bounded dispatcher preserves
those unrelated workflows. The helper uses explicit metadata, body, frame and
concurrency limits. HTTP cookies may feed a later WebSocket to that same backend;
request paths never select another origin. The selected Session remains captured
through any Controller replacement. Dispatcher termination joins its handlers and
the original upstream operations.
