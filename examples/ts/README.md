# TypeScript Example

Install the ESM package and use the runtime-specific opaque session connector:

```bash
npm install @floegence/flowersec-core
```

- Browsers: `connect(...)` from `@floegence/flowersec-core/browser`
- Node.js: `connect(...)` from `@floegence/flowersec-core/node`

Both connectors consume a durable opaque `ArtifactLease` and return the same
`Session` API. The application does not need to know which connection path was
selected.

## Node.js client

Run the maintained Node.js example with a fresh artifact, an exact HTTP(S)
origin, and a new durable receipt path:

```bash
node examples/ts/node-client.mjs \
  /secure/path/artifact-v3.json \
  https://app.example \
  /durable/state/artifact.spent \
  /secure/path/custom-root.pem
```

The trust root is optional when the endpoint uses a system-trusted certificate.
The example atomically creates and synchronizes the spend receipt before the
connector sends connection credentials. Reusing a receipt path fails closed.
After connecting, it registers a decoded notification handler, makes typed RPC
type `7001`, exchanges notification type `7002`, writes `hello` to a
`parity.echo` reliable stream, sends FIN, reads `world` through peer FIN, probes
liveness, cancels the subscription, and closes the session. The decoder rejects
invalid notification or RPC payloads before application code uses them.

The repository server-parity peers implement this application contract for
integration coverage; a deployed service must register equivalent handlers.
When a connection or session operation fails, the one-shot example prints only
the redacted public error code. Long-lived applications use
`ConnectionController` with a refreshable artifact source; the example never
reuses the spent receipt.
