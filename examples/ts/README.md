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
  /secure/path/artifact-v2.json \
  https://app.example \
  /durable/state/artifact.spent \
  /secure/path/custom-root.pem
```

The trust root is optional when the endpoint uses a system-trusted certificate.
The example atomically creates and synchronizes the spend receipt before the
connector sends connection credentials. Reusing a receipt path fails closed.
When connection or liveness fails, the one-shot example prints only the
redacted public connection or session error code. Long-lived applications use
`ConnectionController` with a refreshable artifact source; the example never
reuses the spent receipt.
