# TypeScript Transport v2

Install the ESM package and use the runtime-specific opaque session connector:

```bash
npm install @floegence/flowersec-core
```

- Browsers: `connectBrowserSession(...)` from `@floegence/flowersec-core/browser`
- Node.js: `connectNodeSession(...)` from `@floegence/flowersec-core/node`

Both connectors consume a durable opaque `ArtifactLease` and return a
carrier-neutral `Session`. Transport candidates, wire contracts, key
material, and Yamux are implementation details and are not public APIs.

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
When connection or liveness fails with a public Flowersec error, the example
prints only `recovery=retry`, `recovery=refresh_artifact`, or `recovery=stop`.
Refresh always means acquiring a new artifact and session, never reusing the
spent receipt.
