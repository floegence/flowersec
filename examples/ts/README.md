# TypeScript Transport v2

Install the ESM package and use the runtime-specific opaque session connector:

```bash
npm install @floegence/flowersec-core
```

- Browsers: `connectBrowserSessionV2(...)` from `@floegence/flowersec-core/browser`
- Node.js: `connectNodeSessionV2(...)` from `@floegence/flowersec-core/node`

Both connectors consume a durable opaque `ArtifactLeaseV2` and return a
carrier-neutral `SessionV2`. Transport candidates, wire contracts, key
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
