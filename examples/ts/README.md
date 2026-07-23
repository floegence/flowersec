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
