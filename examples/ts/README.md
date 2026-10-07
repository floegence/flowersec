# TypeScript Example

Build the local TypeScript package before running the maintained example:

```bash
cd flowersec-ts
npm install
npm run build
cd ..
```

The example uses the repository's current engineering peer fixture. It is not a
production material loader and must be given a fresh original pool material
JSON, an exact HTTP(S) origin, and a new durable receipt path.

## Node.js client

Run the Node.js example from the repository root:

```bash
node examples/ts/node-client.mjs \
  /secure/path/current-material.json \
  https://app.example \
  /durable/state/material.spent \
  /secure/path/custom-root.pem
```

The trust root is optional when the endpoint uses a system-trusted certificate.
The fixture consumes one original pool record through its configured source and
checks that exactly one spend was recorded. The receipt is an independent,
post-connect observation marker; reusing an existing receipt path fails closed.

After connecting, the example binds the `flowersec.parity` service, performs a
typed RPC using method type `7001`, sends an observation notification using type
`7002`, writes `hello` to the `parity.echo` reliable stream, sends FIN, reads
`world` through peer FIN, probes liveness, and closes the session. The typed RPC
decoder rejects invalid payloads before application code uses them.

The repository's server-parity peers implement this application contract for
integration coverage; a deployed service must register equivalent handlers.
The example reports the operation error message for local diagnostics and does
not retry or reuse spent material. Long-lived applications should use
`ConnectionController` with a refreshable material source.
