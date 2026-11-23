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
  /secure/path/artifact-v5.json \
  https://app.example \
  /durable/state/artifact.spent \
  /secure/path/custom-root.pem
```

The trust root is optional when the endpoint uses a system-trusted certificate.
The example atomically creates and synchronizes the spend receipt before the
connector sends connection credentials. Reusing a receipt path fails closed.
After connecting, it makes typed RPC type `7001`, sends notification type
`7002`, writes `hello` to a
`parity.echo` reliable stream, sends FIN, reads `world` through peer FIN, probes
liveness, and closes the session. The typed RPC decoder rejects invalid payloads
before application code uses them.

The repository server-parity peers implement this application contract for
integration coverage; a deployed service must register equivalent handlers.
When a connection or session operation fails, the one-shot example prints only
the redacted public error code. Long-lived applications use
`ConnectionController` with a refreshable artifact source; the example never
reuses the spent receipt.

The Node endpoint installs the four parity methods for reverse calls before
connecting. Set `FSEC_EXAMPLE_QUERY=1` to query and compare the peer's four
contracts. `FSEC_TUNNEL_INGRESS` selects this endpoint's authorized Tunnel URL.

To exercise one 32 MiB binary RPC, set `FSEC_EXAMPLE_LARGE_RPC=call` (or `1`) and
`FSEC_RPC_FRAME_BYTES=50331648` on the calling Node endpoint. On a Node peer
that should only serve the request, use `FSEC_EXAMPLE_LARGE_RPC=serve` and the
same frame limit. Method `7010` accepts one standard Base64 JSON string. The
receiver checks the encoded form and decoded length; the caller verifies every
returned byte. The serving endpoint also answers optional `parity.echo`
streams before the peer closes. It reports `binary_echo=accepted` only after
handling the large request and receiving the peer's authenticated session close.
Configure the peer's send and receive limits for the entire JSON
envelope. With neither option set, the SDK retains its 1 MiB limit and the
example runs the ordinary ping, notification, and stream workflow.

An optional `FLOWERSEC_PARITY_POLICY_FILE` is a JSON object with `execute` and
`disclose` arrays of method IDs. The endpoint reads the current policy at use;
an unreadable or invalid policy denies access. Include `7010` in `execute` to
authorize inbound binary echoes. The large value is separate from the four
contracts exposed by `7004`.
