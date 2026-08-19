# Rust Example

This package exercises the maintained Rust public surface. It provides two
workflows:

- parse an application-acquired opaque artifact without exposing its contents;
- establish a session through the one-shot `connect(...)` and `Session` API;
- run the repository parity application contract: typed RPC type `7001` with
  `{ "value": "ping" }`, notification type `7002` with
  `{ "value": "notify" }`, and a `parity.echo` reliable stream that exchanges
  `hello`/`world` and observes FIN in both directions.

The examples keep connection details out of application code. Neither command
prints credentials or protocol state.

## Inspect an Opaque Artifact

Acquire an artifact through the application control plane and save its JSON to
a protected local file. Then run:

```bash
cargo run --locked --manifest-path examples/rust/Cargo.toml -- \
  artifact-v3 /secure/path/artifact.json
```

The command validates the artifact, prints only `Artifact { <opaque> }`, and
moves it into an unspent lease. It never reads the artifact back from the lease
or prints or serializes artifact fields.

## Establish a Session

Provide a DER-encoded trust root accepted by the listener and a new durable
receipt path:

```bash
cargo run --locked --manifest-path examples/rust/Cargo.toml -- \
  connect-v3 /secure/path/artifact.json /secure/path/root.der \
  /durable/state/artifact.spent
```

The public `connect(...)` function consumes only the opaque artifact lease and its trust and
deadline options. Before establishing the encrypted session, it invokes the
`ArtifactLease` callback to synchronize the create-new receipt. A successful
connection prints only `session=ready`, runs the typed RPC, notification, and
reliable-stream workflow, probes liveness, then closes the session cleanly.
The notification subscription is registered before application traffic and is
explicitly canceled after receipt. The stream sends `hello`, closes only its
write direction, reads `world` through peer FIN, and preserves the session for
the final liveness probe. Reusing a receipt path fails closed.
Connection and liveness failures print only their bounded public error code.
Long-lived applications use `ConnectionController` with a refreshable artifact
source; this one-shot example never reuses the committed path.

The receipt does not contain the artifact or cryptographic material. Keep both
paths outside the repository and apply permissions suitable for deployment
secrets and state.

## Verify

```bash
cargo test --locked --manifest-path examples/rust/Cargo.toml
cargo clippy --locked --manifest-path examples/rust/Cargo.toml \
  --all-targets -- -D warnings
```

The integration test verifies artifact redaction. The compiled `connect-v3`
workflow uses trusted roots, durable single-use spend, the opaque connection
boundary, typed RPC, notification subscription and delivery, reliable stream
write/read/FIN, session liveness, and bounded close. The repository's maintained
server-parity peers implement the same application contract for integration
coverage; a deployed service must register those application handlers before
running this client.
