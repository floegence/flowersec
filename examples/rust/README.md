# Rust Transport v2 Example

This package exercises the maintained Rust v2 public surface without exposing
carrier candidates, credentials, keys, or wire contracts. It provides two
workflows:

- parse an application-acquired opaque artifact without exposing its contents;
- establish a session through the carrier-neutral `Connector` and `Session`.

Transport selection and topology remain internal. Neither command prints a
carrier, path, candidate, endpoint identity, stream identifier, credential,
key, wire value, or transport diagnostic.

## Inspect an Opaque Artifact

Acquire an artifact through the application control plane and save its JSON to
a protected local file. Then run:

```bash
cargo run --locked --manifest-path examples/rust/Cargo.toml -- \
  artifact-v2 /secure/path/artifact.json
```

The command validates the artifact and prints only `Artifact { <opaque> }` plus
the unspent lease state. It never prints or serializes artifact fields.

## Establish a Session

Provide a DER-encoded trust root accepted by the listener and a new durable
receipt path:

```bash
cargo run --locked --manifest-path examples/rust/Cargo.toml -- \
  connect-v2 /secure/path/artifact.json /secure/path/root.der \
  /durable/state/artifact.spent
```

The public `Connector` consumes only the opaque artifact lease and its trust and
deadline options. Before establishing the encrypted session, it invokes the
`ArtifactLease` callback to synchronize the create-new receipt. A successful
connection prints only `session=ready` and the carrier-neutral liveness result,
then closes the session cleanly. Reusing a receipt path fails closed.

The receipt does not contain the artifact or cryptographic material. Keep both
paths outside the repository and apply permissions suitable for deployment
secrets and state.

## Verify

```bash
cargo test --locked --manifest-path examples/rust/Cargo.toml
cargo clippy --locked --manifest-path examples/rust/Cargo.toml \
  --all-targets -- -D warnings
```

The integration test verifies artifact redaction. The compiled `connect-v2`
workflow uses trusted roots, a bounded deadline, a cancellation token, durable
single-use spend, the opaque connector boundary, session liveness, and bounded
close.
