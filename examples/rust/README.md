# Rust Example

This package exercises the Rust public API:

- parse an application-acquired opaque artifact without exposing its contents;
- establish a session through the one-shot `connect(...)` and `Session` API;
- serve the first authorized Echo on a shared listener, or connect either end of a tunnel to its own ingress;
- run the repository parity application contract: typed RPC type `7001` with
  `{ "value": "ping" }`, notification type `7002` with
  `{ "value": "notify" }`, and a `parity.echo` reliable stream that exchanges
  `hello`/`world` and observes FIN in both directions.

The examples keep connection details out of application code. No command
prints credentials or protocol state.

## Serve the First Echo

Start with an empty, private approval directory on a filesystem that supports hard links and directory sync:

```sh
cargo run --locked --manifest-path examples/rust/Cargo.toml -- \
  listen-v5 127.0.0.1:4433 certificate.der key.der approvals
```

This binds raw QUIC. To bind WSS instead, set `FSEC_ORIGIN` on both ends to the allowed HTTPS origin. The issuer must use the actual listener address, its TLS policy and the configured inbound-stream count (`FSEC_MAX_INBOUND_STREAMS`, default 16). Publish one immutable server copy of the direct artifact as `approvals/<channel-id>.json`; the example accepts alphanumeric, dot, underscore and hyphen in this local filename. Deliver the matching invitation privately to the caller:

```sh
cargo run --locked --manifest-path examples/rust/Cargo.toml -- \
  echo-v5 invitation.json root.der receipts/client.spent
```

The server looks up the channel when a connection arrives. It links the current approval to a non-replaceable `<channel-id>.spent` and syncs the file and directory before acknowledging the verified admission. Both server files contain the original secret. Withdrawing an unused approval prevents a later claim. Restoring this whole directory can undo a spend; this example does not implement independent anti-rollback history, writer fencing or revocation of an already active session. Treat a required fresh challenge proving the designated peer's possession on this leg as unsupported by the wire protocol. The example rejects `FSEC_REQUIRE_ROLLBACK_PROTECTION` or `FSEC_REQUIRE_FRESH_LEG_PROOF` before connecting/listening.

For a tunnel, both endpoints receive independent signed invitations. The receiving endpoint runs `serve-tunnel-v5` with the same three arguments as `echo-v5`; the calling endpoint runs `echo-v5`. Set `FSEC_TUNNEL_INGRESS` separately on each endpoint to its authorized URL. Neither needs to know the path between the two ingress nodes. Supply a fresh local receipt for each leg.

`FSEC_RPC_FRAME_BYTES` sets the maximum encoded JSON envelope on each Rust endpoint (default 1 MiB). To echo 32 MiB through one RPC, set `FSEC_RPC_FRAME_BYTES=50331648` and `FSEC_EXAMPLE_LARGE_RPC=1` on both endpoints. With `1`, `connect-v5` and `echo-v5` call method `7010`; `listen-v5` and `serve-tunnel-v5` serve it. To reverse the direction, explicitly set `FSEC_EXAMPLE_LARGE_RPC=call` on the caller and `serve` on its peer. For example, a Rust Direct listener in `call` mode can call a Node connector in `serve` mode. Tunnel endpoints still use their own authorized ingress regardless of who calls.

Method `7010` takes a standard padded base64 JSON string containing exactly 32 MiB of arbitrary binary data. The string occupies 44,739,244 bytes before the envelope. The serving endpoint checks the length and encoding, echoes the value, and leaves the session open. The caller verifies every returned byte before closing. No reverse call, contract query, notification, or application stream is required. Peers may still use the ordinary echo, notification and stream handlers. If a policy file is configured, the serving side must grant `execute` for `7010`.

Set `FLOWERSEC_PARITY_WIDE_RPC=1` and `FSEC_RPC_CONCURRENT_REQUESTS=2` on both Rust endpoints to call 256 distinct methods (`8000` through `8255`) twice in each direction. Each side first queries the four application contracts, then verifies each method's reply. The serving side sends a `7002` completion notification; `echo-v5` waits for both directions before closing. The example allows 120 seconds for this exchange. When `FLOWERSEC_PARITY_POLICY_FILE` is set, its `execute` grants must include the workload methods and its `disclose` grants must include the four queried IDs.

## Inspect an Opaque Artifact

Acquire an artifact through the application control plane and save its JSON to
a protected local file. Then run:

```bash
cargo run --locked --manifest-path examples/rust/Cargo.toml -- \
  artifact-v5 /secure/path/artifact.json
```

The command validates the artifact, prints only `Artifact { <opaque> }`, and
moves it into an unspent lease. It never reads the artifact back from the lease
or prints or serializes artifact fields.

## Establish a Session

Provide a DER-encoded trust root accepted by the listener and a new durable
receipt path:

```bash
cargo run --locked --manifest-path examples/rust/Cargo.toml -- \
  connect-v5 /secure/path/artifact.json /secure/path/root.der \
  /durable/state/artifact.spent
```

The public `connect(...)` function consumes only the opaque artifact lease and its trust and
deadline options. Before establishing the encrypted session, it invokes the
`ArtifactLease` callback to synchronize the create-new receipt. A successful
connection prints only `session=ready`, runs the typed RPC, notification, and
reliable-stream workflow, probes liveness, then closes the session cleanly.
Both `listen-v5` and `serve-tunnel-v5` handle this workflow. The notification does not request a receipt. The stream sends `hello`, closes only its
write direction, reads `world` through peer FIN, and preserves the session for
the final liveness probe. Reusing a receipt path fails closed.
Connection and liveness failures print only their bounded public error code.
Long-lived applications use `ConnectionController` with a refreshable artifact
source; this one-shot example never reuses the committed path.

The client receipt does not contain the artifact or cryptographic material. Keep both
paths outside the repository and apply permissions suitable for deployment
secrets and state.

## Verify

```bash
cargo test --locked --manifest-path examples/rust/Cargo.toml
cargo clippy --locked --manifest-path examples/rust/Cargo.toml \
  --all-targets -- -D warnings
```

The integration test verifies artifact redaction. The compiled `connect-v5`
workflow uses trusted roots, durable single-use spend, the opaque connection
boundary, typed RPC, outbound notification, reliable stream
write/read/FIN, session liveness, and bounded close. The repository's maintained
server-parity peers implement the same application contract for integration
coverage; a deployed service must register those application handlers before
running this client.
