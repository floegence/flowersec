# Flowersec Cookbooks

These examples show the public application workflow: create or receive a
connection invitation, open an encrypted session, perform typed RPC, exchange
notifications, complete a bidirectional reliable stream through FIN, and close
the session. The same session API works for direct connections and relayed
connections.

| Language | Cookbook | What it demonstrates |
| --- | --- | --- |
| Go | [`ExampleConnect`](../flowersec-go/example_client_test.go) and [`controlplane.ExampleIssuer_IssueTunnelPair`](../flowersec-go/controlplane/example_test.go) | Typed RPC, notifications, reliable stream FIN, close, durable invitation use, and control-plane issuance |
| TypeScript | [examples/ts](ts/README.md) | A runnable Node.js client with typed RPC, notification send, reliable stream FIN, liveness, and close |
| Swift | [examples/swift](swift/README.md) | An Apple client with typed RPC, notification send, reliable stream FIN, liveness, and close |
| Rust | [examples/rust](rust/README.md) | A Tokio client with typed RPC, notifications, reliable stream FIN, and close |

## Run the Examples

From the repository root:

```bash
make example-check
```

The examples intentionally use the public SDK surface. The complete application
traffic path uses the same maintained parity contract in every language: RPC
type `7001`, notification type `7002`, `{ "value": "..." }` JSON payloads,
and `parity.echo` stream bytes `hello`/`world`. The repository integration peers
implement this contract; production services register equivalent application
handlers. Application code does not need to know how a relay forwards encrypted
data.

See the [API contract](../docs/API_CONTRACT.md) for shared behavior and the
[transport architecture](../docs/TRANSPORT_V3_ARCHITECTURE.md) for connection
details.
