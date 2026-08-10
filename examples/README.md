# Flowersec Cookbooks

These examples show the public application workflow: create or receive a
connection invitation, open an encrypted session, and use RPC or byte streams.
The same session API works for direct connections and relayed connections.

| Language | Cookbook | What it demonstrates |
| --- | --- | --- |
| Go | [`ExampleConnect`](../flowersec-go/example_client_test.go) and [`controlplane.ExampleIssuer_IssueTunnelPair`](../flowersec-go/controlplane/example_test.go) | Client sessions, durable invitation use, and control-plane issuance |
| TypeScript | [examples/ts](ts/README.md) | A runnable Node.js connector and long-lived session setup |
| Swift | [examples/swift](swift/README.md) | The Apple client session contract |
| Rust | [examples/rust](rust/README.md) | A Tokio client session and native QUIC connection |

## Run the Examples

From the repository root:

```bash
make example-check
```

The examples intentionally use the public SDK surface. They do not require
application code to know which connection path was selected or how the relay
forwards encrypted data.

See the [API contract](../docs/API_CONTRACT.md) for shared behavior and the
[transport architecture](../docs/TRANSPORT_V2_ARCHITECTURE.md) for connection
details.
