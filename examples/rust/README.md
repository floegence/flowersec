# Rust Cookbook

The Rust example is a Transport v1 Tokio-native client that exercises artifact fetch, tunnel connect, typed RPC, custom streams, liveness, HTTP proxy, and WebSocket proxy.

## Run

Requirements: Rust 1.85+, Node.js 24+, Go 1.26.5+, and `jq`.

Start the shared stack from the repository root:

```bash
make ts-ensure-deps ts-build
node ./examples/ts/dev-server.mjs | tee dev.json
```

In another terminal:

```bash
FSEC_CONTROLPLANE_BASE_URL="$(jq -r '.controlplane_http_url' dev.json)" \
  cargo run --manifest-path ./examples/rust/Cargo.toml
```

Expected output includes these signals:

```text
stream=flowersec-rust-example
http_status=200
websocket=
```

## Examples

| Scenario | Source | Run or verify |
| --- | --- | --- |
| Artifact-first tunnel connect | [`main.rs`](src/main.rs) | Recommended command above |
| Typed RPC and custom stream | [`main.rs`](src/main.rs) | Included in the recommended run |
| Liveness probe | [`main.rs`](src/main.rs) | Included in the recommended run |
| HTTP/WebSocket proxy client | [`main.rs`](src/main.rs) | Included in the recommended run |
| Direct and tunnel client behavior | [`client.rs`](../../flowersec-rust/src/client.rs) | `cd flowersec-rust && cargo test --all-features client::tests` |
| Endpoint and RPC server | [`endpoint.rs`](../../flowersec-rust/src/endpoint.rs) | `cd flowersec-rust && cargo test --all-features endpoint::tests` |
| Reconnect | [`reconnect.rs`](../../flowersec-rust/src/reconnect.rs) | `cd flowersec-rust && cargo test --all-features reconnect::tests` |
| Controlplane issuance and fetch | [`controlplane.rs`](../../flowersec-rust/src/controlplane.rs) | `cd flowersec-rust && cargo test --all-features controlplane::tests` |

## Source Map

- `src/main.rs` is the application-facing example and uses the high-level public crate surface.
- The crate-local unit and integration tests are executable references for endpoint, reconnect, proxy policy, limits, and protocol edge cases.
- The cross-language interoperability harness validates Rust in both client and server roles against the Go reference peer.

## Runtime Boundaries

Rust provides the portable Tokio-native client and endpoint contract for Linux, macOS, and Windows. It does not duplicate the TypeScript browser runtime or the Go-owned tunnel, gateway, and helper binaries.

## Transport v2 Boundary

Rust includes portable Transport v2 protocol/session code and a tested Quinn raw QUIC adapter with native bidirectional streams, no Yamux over QUIC, no 0-RTT, and no QUIC DATAGRAM. It does not yet advertise a production v2 carrier tuple because artifact acquisition, equal-candidate durable spend, and server admission are not committed as one connector. The runnable example above remains v1; use `cargo test --manifest-path flowersec-rust/Cargo.toml --test raw_quic_v2` as the adapter reference and follow the [migration guide](../../docs/MIGRATION_TRANSPORT_V2.md).

## Troubleshooting

- Missing `FSEC_CONTROLPLANE_BASE_URL`: keep the shared stack running and read `controlplane_http_url` from `dev.json`.
- `token_replay`: rerun the client so it fetches a fresh artifact.
- Local `ws://` rejection: the example explicitly uses `allow_plaintext_for_loopback`; production deployments should use `wss://`.
- Toolchain mismatch: confirm `rustc --version` is 1.85 or newer.
