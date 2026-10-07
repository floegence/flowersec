# Rust Client Integration Example

This package demonstrates the current Rust client API. The deployment
adapter constructs the trusted `TransportEnvironment` and
`ConnectionMaterialSource` from its verified namespace bootstrap, identity,
provider policy, credential issuer or preauthorized pool, and durable spend
store. `connect_current` accepts those opaque owners. The runnable consumer also
includes an explicitly selected local engineering adapter; it loads the
acceptance host's installed roots and issuer material, bootstraps namespaces
through their pinned endpoint, imports the provisioned identity, and creates a
fresh SDK SQLite spend history. It does not discover production authority from
peer bytes or reuse a previous process's history.

## Connect through the current API

The package exposes `connect_current` as a small convenience wrapper around the
SDK's normal `TransportEnvironment::connect` entry point:

```rust,no_run
use flowersec::{ConnectionMaterialSource, ConnectionRequirements, TransportEnvironment};
use flowersec_rust_client_example::connect_current;
use tokio_util::sync::CancellationToken;

# async fn run(
#     environment: &TransportEnvironment,
#     source: &ConnectionMaterialSource,
# ) -> Result<(), Box<dyn std::error::Error>> {
let session = connect_current(
    environment,
    source,
    ConnectionRequirements {
        application_profile: Some("services".to_owned()),
        ..ConnectionRequirements::default()
    },
    CancellationToken::new(),
).await?;

// Bind the application's service and stream facades before publishing the
// Session to application callers.
session.probe_liveness(std::time::Duration::from_secs(5)).await?;
session.close();
session.wait_cleanup().await;
# Ok(()) }
```

The source captures one material generation, identity, provider, and spend
owner. Each call makes one acquisition. Cancellation or an uncertain live
authorization result is returned to the caller; the wrapper never acquires a
second credential automatically. The application should build the Environment
and source through its trusted deployment integration, then pass them to this
function.

## Runnable public SDK consumer

The shared acceptance runner invokes the executable with this contract:

```bash
cargo run --locked --manifest-path examples/rust/Cargo.toml --   connect /absolute/path/material.json /absolute/path/trust.der   /absolute/path/artifact.spent
```

`MATERIAL_JSON` is a trusted deployment manifest supplied by the acceptance
host. It contains independently installed namespace root pins, endpoint policy,
issuer credentials and provisioned identity seeds; peer messages do not install
or replace these trust anchors. `TRUST_DER` supplies the installed TLS root.

`FSEC_ORIGIN` supplies the installed WebSocket origin and
`FSEC_EXAMPLE_STREAM_CELL` supplies the application Stream cell. The local
engineering adapter uses `curl` for one bounded namespace bootstrap exchange;
HTTPS uses the supplied DER root, TLS 1.3 and the explicitly selected loopback
endpoint, with redirects, proxies and cookies disabled. HTTP is allowed only
for the fixture's explicit loopback bootstrap address.

The consumer calls the ordinary public `TransportEnvironment::connect` entry
once, checks the original Source acquisition observation equals one and the
original SQLite spend observation is `CommitKnown`, then records that detached
fact after authenticated READY in an exclusive, file-and-directory-synchronized
spend receipt. It exercises
named typed RPC 7001, notification 7002, the `parity.echo` hello/world Stream,
normal FIN and authenticated liveness. Errors retain connection facts and never
trigger implicit material reacquisition or request replay. The SQLite database
and its history marker remain beside the receipt for diagnosis.

Run the example package's checks with:

```bash
cargo test --locked --manifest-path examples/rust/Cargo.toml
cargo clippy --locked --manifest-path examples/rust/Cargo.toml \
  --all-targets -- -D warnings
```
