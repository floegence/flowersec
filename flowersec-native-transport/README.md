# Flowersec Native Transport

`flowersec-native-transport` contains the Flowersec-owned native carrier
primitives shared by the Rust SDK and the Node.js native addon. It provides a
bounded raw QUIC driver with explicit TLS trust, direct and tunnel ALPN
profiles, bidirectional streams, datagrams, cancellation, migration, and
application close semantics.

The `webtransport` module provides a dedicated HTTP/3 connection per session.
Draft02 dialers use CA roots or active SHA-256 leaf pins and an exact
Origin. Listeners check the CONNECT authority, path, and Origin before exposing
streams or HTTP datagrams. `Listener::new` takes an already bound UDP socket;
`Carrier::wait_shutdown` waits for that connection's workers and QUIC driver.
Resetting a new bidirectional stream does not terminate other streams or its session.

Applications should normally depend on the public `flowersec` SDK rather than
this lower-level crate. The driver deliberately exposes only Flowersec types;
Quinn and rustls implementation types remain private.

The crate requires Rust 1.88 or newer and contains no Flowersec-authored
`unsafe` code.
