# Flowersec Native Transport

`flowersec-native-transport` contains the Flowersec-owned native carrier
primitives shared by the Rust SDK and the Node.js native addon. It provides a
bounded raw QUIC driver with explicit TLS trust, direct and tunnel ALPN
profiles, bidirectional streams, datagrams, cancellation, migration, and
application close semantics.

Applications should normally depend on the public `flowersec` SDK rather than
this lower-level crate. The driver deliberately exposes only Flowersec types;
Quinn and rustls implementation types remain private.

The crate requires Rust 1.88 or newer and contains no Flowersec-authored
`unsafe` code.
