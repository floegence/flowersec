# Flowersec Node Native Transport

`@floegence/flowersec-node-native` loads the supported prebuilt native transport
for the current Node.js platform. It is an implementation dependency of
`@floegence/flowersec-core`; applications should use the public Flowersec Node.js
API instead of importing this package directly.

The addon exposes a Flowersec-owned raw QUIC boundary backed by the shared Rust
native driver. Browser exports never load this package.
