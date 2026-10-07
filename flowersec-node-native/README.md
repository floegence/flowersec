# Flowersec Node Native Support

`@floegence/flowersec-node-native` loads the supported prebuilt native transport
for the current Node.js platform. It is an implementation dependency of
`@floegence/flowersec-core`; applications should use the public Flowersec Node.js
API instead of importing this package directly.

The addon exposes Flowersec-owned raw QUIC and WebTransport boundaries backed
by the shared Rust native driver. It also supplies the fixed SQLite admission
extension used by Node durable stores. That extension configures the original
`node:sqlite` connection through SQLite's public extension API; it does not
embed another SQLite engine. Browser exports never load this package.

Published native binaries are distributed as four platform packages: macOS
arm64, macOS x64, Linux arm64 glibc, and Linux x64 glibc. The wrapper selects
the matching optional package for the current Node.js platform. Windows and
musl packages are not published because they have no supported build and smoke
coverage. Node durable stores require the matching installed native package.
