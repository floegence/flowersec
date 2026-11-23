# Flowersec Node Native Transport

`@floegence/flowersec-node-native` loads the supported prebuilt native transport
for the current Node.js platform. It is an implementation dependency of
`@floegence/flowersec-core`; applications should use the public Flowersec Node.js
API instead of importing this package directly.

The addon exposes raw QUIC and `draft02` WebTransport backed by the shared Rust
native driver. Browser exports never load this package.

`waitRemoteSessionClose()` resolves to `true` only for a peer application close
with code `1` and reason `session closed`. Local shutdown and other terminal
causes resolve to `false`. Multiple callers can wait for the same result.
`waitTermination()` continues to report termination without classifying its cause.

Published native binaries are distributed as four platform packages: macOS
arm64, macOS x64, Linux arm64 glibc, and Linux x64 glibc. The wrapper selects
the matching optional package for the current Node.js platform. Windows and
musl packages are not published because they have no supported build and smoke
coverage.

Each platform binary uses unmodified crates.io releases of Quinn and quinn-proto
through the shared Rust driver. The wrapper and each platform package include SPDX and
CycloneDX documents in `sbom/` and upstream license texts in
`THIRD_PARTY_NOTICES.md`. In the wrapper, these describe the native addon
loaded from the selected platform package.
