# Third Party Notices

The packaged native transport driver directly uses the following third-party
crates. Their transitive dependencies remain governed by `Cargo.lock` and the
repository SBOM.

- `bytes` (MIT)
- `http` (MIT OR Apache-2.0)
- `qpack` (MIT)
- `quinn` and `quinn-proto` (MIT OR Apache-2.0) are unmodified crates.io releases.
- `sha2` and `x509-parser` (MIT OR Apache-2.0); `subtle` (BSD-3-Clause).
- `rustls` (Apache-2.0 OR ISC OR MIT)
- `thiserror` (MIT OR Apache-2.0)
- `tokio` (MIT)
- `tokio-util` (MIT)
- `url` (MIT OR Apache-2.0)
