# Third Party Notices

The packaged native transport driver directly uses the following third-party
crates. Their transitive dependencies remain governed by `Cargo.lock` and the
repository SBOM.

- `bytes` (MIT)
- Quinn runtime 0.11.11 and quinn-proto 0.11.15 (MIT OR Apache-2.0):
  incorporated as private native provider source, with negotiated partial reset
  and safe checked offset constructors. Original licenses are included in
  `src/QUINN_LICENSE-MIT` and `src/QUINN_LICENSE-APACHE`.
- `quinn-udp` (MIT OR Apache-2.0)
- `rustls` (Apache-2.0 OR ISC OR MIT)
- `thiserror` (MIT OR Apache-2.0)
- `tokio` (MIT)
- `tokio-util` (MIT)

- `qpack` (MIT): stateless QPACK header codec extracted from the h3 implementation.
- `url` (MIT OR Apache-2.0): canonical HTTPS authority and Origin parsing.
