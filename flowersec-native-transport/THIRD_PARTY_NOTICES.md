# Third Party Notices

The packaged native transport driver directly uses the following third-party
crates. Their transitive dependencies remain governed by `Cargo.lock` and the
repository SBOM.

- `bytes` (MIT)
- `http` (MIT OR Apache-2.0)
- `qpack` (MIT)
- Quinn 0.11.11 and quinn-proto 0.11.17 (MIT OR Apache-2.0) are incorporated
  as private source with negotiated reliable stream reset, prefix retransmission
  and checked offsets. The original licenses are packaged in
  `src/QUINN_LICENSE-MIT` and `src/QUINN_LICENSE-APACHE`.
- `quinn-udp`, `rand`, `rand_pcg`, `rustc-hash`, `socket2` and `pin-project-lite`
  (MIT OR Apache-2.0); `tinyvec` and `lru-slab` (MIT OR Apache-2.0 OR Zlib);
  `slab` and `tracing` (MIT); `ring` (Apache-2.0 AND ISC).
- `rustls` (Apache-2.0 OR ISC OR MIT)
- `thiserror` (MIT OR Apache-2.0)
- `tokio` (MIT)
- `tokio-util` (MIT)
- `url` (MIT OR Apache-2.0)
