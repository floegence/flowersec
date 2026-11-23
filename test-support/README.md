# Noise interoperability reference

`flowersec-rust/noise-reference` tests the two SDK handshake profiles against
Snow's state machine. Its private dependency in `snow/` contains the library
source, build script, README and licenses from the `snow` 0.10.0 crate. The
manifest disables publishing, omits the benchmark target and selects `p256`
0.14. The default resolver uses that version's `Sec1Point` and `ToSec1Point`
APIs for uncompressed public keys. The state machine and wire buffers are
unchanged. Neither this dependency nor the reference harness is distributed
with the SDK. The source inventory records the upstream archive checksum and
the local tree digest.
